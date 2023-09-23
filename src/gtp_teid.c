/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "vty.h"
#include "logger.h"
#include "list_head.h"
#include "json_writer.h"
#include "scheduler.h"
#include "jhash.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"


/*
 *	TEID hashtab
 */
static struct hlist_head *
gtp_teid_hashkey(gtp_htab_t *h, uint32_t id, uint32_t ipv4)
{
	return h->htab + (jhash_2words(id, ipv4, 0) & CONN_HASHTAB_MASK);
}

gtp_teid_t *
gtp_teid_get(gtp_htab_t *h, gtp_f_teid_t *f_teid)
{
	struct hlist_head *head = gtp_teid_hashkey(h, *f_teid->teid_grekey, *f_teid->ipv4);
	struct hlist_node *n;
	gtp_teid_t *t;

	dlock_lock_id(h->dlock, *f_teid->teid_grekey, *f_teid->ipv4);
	hlist_for_each_entry(t, n, head, hlist_teid) {
		if (t->id == *f_teid->teid_grekey && t->ipv4 == *f_teid->ipv4) {
			dlock_unlock_id(h->dlock, *f_teid->teid_grekey, *f_teid->ipv4);
			__sync_add_and_fetch(&t->refcnt, 1);
			return t;
		}
	}
	dlock_unlock_id(h->dlock, *f_teid->teid_grekey, *f_teid->ipv4);

	return NULL;
}

int
gtp_teid_put(gtp_teid_t *t)
{
	if (!t)
		return -1;

	__sync_sub_and_fetch(&t->refcnt, 1);
	return 0;
}

int
gtp_teid_hash(gtp_htab_t *h, gtp_teid_t *teid)
{
	struct hlist_head *head;

	if (!teid)
		return -1;

	head = gtp_teid_hashkey(h, teid->id, teid->ipv4);

	dlock_lock_id(h->dlock, teid->id, teid->ipv4);
	hlist_add_head(&teid->hlist_teid, head);
	dlock_unlock_id(h->dlock, teid->id, teid->ipv4);

	__sync_add_and_fetch(&teid->refcnt, 1);
	return 0;
}

int
gtp_teid_unhash(gtp_htab_t *h, gtp_teid_t *teid)
{
	if (!teid)
		return -1;

	dlock_lock_id(h->dlock, teid->id, teid->ipv4);
	hlist_del_init(&teid->hlist_teid);
	dlock_unlock_id(h->dlock, teid->id, teid->ipv4);

	__sync_sub_and_fetch(&teid->refcnt, 1);
	return 0;
}

gtp_teid_t *
gtp_teid_alloc(gtp_htab_t *h, gtp_f_teid_t *f_teid, gtp_ie_eps_bearer_id_t *bid)
{
	gtp_teid_t *new;

	PMALLOC(new);
	new->version = f_teid->version;
	new->id = *f_teid->teid_grekey;
	new->ipv4 = *f_teid->ipv4;
	if (bid)
		new->bearer_id = bid->id;
	INIT_LIST_HEAD(&new->next);

	gtp_teid_hash(h, new);

	return new;
}

void
gtp_teid_bind(gtp_teid_t *teid, gtp_teid_t *t)
{
	if (!teid || !t)
		return;

	teid->peer_teid = t;
	t->peer_teid = teid;
}

int
gtp_teid_masq(gtp_f_teid_t *f_teid, struct sockaddr_storage *addr, uint32_t vid)
{
	*f_teid->teid_grekey = htonl(vid);
	*f_teid->ipv4 = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
	return 0;
}

int
gtp_teid_restore(gtp_teid_t *teid, gtp_f_teid_t *f_teid)
{
	*f_teid->teid_grekey = teid->id;
	*f_teid->ipv4 = teid->ipv4;
	return 0;
}

void
gtp_teid_dump(gtp_teid_t *teid)
{
	printf(" - F-TEID\n");
	printf("  . TEID/GRE Key=0x%.4x\n", ntohl(teid->id));
	printf("  . Vitual TEID=0x%.4x\n", teid->vid);
	printf("  . IPv4=%u.%u.%u.%u\n", NIPQUAD(teid->ipv4));
	printf("  . Bearer ID=%u\n", teid->bearer_id);
}


/*
 *	Virtual TEID hashtab
 */
static uint32_t
gtp_vteid_generate(unsigned int *seed)
{
	uint32_t shuffle;

	shuffle = rand_r(seed) & 0xff;
	shuffle |= (rand_r(seed) & 0xff) << 8;
	shuffle |= (rand_r(seed) & 0xff) << 16;
	shuffle |= (rand_r(seed) & 0xff) << 24;

	return shuffle;
}

static gtp_teid_t *
__gtp_vteid_get(gtp_htab_t *h, uint32_t id)
{
	struct hlist_head *head = gtp_teid_hashkey(h, id, 0);
	struct hlist_node *n;
	gtp_teid_t *t;

	hlist_for_each_entry(t, n, head, hlist_vteid) {
		if (t->vid == id) {
			__sync_add_and_fetch(&t->refcnt, 1);
			return t;
		}
	}

	return NULL;
}

gtp_teid_t *
gtp_vteid_get(gtp_htab_t *h, uint32_t id)
{
	gtp_teid_t *t;

	dlock_lock_id(h->dlock, id, 0);
	t = __gtp_vteid_get(h, id);
	dlock_unlock_id(h->dlock, id, 0);

	return t;
}

int
__gtp_vteid_hash(gtp_htab_t *h, gtp_teid_t *t, uint32_t vid)
{
	struct hlist_head *head;

	head = gtp_teid_hashkey(h, vid, 0);
	t->vid = vid;
	hlist_add_head(&t->hlist_vteid, head);

	__sync_add_and_fetch(&t->refcnt, 1);
	return 0;
}

int
gtp_vteid_unhash(gtp_htab_t *h, gtp_teid_t *t)
{
	dlock_lock_id(h->dlock, t->vid, 0);
	hlist_del_init(&t->hlist_vteid);
	dlock_unlock_id(h->dlock, t->vid, 0);

	__sync_sub_and_fetch(&t->refcnt, 1);
	return 0;
}

int
gtp_vteid_alloc(gtp_htab_t *h, gtp_teid_t *teid, unsigned int *seed)
{
	uint32_t vid;
	gtp_teid_t *t;

  shoot_again:
	vid = gtp_vteid_generate(seed);
	/* Add some kind of enthropy to workaround rand() crappiness */
	vid ^= teid->id;

	dlock_lock_id(h->dlock, vid, 0);
	t = __gtp_vteid_get(h, vid);
	if (t) {
		dlock_unlock_id(h->dlock, vid, 0);
		/* same player */
		__sync_sub_and_fetch(&t->refcnt, 1);
		goto shoot_again;
	}

	__gtp_vteid_hash(h, teid, vid);
	dlock_unlock_id(h->dlock, vid, 0);
	return 0;
}