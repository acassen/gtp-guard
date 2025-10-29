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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#include <string.h>

#include "gtp_teid.h"
#include "gtp_conn.h"
#include "jhash.h"
#include "memory.h"
#include "bitops.h"
#include "logger.h"
#include "utils.h"
#include "inet_utils.h"

/*
 *	Unuse queue
 */
static struct list_head gtp_teid_unuse;
static int gtp_teid_unuse_count;
static struct hlist_head *gtpc_teid_tab;
static struct hlist_head *gtpu_teid_tab;

static int
gtp_teid_unuse_destroy(void)
{
	struct gtp_teid *t, *_t;

	list_for_each_entry_safe(t, _t, &gtp_teid_unuse, next) {
		list_head_del(&t->next);
		FREE(t);
	}
	INIT_LIST_HEAD(&gtp_teid_unuse);

	return 0;
}

int
gtp_teid_unuse_queue_size(void)
{
	return gtp_teid_unuse_count;
}

static struct gtp_teid *
gtp_teid_unuse_trim_head(void)
{
	struct gtp_teid *t;

	if (list_empty(&gtp_teid_unuse))
		return NULL;

	t = list_first_entry(&gtp_teid_unuse, struct gtp_teid, next);
	list_head_del(&t->next);
	memset(t, 0, sizeof(*t));

	__sync_sub_and_fetch(&gtp_teid_unuse_count, 1);
	return t;
}


static struct gtp_teid *
gtp_teid_malloc(void)
{
	struct gtp_teid *t;

	t = gtp_teid_unuse_trim_head();
	if (!t)
		PMALLOC(t);

	return t;
}

void
gtp_teid_free(struct gtp_teid *t)
{
	INIT_LIST_HEAD(&t->next);
	list_add_tail(&t->next, &gtp_teid_unuse);
	__sync_add_and_fetch(&gtp_teid_unuse_count, 1);
}


/*
 *	TEID hashtab
 */
static struct hlist_head *
gtp_teid_hashkey(struct hlist_head *h, uint32_t id, uint32_t ipv4)
{
	return h + (jhash_2words(id, ipv4, 0) & CONN_HASHTAB_MASK);
}

static struct gtp_teid *
__gtp_teid_get(struct hlist_head *h, uint32_t id, uint32_t ipv4)
{
	struct hlist_head *head = gtp_teid_hashkey(h, id, ipv4);
	struct gtp_teid *t;

	hlist_for_each_entry(t, head, hlist_teid) {
		if (t->id == id && t->ipv4 == ipv4) {
			__sync_add_and_fetch(&t->refcnt, 1);
			return t;
		}
	}

	return NULL;
}

struct gtp_teid *
gtp_teid_get(struct hlist_head *h, struct gtp_f_teid *f_teid)
{
	return __gtp_teid_get(h, *f_teid->teid_grekey, *f_teid->ipv4);
}

struct gtp_teid *
gtpc_teid_get(struct gtp_f_teid *f_teid)
{
	return gtp_teid_get(gtpc_teid_tab, f_teid);
}

struct gtp_teid *
gtpu_teid_get(struct gtp_f_teid *f_teid)
{
	return gtp_teid_get(gtpu_teid_tab, f_teid);
}

int
gtp_teid_put(struct gtp_teid *t)
{
	if (!t)
		return -1;

	__sync_sub_and_fetch(&t->refcnt, 1);
	return 0;
}

static int
gtp_teid_hash(struct hlist_head *h, struct gtp_teid *teid)
{
	struct hlist_head *head = gtp_teid_hashkey(h, teid->id, teid->ipv4);

	if (__test_and_set_bit(GTP_TEID_FL_HASHED, &teid->flags)) {
		log_message(LOG_INFO, "%s(): TEID:0x%.8x already hashed !!!"
				    , __FUNCTION__, ntohl(teid->id));
		return -1;
	}

	hlist_add_head(&teid->hlist_teid, head);
	__sync_add_and_fetch(&teid->refcnt, 1);
	return 0;
}

int
gtp_teid_unhash(struct hlist_head *h, struct gtp_teid *teid)
{
	if (!teid)
		return -1;

	if (!__test_and_clear_bit(GTP_TEID_FL_HASHED, &teid->flags)) {
		log_message(LOG_INFO, "%s(): TEID:0x%.8x already unhashed !!!"
				    , __FUNCTION__, ntohl(teid->id));
		return -1;
	}
	hlist_del_init(&teid->hlist_teid);
	__sync_sub_and_fetch(&teid->refcnt, 1);
	return 0;
}

int
gtpc_teid_unhash(struct gtp_teid *teid)
{
	return gtp_teid_unhash(gtpc_teid_tab, teid);
}

int
gtpu_teid_unhash(struct gtp_teid *teid)
{
	return gtp_teid_unhash(gtpu_teid_tab, teid);
}

struct gtp_teid *
gtp_teid_alloc_peer(struct hlist_head *h, struct gtp_teid *teid, uint32_t ipv4,
		    struct gtp_ie_eps_bearer_id *bid, unsigned int *seed)
{
	struct gtp_teid *new, *t;
	uint32_t id;

	if (!teid)
		return NULL;

	if (teid->peer_teid) {
		log_message(LOG_INFO, "%s(): TEID:0x%.8x already peered !!!"
				    , __FUNCTION__, ntohl(teid->id));
		return NULL;
	}

	new = gtp_teid_malloc();
	if (!new) {
		log_message(LOG_INFO, "%s(): Cant allocate peer for TEID:0x%.8x !!!"
				    , __FUNCTION__, ntohl(teid->id));
		return NULL;
	}

  shoot_again:
	id = poor_prng(seed);
	/* Add some kind of enthropy to workaround rand() crappiness */
	id ^= teid->id;

	t = __gtp_teid_get(h, id, ipv4);
	if (t) {
		/* same player */
		__sync_sub_and_fetch(&t->refcnt, 1);
		goto shoot_again;
	}

	new->id = id;
	new->ipv4 = ipv4;
	if (bid)
		new->bearer_id = bid->id;
	gtp_teid_hash(h, new);

	/* bind new TEID */
	gtp_teid_bind(teid, new);

	return new;
}

struct gtp_teid *
gtpc_teid_alloc_peer(struct gtp_teid *teid, uint32_t ipv4,
		     struct gtp_ie_eps_bearer_id *bid, unsigned int *seed)
{
	return gtp_teid_alloc_peer(gtpc_teid_tab, teid, ipv4, bid, seed);
}

struct gtp_teid *
gtpu_teid_alloc_peer(struct gtp_teid *teid, uint32_t ipv4,
		     struct gtp_ie_eps_bearer_id *bid, unsigned int *seed)
{
	return gtp_teid_alloc_peer(gtpu_teid_tab, teid, ipv4, bid, seed);
}

struct gtp_teid *
gtp_teid_alloc(struct hlist_head *h, struct gtp_f_teid *f_teid, struct gtp_ie_eps_bearer_id *bid)
{
	struct gtp_teid *new;

	new = gtp_teid_malloc();
	new->version = f_teid->version;
	new->id = *f_teid->teid_grekey;
	new->ipv4 = *f_teid->ipv4;
	if (bid)
		new->bearer_id = bid->id;
	INIT_LIST_HEAD(&new->next);

	gtp_teid_hash(h, new);

	return new;
}

struct gtp_teid *
gtpc_teid_alloc(struct gtp_f_teid *f_teid, struct gtp_ie_eps_bearer_id *bid)
{
	return gtp_teid_alloc(gtpc_teid_tab, f_teid, bid);
}

struct gtp_teid *
gtpu_teid_alloc(struct gtp_f_teid *f_teid, struct gtp_ie_eps_bearer_id *bid)
{
	return gtp_teid_alloc(gtpu_teid_tab, f_teid, bid);
}

void
gtp_teid_bind(struct gtp_teid *teid, struct gtp_teid *t)
{
	if (!teid || !t)
		return;

	teid->peer_teid = t;
	t->peer_teid = teid;
}

int
gtp_teid_masq(struct gtp_f_teid *f_teid, struct sockaddr_storage *addr, uint32_t vid)
{
	*f_teid->teid_grekey = htonl(vid);
	*f_teid->ipv4 = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
	return 0;
}

int
gtp_teid_restore(struct gtp_teid *teid, struct gtp_f_teid *f_teid)
{
	*f_teid->teid_grekey = teid->id;
	*f_teid->ipv4 = teid->ipv4;
	return 0;
}

int
gtp_teid_update_sgw(struct gtp_teid *teid, struct sockaddr_storage *addr)
{
	if (!teid)
		return -1;

	teid->sgw_addr = *((struct sockaddr_in *) addr);
	return 0;
}

int
gtp_teid_update_pgw(struct gtp_teid *teid, struct sockaddr_storage *addr)
{
	if (!teid)
		return -1;

	teid->pgw_addr = *((struct sockaddr_in *) addr);
	return 0;
}

void
gtp_teid_dump(struct gtp_teid *teid)
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
struct gtp_teid *
gtp_vteid_get(struct hlist_head *h, uint32_t id)
{
	struct hlist_head *head = gtp_teid_hashkey(h, id, 0);
	struct gtp_teid *t;

	hlist_for_each_entry(t, head, hlist_vteid) {
		if (t->vid == id) {
			__sync_add_and_fetch(&t->refcnt, 1);
			return t;
		}
	}

	return NULL;
}

int
gtp_vteid_hash(struct hlist_head *h, struct gtp_teid *t, uint32_t vid)
{
	struct hlist_head *head;

	if (__test_and_set_bit(GTP_TEID_FL_VTEID_HASHED, &t->flags)) {
		log_message(LOG_INFO, "%s(): VTEID:0x%.8x for TEID:0x%.8x already hashed !!!"
				    , __FUNCTION__, t->vid, ntohl(t->id));
		return -1;
	}

	head = gtp_teid_hashkey(h, vid, 0);
	t->vid = vid;
	hlist_add_head(&t->hlist_vteid, head);

	__sync_add_and_fetch(&t->refcnt, 1);
	return 0;
}

int
gtp_vteid_unhash(struct hlist_head *h, struct gtp_teid *t)
{
	if (!__test_and_clear_bit(GTP_TEID_FL_VTEID_HASHED, &t->flags)) {
		log_message(LOG_INFO, "%s(): VTEID:0x%.8x for TEID:0x%.8x already unhashed !!!"
				    , __FUNCTION__, t->vid, ntohl(t->id));
		return -1;
	}

	hlist_del_init(&t->hlist_vteid);
	__sync_sub_and_fetch(&t->refcnt, 1);
	return 0;
}

int
gtp_vteid_alloc(struct hlist_head *h, struct gtp_teid *teid, unsigned int *seed)
{
	struct gtp_teid *t;
	uint32_t vid;

  shoot_again:
	vid = poor_prng(seed);
	/* Add some kind of enthropy to workaround rand() crappiness */
	vid ^= teid->id;

	t = gtp_vteid_get(h, vid);
	if (t) {
		/* same player */
		__sync_sub_and_fetch(&t->refcnt, 1);
		goto shoot_again;
	}

	gtp_vteid_hash(h, teid, vid);
	return 0;
}

/*
 *	Tunnel ID tracking init
 */
int
gtp_teid_init(void)
{
	INIT_LIST_HEAD(&gtp_teid_unuse);

	/* Init hashtab */
	gtpc_teid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	gtpu_teid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	return 0;
}

int
gtp_teid_destroy(void)
{
	free(gtpc_teid_tab);
	free(gtpu_teid_tab);
	gtp_teid_unuse_destroy();
	return 0;
}
