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
#include "gtp_guard.h"


/*
 *	Virtual sqn hashtab
 */
static struct hlist_head *
gtp_sqn_hashkey(gtp_htab_t *h, uint32_t id)
{
	return h->htab + (jhash_1word(id, 0) & CONN_HASHTAB_MASK);
}

static gtp_teid_t *
__gtp_vsqn_get(gtp_htab_t *h, uint32_t sqn)
{
	struct hlist_head *head = gtp_sqn_hashkey(h, sqn);
	struct hlist_node *n;
	gtp_teid_t *t;

	hlist_for_each_entry(t, n, head, hlist_vsqn) {
		if (t->vsqn == sqn) {
			__sync_add_and_fetch(&t->refcnt, 1);
			return t;
		}
	}

	return NULL;
}

gtp_teid_t *
gtp_vsqn_get(gtp_htab_t *h, uint32_t sqn)
{
	gtp_teid_t *t;

	dlock_lock_id(h->dlock, sqn, 0);
	t = __gtp_vsqn_get(h, sqn);
	dlock_unlock_id(h->dlock, sqn, 0);

	return t;
}

int
__gtp_vsqn_hash(gtp_htab_t *h, gtp_teid_t *t, uint32_t sqn)
{
	struct hlist_head *head;

	if (__test_and_set_bit(GTP_TEID_FL_VSQN_HASHED, &t->flags)) {
		log_message(LOG_INFO, "%s(): VSQN:0x%.8x for TEID:0x%.8x already hashed !!!"
				    , __FUNCTION__, t->vsqn, ntohl(t->id));
		return -1;
	}

	head = gtp_sqn_hashkey(h, sqn);
	t->vsqn = sqn;
	hlist_add_head(&t->hlist_vsqn, head);

	__sync_add_and_fetch(&t->refcnt, 1);
	return 0;
}

int
gtp_vsqn_hash(gtp_htab_t *h, gtp_teid_t *t, uint32_t sqn)
{
	dlock_lock_id(h->dlock, sqn, 0);
	__gtp_vsqn_hash(h, t, sqn);
	dlock_unlock_id(h->dlock, sqn, 0);
	return 0;
}

int
gtp_vsqn_unhash(gtp_htab_t *h, gtp_teid_t *t)
{
	if (!t->vsqn)
		return -1;

	dlock_lock_id(h->dlock, t->vsqn, 0);
	if (!__test_and_clear_bit(GTP_TEID_FL_VSQN_HASHED, &t->flags)) {
		log_message(LOG_INFO, "%s(): VSQN:0x%.8x for TEID:0x%.8x already unhashed !!!"
				    , __FUNCTION__, t->vsqn, ntohl(t->id));
		dlock_unlock_id(h->dlock, t->vsqn, 0);
		return -1;
	}
	hlist_del_init(&t->hlist_vsqn);
	__sync_sub_and_fetch(&t->refcnt, 1);
	dlock_unlock_id(h->dlock, t->vsqn, 0);

	return 0;
}

int
gtp_vsqn_alloc(gtp_server_worker_t *w, gtp_teid_t *teid, bool set_msb)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_switch_t *ctx = srv->ctx;
	uint32_t *sqn = &ctx->seqnum;
	uint32_t sqn_max = ~(1 << 31) >> 8; /* MSB is reserved */
	uint32_t vsqn;

	/* nbytes counter circle */
	if (!*sqn || *sqn >= sqn_max)
		*sqn = 0x0f;
	__sync_add_and_fetch(sqn, 1);

	/* In GTPv2 simply shift 8bit for spare field */
	vsqn = (gtph->version == 2) ? *sqn << 8 : *sqn;

	if (set_msb)
		vsqn |= 1 << 31;

	/* Hash it */
	if (__test_bit(GTP_TEID_FL_VSQN_HASHED, &teid->flags))
		gtp_vsqn_unhash(&ctx->vsqn_tab, teid);
	gtp_vsqn_hash(&ctx->vsqn_tab, teid, vsqn);

	return 0;
}

int
gtp_sqn_update(gtp_server_worker_t *w, gtp_teid_t *teid)
{
	gtp1_hdr_t *gtp1h = (gtp1_hdr_t *) w->pbuff->head;
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;

	if (!teid)
		return -1;

	if (gtph->version == 1) {
		teid->sqn = (gtp1h->seq) ? gtp1h->sqn : 0;
		return 0;
	}

	teid->sqn = (gtph->teid_presence) ? gtph->sqn : gtph->sqn_only;
	return 0;
}

int
gtp_sqn_masq(gtp_server_worker_t *w, gtp_teid_t *teid)
{
	gtp1_hdr_t *gtp1h = (gtp1_hdr_t *) w->pbuff->head;
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;

	if (gtph->version == 1) {
		if (gtp1h->seq)
			gtp1h->sqn = htons(teid->vsqn);
		return 0;
	}

	if (gtph->teid_presence) {
		gtph->sqn = htonl(teid->vsqn);
		return 0;
	}
	gtph->sqn_only = htonl(teid->vsqn);

	return 0;
}

int
gtp_sqn_restore(gtp_server_worker_t *w, gtp_teid_t *teid)
{
	gtp1_hdr_t *gtp1h = (gtp1_hdr_t *) w->pbuff->head;
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;

	if (!teid)
		return -1;

	if (gtph->version == 1) {
		if (gtp1h->seq)
			gtp1h->sqn = teid->sqn;
		return 0;
	}

	if (gtph->teid_presence) {
		gtph->sqn = teid->sqn;
		return 0;
	}
	gtph->sqn_only = teid->sqn;

	return 0;
}
