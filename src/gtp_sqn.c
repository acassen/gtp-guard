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

#include "gtp_teid.h"
#include "gtp_conn.h"
#include "gtp_proxy.h"
#include "gtp.h"
#include "jhash.h"
#include "bitops.h"
#include "logger.h"


/*
 *	Virtual sqn hashtab
 */
static struct hlist_head *
gtp_sqn_hashkey(struct hlist_head *h, uint32_t id)
{
	return h + (jhash_1word(id, 0) & CONN_HASHTAB_MASK);
}

struct gtp_teid *
gtp_vsqn_get(struct hlist_head *h, uint32_t sqn)
{
	struct hlist_head *head = gtp_sqn_hashkey(h, sqn);
	struct gtp_teid *t;

	hlist_for_each_entry(t, head, hlist_vsqn) {
		if (t->vsqn == sqn) {
			__sync_add_and_fetch(&t->refcnt, 1);
			return t;
		}
	}

	return NULL;
}

int
gtp_vsqn_hash(struct hlist_head *h, struct gtp_teid *t, uint32_t sqn)
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
gtp_vsqn_unhash(struct hlist_head *h, struct gtp_teid *t)
{
	if (!t->vsqn)
		return -1;

	if (!__test_and_clear_bit(GTP_TEID_FL_VSQN_HASHED, &t->flags)) {
		log_message(LOG_INFO, "%s(): VSQN:0x%.8x for TEID:0x%.8x already unhashed !!!"
				    , __FUNCTION__, t->vsqn, ntohl(t->id));
		return -1;
	}
	hlist_del_init(&t->hlist_vsqn);
	__sync_sub_and_fetch(&t->refcnt, 1);
	return 0;
}

int
gtp_vsqn_alloc(struct gtp_server *s, struct gtp_teid *teid, bool set_msb)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) s->s.pbuff->head;
	struct gtp_proxy *ctx = s->ctx;
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
		gtp_vsqn_unhash(ctx->vsqn_tab, teid);
	gtp_vsqn_hash(ctx->vsqn_tab, teid, vsqn);

	return 0;
}

int
gtp_sqn_update(struct gtp_server *s, struct gtp_teid *teid)
{
	struct gtp1_hdr *gtp1h = (struct gtp1_hdr *) s->s.pbuff->head;
	struct gtp_hdr *gtph = (struct gtp_hdr *) s->s.pbuff->head;

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
gtp_sqn_masq(struct gtp_server *s, struct gtp_teid *teid)
{
	struct gtp1_hdr *gtp1h = (struct gtp1_hdr *) s->s.pbuff->head;
	struct gtp_hdr *gtph = (struct gtp_hdr *) s->s.pbuff->head;

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
gtp_sqn_restore(struct gtp_server *s, struct gtp_teid *teid)
{
	struct gtp1_hdr *gtp1h = (struct gtp1_hdr *) s->s.pbuff->head;
	struct gtp_hdr *gtph = (struct gtp_hdr *) s->s.pbuff->head;

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
