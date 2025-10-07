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

#include "ppp_session.h"
#include "pppoe_session.h"
#include "pppoe_proto.h"
#include "jhash.h"
#include "bitops.h"
#include "logger.h"
#include "utils.h"
#include "memory.h"
#include "gtp_htab.h"
#include "gtp_utils.h"
#include "gtp_utils_uli.h"


/*
 *	PPPoE Sessions tracking
 */
static int pppoe_sessions_count = 0;
static struct gtp_htab *pppoe_session_tab;
static struct gtp_htab *pppoe_unique_tab;

int
spppoe_sessions_count_read(void)
{
	return pppoe_sessions_count;
}




/* Host-Unique related */
static struct hlist_head *
spppoe_unique_hashkey(struct gtp_htab *h, uint32_t id)
{
	return h->htab + (jhash_1word(id, 0) & CONN_HASHTAB_MASK);
}

static struct spppoe *
__spppoe_get_by_unique(struct gtp_htab *h, uint32_t id)
{
	struct hlist_head *head = spppoe_unique_hashkey(h, id);
	struct hlist_node *n;
	struct spppoe *s;

	hlist_for_each_entry(s, n, head, h_unique) {
		if (s->unique == id) {
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}

	return NULL;
}

struct spppoe *
spppoe_get_by_unique(uint32_t id)
{
	return __spppoe_get_by_unique(pppoe_unique_tab, id);
}

static int
__spppoe_unique_hash(struct gtp_htab *h, struct spppoe *s, uint32_t id)
{
	struct hlist_head *head;

	if (__test_and_set_bit(GTP_PPPOE_FL_UNIQUE_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.4x already hashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		return -1;
	}

	head = spppoe_unique_hashkey(h, id);
	s->unique = id;
	hlist_add_head(&s->h_unique, head);
	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
spppoe_unique_unhash(struct gtp_htab *h, struct spppoe *s)
{
	if (!__test_and_clear_bit(GTP_PPPOE_FL_UNIQUE_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.4x already unhashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		return -1;
	}

	hlist_del_init(&s->h_unique);
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
spppoe_unique_hash(struct gtp_htab *h, struct spppoe *s, uint64_t imsi, unsigned int *seed)
{
	struct spppoe *_s;
	uint32_t id;

  shoot_again:
	id = poor_prng(seed) ^ (uint32_t) imsi;

	_s = __spppoe_get_by_unique(h, id);
	if (_s) {
		/* same player */
		__sync_sub_and_fetch(&_s->refcnt, 1);
		goto shoot_again;
	}

	__spppoe_unique_hash(h, s, id);
	return 0;
}

/* Session-ID related */
static struct hlist_head *
spppoe_session_hashkey(struct gtp_htab *h, struct ether_addr *hw_addr, uint16_t id)
{
	void *pkey = (void *) hw_addr->ether_addr_octet;
	uint32_t hbits = *(uint32_t *) pkey;
	uint32_t lbits = *(uint32_t *) (pkey + 4);

	return h->htab + (jhash_3words(hbits, lbits, id, 0) & CONN_HASHTAB_MASK);
}

static struct spppoe *
__spppoe_get_by_session(struct gtp_htab *h, struct ether_addr *hw_addr, uint16_t id)
{
	struct hlist_head *head = spppoe_session_hashkey(h, hw_addr, id);
	struct hlist_node *n;
	struct spppoe *s;

	hlist_for_each_entry(s, n, head, h_session) {
		if (s->session_id == id && !memcmp(&s->hw_src, hw_addr, ETH_ALEN)) {
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}

	return NULL;
}

struct spppoe *
spppoe_get_by_session(struct ether_addr *hw_addr, uint16_t id)
{
	return __spppoe_get_by_session(pppoe_session_tab, hw_addr, id);
}

int
spppoe_session_hash(struct spppoe *s, struct ether_addr *hw_addr, uint16_t id)
{
	struct gtp_htab *h = pppoe_session_tab;
	struct hlist_head *head;

	if (__test_and_set_bit(GTP_PPPOE_FL_SESSION_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.4x already hashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		return -1;
	}

	head = spppoe_session_hashkey(h, hw_addr, id);
	hlist_add_head(&s->h_session, head);
	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
spppoe_session_unhash(struct gtp_htab *h, struct spppoe *s)
{
	if (!__test_and_clear_bit(GTP_PPPOE_FL_SESSION_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.4x already unhashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		return -1;
	}

	hlist_del_init(&s->h_session);
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

int
spppoe_sessions_destroy(struct gtp_htab *h)
{
	struct hlist_node *n, *_n;
	struct spppoe *s;
	int i;

	for (i = 0; i < CONN_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(s, n, _n, &h->htab[i], h_session) {
			spppoe_free(s);
		}
	}

	return 0;
}

/*
 *	PPPoE Sessions related
 */
static int
spppoe_generate_id(struct gtp_conn *c)
{
	struct spppoe *s;
	bool inuse[GTP_PPPOE_MAX_SESSION_PER_IMSI] = { 0 };
	int i;

	if (__sync_add_and_fetch(&c->pppoe_cnt, 0) == GTP_PPPOE_MAX_SESSION_PER_IMSI)
		return -1;

	/* Phase 0 : populate inuse table, since session can
	 * be deleted or added we need to mark and look for
	 * available id */
	list_for_each_entry(s, &c->pppoe_sessions, next)
		inuse[s->id] = true;

	/* Phase 1 : return first available id */
	for (i = 0; i < GTP_PPPOE_MAX_SESSION_PER_IMSI; i++) {
		if (!inuse[i]) {
			return i;
		}
	}

	return -1;
}

static int
spppoe_add(struct gtp_conn *c, struct spppoe *s)
{
	struct pppoe *pppoe = s->pppoe;

	list_add_tail(&s->next, &c->pppoe_sessions);
	__sync_add_and_fetch(&c->pppoe_cnt, 1);
	__sync_add_and_fetch(&pppoe->session_count, 1);
	__sync_add_and_fetch(&pppoe_sessions_count, 1);
	return 0;
}

static int
spppoe_del(struct gtp_conn *c, struct spppoe *s)
{
	struct pppoe *pppoe = s->pppoe;

	list_head_del(&s->next);
	__sync_sub_and_fetch(&c->pppoe_cnt, 1);
	__sync_sub_and_fetch(&pppoe->session_count, 1);
	__sync_sub_and_fetch(&pppoe_sessions_count, 1);
	return 0;
}

void
spppoe_free(struct spppoe *s)
{
	sppp_destroy(s->s_ppp);
	FREE_PTR(s->ac_cookie);
	FREE_PTR(s->relay_sid);
	FREE(s);
}

static int
spppoe_release(struct spppoe *s)
{
	/* Disconnect pppoe session */
	spppoe_disconnect(s);

	/* Release tracking */
	spppoe_session_unhash(pppoe_session_tab, s);
	spppoe_unique_unhash(pppoe_unique_tab, s);
	spppoe_free(s);
	return 0;
}

int
spppoe_destroy(struct spppoe *s)
{
	if (!s)
		return -1;

	spppoe_del(s->s_gtp->conn, s);
	spppoe_release(s);
	return 0;
}

struct spppoe *
spppoe_alloc(struct pppoe *pppoe, struct gtp_conn *c,
	     void (*pp_tls)(struct sppp *), void (*pp_tlf)(struct sppp *),
	     void (*pp_con)(struct sppp *), void (*pp_chg)(struct sppp *, int),
	     const uint64_t imsi, const uint64_t mei, const char *apn_str,
	     struct gtp_id_ecgi *ecgi, struct gtp_ie_ambr *ambr)
{
	struct spppoe *s;
	int err, id;

	if (!pppoe)
		return NULL;

	id = spppoe_generate_id(c);
	if (id < 0) {
		log_message(LOG_INFO, "%s(): %d veth already allocated to imsi:%ld"
				    , __FUNCTION__
				    , GTP_PPPOE_MAX_SESSION_PER_IMSI, imsi);
		return NULL;
	}

	PMALLOC(s);
	INIT_LIST_HEAD(&s->next);
	s->id = id;
	s->session_time = time(NULL);
	gtp_imsi_ether_addr_build(imsi, &s->hw_src, id);
	s->hw_src.ether_addr_octet[0] |= pppoe->vmac_hbits;
	s->pppoe = pppoe;

	/* PAP username templating */
	if (__test_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_0_BIT, &pppoe->flags))
		snprintf(s->gtp_username, PPPOE_NAMELEN
					, "%lu+%lu@%s"
					, imsi, mei, apn_str);
	else if (__test_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_1_BIT, &pppoe->flags))
		snprintf(s->gtp_username, PPPOE_NAMELEN
					, "%lu@%s"
					, imsi, apn_str);

	/* Vendor Specific tags */
	if (__test_bit(PPPOE_FL_VENDOR_SPECIFIC_BBF_BIT, &pppoe->flags)) {
		snprintf(s->remote_id, PPPOE_NAMELEN, "%lu", mei);
		gtp_id_ecgi_str(ecgi, s->circuit_id, PPPOE_NAMELEN);
		if (ambr) {
			s->ambr_downlink = ambr->downlink;
			s->ambr_uplink = ambr->uplink;
		}
	}

	s->s_ppp = sppp_init(s, pp_tls, pp_tlf, pp_con, pp_chg);
	spppoe_unique_hash(pppoe_unique_tab, s, imsi, &pppoe->seed);
	spppoe_add(c, s);

	err = pppoe_connect(s);
	if (err) {
		spppoe_destroy(s);
		return NULL;
	}

	return s;
}

int
spppoe_close(struct spppoe *s)
{
	if (!s)
		return -1;

	__set_bit(GTP_PPPOE_FL_DELETE, &s->flags);
	return pppoe_disconnect(s);
}

int
spppoe_disconnect(struct spppoe *s)
{
	if (!s)
		return -1;

	__set_bit(GTP_PPPOE_FL_DELETE_IGNORE, &s->flags);
	return pppoe_disconnect(s);
}


/*
 *	PPPoE Tracking
 */
int
spppoe_tracking_init(void)
{
	pppoe_session_tab = gtp_htab_alloc(CONN_HASHTAB_SIZE);
	pppoe_unique_tab = gtp_htab_alloc(CONN_HASHTAB_SIZE);
	return 0;
}

int
spppoe_tracking_destroy(void)
{
	spppoe_sessions_destroy(pppoe_session_tab);
	gtp_htab_destroy(pppoe_session_tab);
	gtp_htab_destroy(pppoe_unique_tab);
	gtp_htab_free(pppoe_session_tab);
	gtp_htab_free(pppoe_unique_tab);
	return 0;
}
