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
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	PPPoE Session tracking
 */

/* Host-Unique related */
static struct hlist_head *
spppoe_unique_hashkey(gtp_htab_t *h, uint32_t id)
{
	return h->htab + (jhash_1word(id, 0) & CONN_HASHTAB_MASK);
}

static spppoe_t *
__spppoe_get_by_unique(gtp_htab_t *h, uint32_t id)
{
	struct hlist_head *head = spppoe_unique_hashkey(h, id);
	struct hlist_node *n;
	spppoe_t *s;

	hlist_for_each_entry(s, n, head, h_unique) {
		if (s->unique == id) {
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}

	return NULL;
}

spppoe_t *
spppoe_get_by_unique(gtp_htab_t *h, uint32_t id)
{
	spppoe_t *s;

	dlock_lock_id(h->dlock, id, 0);
	s = __spppoe_get_by_unique(h, id);
	dlock_unlock_id(h->dlock, id, 0);

	return s;
}

int
__spppoe_unique_hash(gtp_htab_t *h, spppoe_t *s, uint32_t id)
{
	struct hlist_head *head;

	if (__test_and_set_bit(GTP_PPPOE_FL_UNIQUE_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.8x already hashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		return -1;
	}

	head = spppoe_unique_hashkey(h, id);
	s->unique = id;
	hlist_add_head(&s->h_unique, head);

	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

int
spppoe_unique_unhash(gtp_htab_t *h, spppoe_t *s)
{
	dlock_lock_id(h->dlock, s->unique, 0);
	if (!__test_and_clear_bit(GTP_PPPOE_FL_UNIQUE_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.8x already unhashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		dlock_unlock_id(h->dlock, s->unique, 0);
		return -1;
	}

	hlist_del_init(&s->h_unique);
	__sync_sub_and_fetch(&s->refcnt, 1);
	dlock_unlock_id(h->dlock, s->unique, 0);

	return 0;
}

int
spppoe_unique_hash(gtp_htab_t *h, spppoe_t *s, uint64_t imsi, unsigned int *seed)
{
	spppoe_t *_s;
	uint32_t id;

  shoot_again:
	id = poor_prng(seed) ^ (uint32_t) imsi;

	dlock_lock_id(h->dlock, id, 0);
	_s = __spppoe_get_by_unique(h, id);
	if (_s) {
		dlock_unlock_id(h->dlock, id, 0);
		/* same player */
		__sync_sub_and_fetch(&_s->refcnt, 1);
		goto shoot_again;
	}

	__spppoe_unique_hash(h, s, id);
	dlock_unlock_id(h->dlock, id, 0);
	return 0;
}

/* Session-ID related */
static struct hlist_head *
spppoe_session_hashkey(gtp_htab_t *h, struct ether_addr *hw_addr, uint16_t id)
{
	void *pkey = (void *) hw_addr->ether_addr_octet;
	uint32_t hbits = *(uint32_t *) pkey;
	uint32_t lbits = *(uint32_t *) (pkey + 4);

	return h->htab + (jhash_3words(hbits, lbits, id, 0) & CONN_HASHTAB_MASK);
}

static spppoe_t *
__spppoe_get_by_session(gtp_htab_t *h, struct ether_addr *hw_addr, uint16_t id)
{
	struct hlist_head *head = spppoe_session_hashkey(h, hw_addr, id);
	struct hlist_node *n;
	spppoe_t *s;

	hlist_for_each_entry(s, n, head, h_session) {
		if (s->session_id == id && !memcmp(&s->hw_src, hw_addr, ETH_ALEN)) {
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}

	return NULL;
}

spppoe_t *
spppoe_get_by_session(gtp_htab_t *h, struct ether_addr *hw_addr, uint16_t id)
{
	spppoe_t *s;

	dlock_lock_id(h->dlock, id, 0);
	s = __spppoe_get_by_session(h, hw_addr, id);
	dlock_unlock_id(h->dlock, id, 0);

	return s;
}

int
spppoe_session_hash(gtp_htab_t *h, spppoe_t *s, struct ether_addr *hw_addr, uint16_t id)
{
	struct hlist_head *head;

	dlock_lock_id(h->dlock, s->session_id, 0);
	if (__test_and_set_bit(GTP_PPPOE_FL_SESSION_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.8x already hashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		dlock_unlock_id(h->dlock, s->session_id, 0);
		return -1;
	}

	head = spppoe_session_hashkey(h, hw_addr, id);
	hlist_add_head(&s->h_session, head);
	__sync_add_and_fetch(&s->refcnt, 1);
	dlock_unlock_id(h->dlock, s->session_id, 0);

	return 0;
}

int
spppoe_session_unhash(gtp_htab_t *h, spppoe_t *s)
{
	dlock_lock_id(h->dlock, s->session_id, 0);
	if (!__test_and_clear_bit(GTP_PPPOE_FL_SESSION_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.8x already unhashed !!!"
				    , __FUNCTION__, s->unique, s->session_id);
		dlock_unlock_id(h->dlock, s->session_id, 0);
		return -1;
	}

	hlist_del_init(&s->h_session);
	__sync_sub_and_fetch(&s->refcnt, 1);
	dlock_unlock_id(h->dlock, s->session_id, 0);

	return 0;
}


/*
 *	PPPoE Sessions related
 */
static int
spppoe_generate_id(gtp_conn_t *c)
{
	spppoe_t *s;
	bool inuse[GTP_PPPOE_MAX_SESSION_PER_IMSI] = { 0 };
	int i;

	if (__sync_add_and_fetch(&c->pppoe_cnt, 0) == GTP_PPPOE_MAX_SESSION_PER_IMSI)
		return -1;

	/* Phase 0 : populate inuse table, since session can
	 * be deleted or added we need to mark and look for
	 * available id */
	pthread_mutex_lock(&c->session_mutex);
	list_for_each_entry(s, &c->pppoe_sessions, next)
		inuse[s->id] = true;
	pthread_mutex_unlock(&c->session_mutex);

	/* Phase 1 : return first available id */
	for (i = 0; i < GTP_PPPOE_MAX_SESSION_PER_IMSI; i++) {
		if (!inuse[i]) {
			return i;
		}
	}

	return -1;
}

static int
spppoe_add(gtp_conn_t *c, spppoe_t *s)
{
	pthread_mutex_lock(&c->session_mutex);
	list_add_tail(&s->next, &c->pppoe_sessions);
	__sync_add_and_fetch(&c->pppoe_cnt, 1);
	pthread_mutex_unlock(&c->session_mutex);

	return 0;
}

static int
__spppoe_del(gtp_conn_t *c, spppoe_t *s)
{
	list_head_del(&s->next);
	__sync_sub_and_fetch(&c->pppoe_cnt, 1);
	return 0;
}

static int
spppoe_del(gtp_conn_t *c, spppoe_t *s)
{
	pthread_mutex_lock(&c->session_mutex);
	__spppoe_del(c, s);
	pthread_mutex_unlock(&c->session_mutex);
	return 0;
}

static int
spppoe_release(spppoe_t *s)
{
	spppoe_unique_unhash(&s->pppoe->unique_tab, s);
	spppoe_session_unhash(&s->pppoe->session_tab, s);
	sppp_destroy(s->s_ppp);
	FREE(s);

	return 0;
}

int
__spppoe_destroy(spppoe_t *s)
{
	if (!s)
		return -1;

	__spppoe_del(s->s_gtp->conn, s);
	spppoe_release(s);
	return 0;
}

int
spppoe_destroy(spppoe_t *s)
{
	if (!s)
		return -1;

	spppoe_del(s->s_gtp->conn, s);
	spppoe_release(s);
	return 0;
}

spppoe_t *
spppoe_init(gtp_pppoe_t *pppoe, gtp_conn_t *c,
	    void (*pp_tls)(sppp_t *), void (*pp_tlf)(sppp_t *),
	    void (*pp_con)(sppp_t *), void (*pp_chg)(sppp_t *, int),
	    const uint64_t imsi, const uint64_t mei, const char *apn_str)
{
	spppoe_t *s;
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
	if (__test_bit(PPPOE_FL_GTP_USERNAME_BIT, &pppoe->flags))
		snprintf(s->gtp_username, PPPOE_NAMELEN
					, "%lu+%lu@%s"
					, imsi, mei, apn_str);
	s->s_ppp = sppp_init(s, pp_tls, pp_tlf, pp_con, pp_chg);
	timer_node_init(&s->t_node, NULL, s);
	spppoe_unique_hash(&pppoe->unique_tab, s, imsi, &pppoe->seed);
	spppoe_add(c, s);

	err = pppoe_connect(s);
	if (err < 0) {
		spppoe_destroy(s);
		return NULL;
	}

	return s;
}

int
spppoe_close(spppoe_t *s)
{
	if (!s)
		return -1;

	__set_bit(GTP_PPPOE_FL_DELETE, &s->flags);
	return pppoe_disconnect(s);
}

int
spppoe_disconnect(spppoe_t *s)
{
	if (!s)
		return -1;

	__set_bit(GTP_PPPOE_FL_DELETE_IGNORE, &s->flags);
	return pppoe_disconnect(s);
}
