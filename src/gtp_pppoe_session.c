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

	if (__test_and_set_bit(GTP_PPPOE_UNIQUE_FL_HASHED, &s->flags)) {
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
	if (!__test_and_clear_bit(GTP_PPPOE_UNIQUE_FL_HASHED, &s->flags)) {
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
	if (__test_and_set_bit(GTP_PPPOE_SESSION_FL_HASHED, &s->flags)) {
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
	if (!__test_and_clear_bit(GTP_PPPOE_SESSION_FL_HASHED, &s->flags)) {
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
int
spppoe_destroy(spppoe_t *s)
{
	if (!s)
		return -1;

	spppoe_unique_unhash(&s->pppoe->unique_tab, s);
	spppoe_session_unhash(&s->pppoe->session_tab, s);
	FREE(s);
	return 0;
}

spppoe_t *
spppoe_init(gtp_pppoe_t *pppoe, struct ether_addr *s_eth, uint64_t imsi)
{
	spppoe_t *s;
	int err;

	if (!pppoe)
		return NULL;

	PMALLOC(s);
	s->session_time = time(NULL);
	s->hw_src = *s_eth;
	s->pppoe = pppoe;
	sppp_init(s);
	timer_node_init(&s->t_node, NULL, s);
	spppoe_unique_hash(&pppoe->unique_tab, s, imsi, &pppoe->seed);

	err = pppoe_connect(s);
	if (err < 0) {
		spppoe_destroy(s);
		return NULL;
	}

	return s;
}