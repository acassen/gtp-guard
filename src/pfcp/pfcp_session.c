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

#include <inttypes.h>
#include <stdint.h>
#include "pfcp_session.h"
#include "pfcp_router.h"
#include "gtp_conn.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "jhash.h"


/* Extern data */
extern struct thread_master *master;

/* Local data */
static struct list_head pfcp_session_unuse;
static int pfcp_session_unuse_count;
static struct hlist_head *pfcp_session_tab;
static int pfcp_sessions_count = 0;
static void pfcp_session_expire(struct thread *t);


/*
 *	Recycle handling
 */
static int
pfcp_session_unuse_destroy(void)
{
	struct pfcp_session *s, *_s;

	list_for_each_entry_safe(s, _s, &pfcp_session_unuse, next) {
		list_head_del(&s->next);
		free(s);
	}
	INIT_LIST_HEAD(&pfcp_session_unuse);

	return 0;
}

int
pfcp_session_unuse_queue_size(void)
{
	return pfcp_session_unuse_count;
}

static struct pfcp_session *
pfcp_session_unuse_trim_head(void)
{
	struct pfcp_session *s;

	if (list_empty(&pfcp_session_unuse))
		return NULL;

	s = list_first_entry(&pfcp_session_unuse, struct pfcp_session, next);
	list_head_del(&s->next);
	memset(s, 0, sizeof(*s));

	__sync_sub_and_fetch(&pfcp_session_unuse_count, 1);
	return s;
}


static struct pfcp_session *
pfcp_session_malloc(void)
{
	struct pfcp_session *s;

	s = pfcp_session_unuse_trim_head();
	if (!s)
		s = calloc(1, sizeof(*s));

	return s;
}

void
pfcp_session_free(struct pfcp_session *s)
{
	INIT_LIST_HEAD(&s->next);
	list_add_tail(&s->next, &pfcp_session_unuse);
	__sync_add_and_fetch(&pfcp_session_unuse_count, 1);
}


/*
 *	PFCP Session hash handling
 */
static struct hlist_head *
pfcp_session_hashkey(struct hlist_head *h, uint64_t id)
{
	return h + (jhash_2words((uint32_t)id, (uint32_t) (id >> 32), 0) & PFCP_SESSION_HASHTAB_MASK);
}

static struct pfcp_session *
_pfcp_session_get(struct hlist_head *h, uint64_t id)
{
	struct hlist_head *head = pfcp_session_hashkey(h, id);
	struct pfcp_session *s;

	hlist_for_each_entry(s, head, hlist) {
		if (s->seid == id) {
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}

	return NULL;
}

struct pfcp_session *
pfcp_session_get(uint64_t id)
{
	return _pfcp_session_get(pfcp_session_tab, id);
}

int
pfcp_session_put(struct pfcp_session *s)
{
	if (!s)
		return -1;

	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
_pfcp_session_hash(struct hlist_head *h, struct pfcp_session *s)
{
	struct hlist_head *head = pfcp_session_hashkey(h, s->seid);

	if (__test_and_set_bit(PFCP_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): pfcp-session:0x%" PRIx64 " already hashed !!!"
				    , __FUNCTION__, s->seid);
		return -1;
	}

	hlist_add_head(&s->hlist, head);
	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
_pfcp_session_unhash(struct hlist_head *h, struct pfcp_session *s)
{
	if (!s)
		return -1;

	if (!__test_and_clear_bit(PFCP_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): pfcp-session:0x%" PRIx64 " already unhashed !!!"
				    , __FUNCTION__, s->seid);
		return -1;
	}
	hlist_del_init(&s->hlist);
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

int
pfcp_session_unhash(struct pfcp_session *s)
{
	return _pfcp_session_unhash(pfcp_session_tab, s);
}

int
pfcp_session_hash(struct pfcp_session *s)
{
	return _pfcp_session_hash(pfcp_session_tab, s);
}


/*
 *	PFCP Sessions handling
 */
int
pfcp_sessions_count_read(void)
{
	return pfcp_sessions_count;
}

void
pfcp_session_mod_timer(struct pfcp_session *s, int timeout)
{
	if (!s->timer)
		s->timer = thread_add_timer(master, pfcp_session_expire, s,
					    (uint64_t) timeout * TIMER_HZ);
	else
		thread_mod_timer(s->timer, (uint64_t) timeout * TIMER_HZ);
}

static void
pfcp_session_add_timer(struct pfcp_session *s)
{
	struct gtp_apn *apn = s->apn;

	if (!apn->session_lifetime)
		return;

	/* Sort it by timeval */
	pfcp_session_mod_timer(s, apn->session_lifetime);
}

static int
pfcp_session_add(struct gtp_conn *c, struct pfcp_session *s)
{
	list_add_tail(&s->next, &c->pfcp_sessions);
	__sync_add_and_fetch(&c->refcnt, 1);
	__sync_add_and_fetch(&pfcp_sessions_count, 1);
	return 0;
}

static uint64_t
pfcp_session_seid_alloc(struct pfcp_router *r)
{
	struct pfcp_session *s;
	uint64_t seid = 0;
	int retry = 0;

shoot_again:
	seid = xorshift_prng(&r->seed);
	s = pfcp_session_get(seid);
	if (!s)
		return seid;

	pfcp_session_put(s);

	/* allocation active loop prevention */
	if (retry++ < 5)
		goto shoot_again;

	return 0;
}

struct pfcp_session *
pfcp_session_alloc(struct gtp_conn *c, struct gtp_apn *apn, struct pfcp_router *r)
{
	struct pfcp_session *new;
	uint64_t seid;

	new = pfcp_session_malloc();
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&new->next);
	new->apn = apn;
	new->conn = c;
	new->router = r;
	time_now_to_calendar(&new->creation_time);
	seid = pfcp_session_seid_alloc(r);
	if (!seid) {
		log_message(LOG_INFO, "%s(): Something weird while allocating seid !!!"
				    , __FUNCTION__);
		free(new);
		return NULL;
	}
	new->seid = seid;

	/* CDR context */
	if (apn->cdr_spool)
		new->cdr = gtp_cdr_alloc();

	pfcp_session_add(c, new);
	pfcp_session_hash(new);
	pfcp_session_add_timer(new);
	__sync_add_and_fetch(&apn->session_count, 1);
	return new;
}

static int
pfcp_session_release(struct pfcp_session *s)
{
	__sync_sub_and_fetch(&s->apn->session_count, 1);
	__sync_sub_and_fetch(&pfcp_sessions_count, 1);
	gtp_apn_cdr_commit(s->apn, s->cdr);
//	pfcp_session_bpf__destroy(s);
	list_head_del(&s->next);
	pfcp_session_unhash(s);
	pfcp_session_free(s);
	return 0;
}

int
pfcp_session_destroy(struct pfcp_session *s)
{
	struct gtp_conn *c = s->conn;

	thread_del(s->timer);
	pfcp_session_release(s);

	/* Release connection if no more sessions */
	if (__sync_sub_and_fetch(&c->refcnt, 1) == 0) {
		gtp_conn_unhash(c);
		log_message(LOG_INFO, "IMSI:%ld - no more sessions - Releasing tracking"
				    , c->imsi);
		free(c);
	}

	return 0;
}


/*
 *	Session expiration handling
 */
static void
pfcp_session_expire(struct thread *t)
{
	struct pfcp_session *s = THREAD_ARG(t);

	log_message(LOG_INFO, "IMSI:%ld - Expiring pfcp-session-id:0x%" PRIx64 ""
			    , s->conn->imsi, s->seid);
	pfcp_session_destroy(s);
}

int
pfcp_sessions_release(struct gtp_conn *c)
{
	struct list_head *l = &c->pfcp_sessions;
	struct pfcp_session *s, *_s;

	/* Release sessions */
	list_for_each_entry_safe(s, _s, l, next)
		pfcp_session_destroy(s);

	return 0;
}

int
pfcp_sessions_free(struct gtp_conn *c)
{
	struct list_head *l = &c->pfcp_sessions;
	struct pfcp_session *s, *_s;

	list_for_each_entry_safe(s, _s, l, next) {
		thread_del(s->timer);
		pfcp_session_release(s);
	}

	return 0;
}


/*
 *	PFCP Sessions.
 */
int
pfcp_sessions_int(void)
{
	INIT_LIST_HEAD(&pfcp_session_unuse);
	pfcp_session_tab = calloc(PFCP_SESSION_HASHTAB_SIZE, sizeof(struct hlist_head));
	return 0;
}

int
pfcp_sessions_destroy(void)
{
	struct hlist_node *n;
	struct pfcp_session *s;
	int i;

	for (i = 0; i < PFCP_SESSION_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(s, n, &pfcp_session_tab[i], hlist) {
			free(s);
		}
	}

	free(pfcp_session_tab);
	pfcp_session_unuse_destroy();
	return 0;
}
