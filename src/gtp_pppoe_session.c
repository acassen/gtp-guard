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
static struct hlist_head *
gtp_pppoe_session_hashkey(gtp_htab_t *h, uint32_t id)
{
	return h->htab + (jhash_1word(id, 0) & CONN_HASHTAB_MASK);
}

static gtp_pppoe_session_t *
__gtp_pppoe_session_get(gtp_htab_t *h, uint32_t id)
{
	struct hlist_head *head = gtp_pppoe_session_hashkey(h, id);
	struct hlist_node *n;
	gtp_pppoe_session_t *s;

	hlist_for_each_entry(s, n, head, hlist) {
		if (s->unique == id) {
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}

	return NULL;
}

gtp_pppoe_session_t *
gtp_pppoe_session_get(gtp_htab_t *h, uint32_t id)
{
	gtp_pppoe_session_t *s;

	dlock_lock_id(h->dlock, id, 0);
	s = __gtp_pppoe_session_get(h, id);
	dlock_unlock_id(h->dlock, id, 0);

	return s;
}

int
__gtp_pppoe_session_hash(gtp_htab_t *h, gtp_pppoe_session_t *s, uint32_t id)
{
	struct hlist_head *head;

	if (__test_and_set_bit(GTP_PPPOE_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.8x already hashed !!!"
				    , __FUNCTION__, s->unique, ntohl(s->session_id));
		return -1;
	}

	head = gtp_pppoe_session_hashkey(h, id);
	s->unique = id;
	hlist_add_head(&s->hlist, head);

	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

int
gtp_pppoe_session_unhash(gtp_htab_t *h, gtp_pppoe_session_t *s)
{
	dlock_lock_id(h->dlock, s->unique, 0);
	if (!__test_and_clear_bit(GTP_PPPOE_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): unique:0x%.8x for session:0x%.8x already unhashed !!!"
				    , __FUNCTION__, s->unique, ntohl(s->session_id));
		dlock_unlock_id(h->dlock, s->unique, 0);
		return -1;
	}

	hlist_del_init(&s->hlist);
	__sync_sub_and_fetch(&s->refcnt, 1);
	dlock_unlock_id(h->dlock, s->unique, 0);

	return 0;
}

int
gtp_pppoe_session_hash(gtp_htab_t *h, gtp_pppoe_session_t *s, uint64_t imsi, unsigned int *seed)
{
	gtp_pppoe_session_t *_s;
	uint32_t id;
	int i;

  shoot_again:
	id = poor_prng(seed) ^ (uint32_t) imsi;

	dlock_lock_id(h->dlock, id, 0);
	_s = __gtp_pppoe_session_get(h, id);
	if (_s) {
		dlock_unlock_id(h->dlock, id, 0);
		/* same player */
		__sync_sub_and_fetch(&_s->refcnt, 1);
		goto shoot_again;
	}

	__gtp_pppoe_session_hash(h, s, id);
	dlock_unlock_id(h->dlock, id, 0);
	return 0;
}


/*
 *	PPPoE timer
 */
RB_TIMER_LESS(gtp_pppoe_session, n);

void
gtp_pppoe_timer_add(gtp_pppoe_timer_t *t, gtp_pppoe_session_t *s, int sec)
{
	pthread_mutex_lock(&t->timer_mutex);
	s->sands = timer_add_now_sec(s->sands, sec);
	rb_add_cached(&s->n, &t->timer, gtp_pppoe_session_timer_less);
	pthread_mutex_unlock(&t->timer_mutex);
}

void
gtp_pppoe_timer_del(gtp_pppoe_timer_t *t, gtp_pppoe_session_t *s)
{
	pthread_mutex_lock(&t->timer_mutex);
	rb_erase_cached(&s->n, &t->timer);
	pthread_mutex_unlock(&t->timer_mutex);
}

static void
gtp_pppoe_timer_fired(gtp_pppoe_timer_t *t, timeval_t *now)
{
	gtp_pppoe_session_t *s;
	rb_node_t *s_node;

	pthread_mutex_lock(&t->timer_mutex);
	while ((s_node = rb_first_cached(&t->timer))) {
		s = rb_entry(s_node, gtp_pppoe_session_t, n);

		if (timercmp(now, &s->sands, <))
			break;

		rb_erase_cached(&s->n, &t->timer);

		pthread_mutex_unlock(&t->timer_mutex);
		pppoe_timeout(s);
		pthread_mutex_lock(&t->timer_mutex);
	}
	pthread_mutex_unlock(&t->timer_mutex);
}

static void *
gtp_pppoe_timer_task(void *arg)
{
	gtp_pppoe_timer_t *t = arg;
	struct timespec timeout;
	timeval_t now;
	char pname[128];

	/* Our identity */
	snprintf(pname, 127, "pppoe-timer-%s", t->pppoe->ifname);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

  timer_process:
	/* Schedule interruptible timeout */
	pthread_mutex_lock(&t->cond_mutex);
	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + 1;	/* 1sec granularity */
	timeout.tv_nsec = now.tv_usec * 1000;
	pthread_cond_timedwait(&t->cond, &t->cond_mutex, &timeout);
	pthread_mutex_unlock(&t->cond_mutex);

	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		goto timer_finish;

	/* Expiration handling */
	gtp_pppoe_timer_fired(t, &now);

	goto timer_process;

  timer_finish:
	return NULL;
}

int
gtp_pppoe_timer_init(gtp_pppoe_t *pppoe, gtp_pppoe_timer_t *t)
{
	t->timer = RB_ROOT_CACHED;
	t->pppoe = pppoe;
	pthread_mutex_init(&t->timer_mutex, NULL);
	pthread_mutex_init(&t->cond_mutex, NULL);
	pthread_cond_init(&t->cond, NULL);

	pthread_create(&t->task, NULL, gtp_pppoe_timer_task, t);
	return 0;
}

static int
gtp_pppoe_timer_signal(gtp_pppoe_timer_t *t)
{
	pthread_mutex_lock(&t->cond_mutex);
	pthread_cond_signal(&t->cond);
	pthread_mutex_unlock(&t->cond_mutex);
	return 0;
}

int
gtp_pppoe_timer_destroy(gtp_pppoe_timer_t *t)
{
	gtp_pppoe_timer_signal(t);
	pthread_join(t->task, NULL);
	return 0;
}


/*
 *	PPPoE Sessions related
 */
int
gtp_pppoe_session_destroy(gtp_pppoe_session_t *s)
{
	if (!s)
		return -1;

	gtp_pppoe_session_unhash(&s->pppoe->session_tab, s);
	FREE(s);
	return 0;
}

gtp_pppoe_session_t *
gtp_pppoe_session_init(gtp_pppoe_t *pppoe, struct ether_addr *s_eth, uint64_t imsi)
{
	gtp_pppoe_session_t *s;
	int err;

	if (!pppoe)
		return NULL;

	PMALLOC(s);
	s->session_time = time(NULL);
	s->hw_src = *s_eth;
	s->pppoe = pppoe;
	gtp_pppoe_session_hash(&pppoe->session_tab, s, imsi, &pppoe->seed);

	err = pppoe_connect(s);
	if (err < 0) {
		gtp_pppoe_session_destroy(s);
		return NULL;
	}

	return s;
}