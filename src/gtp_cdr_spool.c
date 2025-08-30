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

#include <errno.h>
#include <sys/prctl.h>

#include "gtp_data.h"
#include "gtp_cdr_asn1.h"
#include "gtp_cdr_spool.h"
#include "logger.h"
#include "bitops.h"
#include "memory.h"
#include "utils.h"


/* Extern data */
extern data_t *daemon_data;

/* Local data */
pthread_mutex_t gtp_cdr_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 *	Spool Queue
 */
static int
gtp_cdr_spool_commit(gtp_cdr_spool_t *s, gtp_cdr_t *c)
{
	gtp_cdr_file_t *f = s->cdr_file;
	size_t bsize;
	int err;

	gtp_cdr_close(c);
	bsize = gtp_cdr_asn1_pgw_record_encode(c, s->q_buf, GTP_BUFFER_SIZE);
	gtp_cdr_destroy(c);
	err = gtp_cdr_file_write(f, s->q_buf, bsize);
	if (err) {
		/* This one will be lost in translation... */
		log_message(LOG_INFO, "%s(): Error writing cdr into file:%s (%m)..."
				      " dropping CDR"
				    , __FUNCTION__
				    , f->file->path);
		return -1;
	}

	/* Update stats */
	s->cdr_count++;
	s->cdr_bytes += bsize;
	return 0;
}

static int
gtp_cdr_spool_q_run(gtp_cdr_spool_t *s)
{
	list_head_t *l = &s->q;
	gtp_cdr_t *c, *_c;

	pthread_mutex_lock(&s->q_mutex);
	list_for_each_entry_safe(c, _c, l, next) {
		list_head_del(&c->next);
		pthread_mutex_unlock(&s->q_mutex);

		gtp_cdr_spool_commit(s, c);
		__sync_sub_and_fetch(&s->q_len, 1);

		pthread_mutex_lock(&s->q_mutex);
	}
	pthread_mutex_unlock(&s->q_mutex);

	return 0;
}

static int
gtp_cdr_spool_roll(gtp_cdr_spool_t *s)
{
	gtp_cdr_file_t *f = s->cdr_file;

	if (!f->file)
		return -1;

	if (time(NULL) < f->roll_time)
		return -1;

	return gtp_cdr_file_close(f);
}

static void *
gtp_cdr_spool_q_task(void *arg)
{
	gtp_cdr_spool_t *s = arg;
	struct timespec timeout;
	timeval_t now;

	/* Our identity */
	prctl(PR_SET_NAME, s->name, 0, 0, 0, 0);

q_process:
	/* Schedule interruptible timeout */
	pthread_mutex_lock(&s->cond_mutex);
	monotonic_gettimeofday(&now);
	timespec_add_now_ms(&timeout, &now, 500 * TIMER_HZ); /* 500ms granularity */
	pthread_cond_timedwait(&s->cond, &s->cond_mutex, &timeout);
	pthread_mutex_unlock(&s->cond_mutex);

	if (__test_bit(GTP_CDR_SPOOL_FL_STOP_BIT, &s->flags))
		goto q_finish;

	/* Current file needs to be rolled ? */
	gtp_cdr_spool_roll(s);

	/* Queue processing */
	gtp_cdr_spool_q_run(s);

	goto q_process;

q_finish:
	return NULL;
}

static int
gtp_cdr_spool_q_signal(gtp_cdr_spool_t *s)
{
	pthread_mutex_lock(&s->cond_mutex);
	pthread_cond_signal(&s->cond);
	pthread_mutex_unlock(&s->cond_mutex);
	return 0;
}

static int
gtp_cdr_spool_q_destroy(gtp_cdr_spool_t *s)
{
	list_head_t *l = &s->q;
	gtp_cdr_t *c, *_c;

	pthread_mutex_lock(&s->q_mutex);
	list_for_each_entry_safe(c, _c, l, next) {
		list_head_del(&c->next);
		gtp_cdr_destroy(c);
		__sync_sub_and_fetch(&s->q_len, 1);
	}
	pthread_mutex_unlock(&s->q_mutex);

	INIT_LIST_HEAD(l);
	return 0;
}

int
gtp_cdr_spool_q_add(gtp_cdr_spool_t *s, gtp_cdr_t *c)
{
	if (__test_bit(GTP_CDR_SPOOL_FL_SHUTDOWN_BIT, &s->flags)) {
		gtp_cdr_destroy(c);
		return -1;
	}

	/* This one will be lost in translation... */
	if (s->q_max_size && s->q_len >= s->q_max_size) {
		log_message(LOG_INFO, "%s(): cdr q for spool:%s overflow..."
				      " dropping CDR"
				    , __FUNCTION__
				    , s->name);
		return -1;
	}

	pthread_mutex_lock(&s->q_mutex);
	list_add_tail(&c->next, &s->q);
	pthread_mutex_unlock(&s->q_mutex);

	__sync_add_and_fetch(&s->q_len, 1);
	gtp_cdr_spool_q_signal(s);
	return 0;
}


/*
 *	Spool init
 */
gtp_cdr_spool_t *
gtp_cdr_spool_get(const char *name)
{
	gtp_cdr_spool_t *s;

	pthread_mutex_lock(&gtp_cdr_mutex);
	list_for_each_entry(s, &daemon_data->gtp_cdr, next) {
		if (!strncmp(s->name, name, GTP_STR_MAX_LEN)) {
			pthread_mutex_unlock(&gtp_cdr_mutex);
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}
	pthread_mutex_unlock(&gtp_cdr_mutex);

	return NULL;
}

int
gtp_cdr_spool_put(gtp_cdr_spool_t *s)
{
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

gtp_cdr_spool_t *
gtp_cdr_spool_alloc(const char *name)
{
	gtp_cdr_spool_t *n;
	gtp_cdr_file_t *f;

	PMALLOC(n);
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	bsd_strlcpy(n->name, name, GTP_STR_MAX_LEN);
	INIT_LIST_HEAD(&n->next);
	INIT_LIST_HEAD(&n->q);
	pthread_mutex_init(&n->q_mutex, NULL);
	pthread_mutex_init(&n->cond_mutex, NULL);
	pthread_cond_init(&n->cond, NULL);

	n->roll_period = GTP_CDR_DEFAULT_ROLLPERIOD;
	f = gtp_cdr_file_alloc();
	n->cdr_file = f;
	f->spool = n;

	pthread_mutex_lock(&gtp_cdr_mutex);
	list_add_tail(&n->next, &daemon_data->gtp_cdr);
	pthread_mutex_unlock(&gtp_cdr_mutex);

	return n;
}

int
gtp_cdr_spool_start(gtp_cdr_spool_t *s)
{
	return pthread_create(&s->task, NULL, gtp_cdr_spool_q_task, s);
}

int
gtp_cdr_spool_stop(gtp_cdr_spool_t *s)
{
	__set_bit(GTP_CDR_SPOOL_FL_STOP_BIT, &s->flags);
	gtp_cdr_spool_q_signal(s);
	pthread_join(s->task, NULL);
	gtp_cdr_spool_q_destroy(s);
	__clear_bit(GTP_CDR_SPOOL_FL_STOP_BIT, &s->flags);
	return 0;
}

static int
__gtp_cdr_spool_destroy(gtp_cdr_spool_t *s)
{
	gtp_cdr_spool_stop(s);
	pthread_mutex_destroy(&s->q_mutex);
	pthread_mutex_destroy(&s->cond_mutex);
	pthread_cond_destroy(&s->cond);
	gtp_cdr_file_destroy(s->cdr_file);
	list_head_del(&s->next);
	FREE(s);
	return 0;
}

int
gtp_cdr_spool_destroy(gtp_cdr_spool_t *spool)
{
	list_head_t *l = &daemon_data->gtp_cdr;
	gtp_cdr_spool_t *s, *_s;
	int err = 0;

	pthread_mutex_lock(&gtp_cdr_mutex);
	if (spool) {
		if (__sync_add_and_fetch(&spool->refcnt, 0)) {
			err = -1;
			goto end;
		}

		__gtp_cdr_spool_destroy(spool);
		goto end;
	}

	list_for_each_entry_safe(s, _s, l, next)
		__gtp_cdr_spool_destroy(s);

end:
	pthread_mutex_unlock(&gtp_cdr_mutex);
	return err;
}
