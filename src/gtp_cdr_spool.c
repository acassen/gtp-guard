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

/* system includes */
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;

/* Local data */
pthread_mutex_t gtp_cdr_mutex = PTHREAD_MUTEX_INITIALIZER;



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

	INIT_LIST_HEAD(&n->next);
	bsd_strlcpy(n->name, name, GTP_STR_MAX_LEN);
	f = gtp_cdr_file_alloc();
	n->cdr_file = f;
	f->spool = n;

	pthread_mutex_lock(&gtp_cdr_mutex);
	list_add_tail(&n->next, &daemon_data->gtp_cdr);
	pthread_mutex_unlock(&gtp_cdr_mutex);

	return n;
}

static int
__gtp_cdr_spool_destroy(gtp_cdr_spool_t *s)
{
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
