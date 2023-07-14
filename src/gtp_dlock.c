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
#include <errno.h>

/* local includes */
#include "memory.h"
#include "logger.h"
#include "list_head.h"
#include "jhash.h"
#include "gtp_dlock.h"

/*
 *      Distributate lock handling
 */
static dlock_mutex_t *
dlock_hash(dlock_mutex_t *__array, uint32_t w1, uint32_t w2)
{
	return __array + (jhash_2words(w1, w2, 0) & DLOCK_HASHTAB_MASK);
}

int
dlock_lock_id(dlock_mutex_t *__array, uint32_t w1, uint32_t w2)
{
	dlock_mutex_t *m = dlock_hash(__array, w1, w2);
	pthread_mutex_lock(&m->mutex);
	__sync_add_and_fetch(&m->refcnt, 1);
	return 0;
}

int
dlock_unlock_id(dlock_mutex_t *__array, uint32_t w1, uint32_t w2)
{
	dlock_mutex_t *m = dlock_hash(__array, w1, w2);
	if (__sync_sub_and_fetch(&m->refcnt, 1) == 0)
		pthread_mutex_unlock(&m->mutex);
	return 0;
}

dlock_mutex_t *
dlock_init(void)
{
	dlock_mutex_t *new;
	new = (dlock_mutex_t *) MALLOC(DLOCK_HASHTAB_SIZE * sizeof(dlock_mutex_t));
        return new;
}

int
dlock_destroy(dlock_mutex_t *__array)
{
	FREE(__array);
	return 0;
}
