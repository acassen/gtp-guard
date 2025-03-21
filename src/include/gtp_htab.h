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

#ifndef _GTP_HTAB_H
#define _GTP_HTAB_H

/* Distributed lock */
#define DLOCK_HASHTAB_BITS    10
#define DLOCK_HASHTAB_SIZE    (1 << DLOCK_HASHTAB_BITS)
#define DLOCK_HASHTAB_MASK    (DLOCK_HASHTAB_SIZE - 1)

/* htab */
typedef struct _gtp_htab {
	struct hlist_head	*htab;
	pthread_mutex_t		*dlock;
} gtp_htab_t;

/* Prototypes */
extern int dlock_lock_id(pthread_mutex_t *, uint32_t, uint32_t);
extern int dlock_unlock_id(pthread_mutex_t *, uint32_t, uint32_t);
extern pthread_mutex_t *dlock_init(void);
extern void gtp_htab_init(gtp_htab_t *, size_t);
extern void gtp_htab_destroy(gtp_htab_t *);

#endif
