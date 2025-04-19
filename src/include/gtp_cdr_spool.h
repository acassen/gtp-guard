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

#ifndef _GTP_CDR_SPOOL_H
#define _GTP_CDR_SPOOL_H

/* Flags */
enum gtp_cdr_file_flags {
	GTP_CDR_SPOOL_FL_ASYNC_BIT,
	GTP_CDR_SPOOL_FL_SHUTDOWN_BIT,
	GTP_CDR_SPOOL_FL_STOP_BIT,
};

/* Spool data structure */
typedef struct _gtp_cdr_spool {
	char			name[GTP_STR_MAX_LEN];
	char			document_root[GTP_PATH_MAX_LEN];
	char			archive_root[GTP_PATH_MAX_LEN];
	char			prefix[GTP_NAME_MAX_LEN];
	int			roll_period;

	gtp_cdr_file_t		*cdr_file;
	size_t			cdr_file_size;

	list_head_t		q;
	uint8_t			q_buf[GTP_BUFFER_SIZE];
	int			q_size;
	int			q_max_size;
	pthread_mutex_t		q_mutex;
	pthread_t		task;
	pthread_cond_t		cond;
	pthread_mutex_t		cond_mutex;

	/* stats */
	uint64_t		cdr_count;
	uint64_t		cdr_bytes;

	list_head_t		next;

	int			refcnt;
	unsigned long		flags;
} gtp_cdr_spool_t;


/* Prototypes */
extern int gtp_cdr_spool_q_add(gtp_cdr_spool_t *, gtp_cdr_t *);
extern gtp_cdr_spool_t *gtp_cdr_spool_get(const char *);
extern int gtp_cdr_spool_put(gtp_cdr_spool_t *);
extern int gtp_cdr_spool_start(gtp_cdr_spool_t *);
extern int gtp_cdr_spool_stop(gtp_cdr_spool_t *);
extern gtp_cdr_spool_t *gtp_cdr_spool_alloc(const char *);
extern int gtp_cdr_spool_destroy(gtp_cdr_spool_t *);

#endif
