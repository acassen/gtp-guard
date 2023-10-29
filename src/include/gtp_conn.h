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

#ifndef _GTP_CONN_H
#define _GTP_CONN_H

/* Hash table */
#define CONN_HASHTAB_BITS  20
#define CONN_HASHTAB_SIZE  (1 << CONN_HASHTAB_BITS)
#define CONN_HASHTAB_MASK  (CONN_HASHTAB_SIZE - 1)

/* Connection flags */
enum conn_flags {
	GTP_CONN_F_HASHED,
};

typedef struct _gtp_conn {
        uint64_t                imsi;
	struct sockaddr_in	sgw_addr;
	gtp_ctx_t		*ctx;

	/* FIXME: maybe use a global dlock here */
	list_head_t		gtp_sessions;
        pthread_mutex_t		gtp_session_mutex;

	time_t			ts;

	/* hash stuff */
        struct hlist_node       hlist;

	unsigned long		flags;
	int			refcnt;
} gtp_conn_t;


/* Prototypes */
extern int gtp_conn_get(gtp_conn_t *);
extern int gtp_conn_put(gtp_conn_t *);
extern gtp_conn_t *gtp_conn_alloc(uint64_t, gtp_ctx_t *);
extern gtp_conn_t *gtp_conn_get_by_imsi(uint64_t);
extern int gtp_conn_hash(gtp_conn_t *);
extern int gtp_conn_unhash(gtp_conn_t *);
extern int gtp_conn_vty(vty_t *, int (*vty_conn) (vty_t *, gtp_conn_t *), uint64_t);
extern int gtp_conn_init(void);
extern int gtp_conn_destroy(void);

#endif
