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

#ifndef _GTP_SERVER_H
#define _GTP_SERVER_H

/* GTP Switching context */
typedef struct _gtp_server_worker {
	char			pname[GTP_PNAME];
	int			id;
	pthread_t		task;
	int			fd;
	struct _gtp_server	*srv;		/* backpointer */
	pkt_buffer_t		*pbuff;
	unsigned int		seed;

	/* stats */
	uint64_t		rx_bytes;
	uint64_t		tx_bytes;
	uint64_t		rx_pkt;
	uint64_t		tx_pkt;

	list_head_t		next;

	unsigned long		flags;
} gtp_server_worker_t;

typedef struct _gtp_server {
	struct sockaddr_storage	addr;
	int			thread_cnt;
	void			*ctx;		/* backpointer */

	pthread_mutex_t		workers_mutex;
	list_head_t		workers;

	/* Local method */
	int (*init) (gtp_server_worker_t *);
	int (*process) (gtp_server_worker_t *, struct sockaddr_storage *);

	unsigned long		flags;
} gtp_server_t;


/* Prototypes */
extern ssize_t gtp_server_send(gtp_server_worker_t *, int, struct sockaddr_in *);
extern int gtp_server_start(gtp_server_t *);
extern int gtp_server_for_each_worker(gtp_server_t *, int (*hdl) (gtp_server_worker_t *));
extern int gtp_server_init(gtp_server_t *, void *
					 , int (*init) (gtp_server_worker_t *)
					 , int (*process) (gtp_server_worker_t *, struct sockaddr_storage *));
extern int gtp_server_destroy(gtp_server_t *);


#endif
