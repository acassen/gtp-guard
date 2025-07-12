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
#pragma once

#define DEFAULT_SOCKBUF	(64 * 1024)

/* GTP Server context */
typedef struct _gtp_server {
	struct sockaddr_storage	addr;
	int			fd;
	pkt_buffer_t		*pbuff;
	unsigned int		seed;
	void			*ctx;		/* backpointer */

	/* I/O MUX */
	thread_t		*r_thread;
	thread_t		*w_thread;

	/* Local method */
	int (*init) (struct _gtp_server *);
	int (*process) (struct _gtp_server *, struct sockaddr_storage *);

	/* metrics */
	uint64_t		rx_pkts;
	uint64_t		rx_errors;
	uint64_t		tx_pkts;
	uint64_t		tx_errors;
	gtp_metrics_pkt_t	rx_metrics;
	gtp_metrics_pkt_t	tx_metrics;
	gtp_metrics_cause_t	cause_rx_metrics;
	gtp_metrics_cause_t	cause_tx_metrics;
	gtp_metrics_msg_t	msg_metrics;

	unsigned long		flags;
} gtp_server_t;


/* Prototypes */
extern ssize_t gtp_server_send(gtp_server_t *, int, pkt_buffer_t *, struct sockaddr_in *);
extern int gtp_server_start(gtp_server_t *);
extern int gtp_server_foreach_worker(gtp_server_t *, int (*hdl) (gtp_server_t *, void *), void *);
extern int gtp_server_init(gtp_server_t *, void *
					 , int (*init) (gtp_server_t *)
					 , int (*process) (gtp_server_t *, struct sockaddr_storage *));
extern int gtp_server_destroy(gtp_server_t *);
