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

#include "inet_server.h"
#include "gtp_metrics.h"

/* GTP Server context */
typedef struct gtp_server {
	inet_server_t		s;
	void			*ctx;	/* context back-pointer */

	/* metrics */
	gtp_metrics_pkt_t	rx_metrics;
	gtp_metrics_pkt_t	tx_metrics;
	gtp_metrics_cause_t	cause_rx_metrics;
	gtp_metrics_cause_t	cause_tx_metrics;
	gtp_metrics_msg_t	msg_metrics;

	unsigned long		flags;
} gtp_server_t;


/* Prototypes */
int gtp_server_init(gtp_server_t *s, void *ctx,
		    int (*init) (inet_server_t *),
		    int (*process) (inet_server_t *, struct sockaddr_storage *));
int gtp_server_destroy(gtp_server_t *s);
