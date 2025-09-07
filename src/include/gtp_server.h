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
struct gtp_server {
	struct inet_server	s;
	void			*ctx;	/* context back-pointer */

	/* metrics */
	struct gtp_metrics_pkt	rx_metrics;
	struct gtp_metrics_pkt	tx_metrics;
	struct gtp_metrics_cause cause_rx_metrics;
	struct gtp_metrics_cause cause_tx_metrics;
	struct gtp_metrics_msg	msg_metrics;

	unsigned long		flags;
};


/* Prototypes */
int gtp_server_init(struct gtp_server *s, void *ctx,
		    int (*init) (struct inet_server *),
		    int (*process) (struct inet_server *, struct sockaddr_storage *));
int gtp_server_destroy(struct gtp_server *s);
