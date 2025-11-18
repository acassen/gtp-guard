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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include "inet_server.h"
#include "pfcp_msg.h"
#include "pfcp_metrics.h"

enum pfcp_server_flags {
	PFCP_FL_RUNNING_BIT,
};

/* PFCP Server context */
struct pfcp_server {
	struct inet_server	s;
	struct pfcp_msg		*msg;
	void			*ctx;	/* context back-pointer */

	/* metrics */
	struct pfcp_metrics_pkt	rx_metrics;
	struct pfcp_metrics_pkt	tx_metrics;
	struct pfcp_metrics_msg	msg_metrics;

	unsigned long		flags;
};


/* Prototypes */
int pfcp_server_init(struct pfcp_server *s, void *ctx,
		     int (*init) (struct inet_server *),
		     int (*process) (struct inet_server *, struct sockaddr_storage *));
int pfcp_server_destroy(struct pfcp_server *s);
