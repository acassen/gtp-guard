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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <sys/socket.h>
#include "inet_server.h"
#include "gtp_stddef.h"

/* Flags */
enum daemon_flags {
	GTP_FL_STOP_BIT,
	GTP_FL_MIRROR_LOADED_BIT,
	GTP_FL_RESTART_COUNTER_LOADED_BIT,
};

/* Main control block */
struct data {
	char			realm[GTP_STR_MAX_LEN];
	struct sockaddr_storage	nameserver;
	struct inet_server	request_channel;
	struct inet_server	metrics_channel;
	char			restart_counter_filename[GTP_STR_MAX_LEN];
	uint8_t			restart_counter;

	struct list_head	mirror;
	struct list_head	cgn;
	struct list_head	pppoe;
	struct list_head	pppoe_bundle;
	struct list_head	ip_vrf;
	struct list_head	ip_pool;
	struct list_head	bpf_progs;
	struct list_head	interfaces;
	struct list_head	gtp_apn;
	struct list_head	gtp_cdr;
	struct list_head	gtp_proxy_ctx;
	struct list_head	gtp_router_ctx;
	struct list_head	pfcp_peers;;
	struct list_head	pfcp_router_ctx;;

	unsigned long		flags;
};


/* Prototypes */
struct data *alloc_daemon_data(void);
void free_daemon_data(void);
