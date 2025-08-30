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
typedef struct data {
	char			realm[GTP_STR_MAX_LEN];
	struct sockaddr_storage	nameserver;
	inet_server_t		request_channel;
	inet_server_t		metrics_channel;
	char			restart_counter_filename[GTP_STR_MAX_LEN];
	uint8_t			restart_counter;
	unsigned		nl_rcvbuf_size;

	list_head_t		mirror;
	list_head_t		cgn;
	list_head_t		pppoe;
	list_head_t		pppoe_bundle;
	list_head_t		ip_vrf;
	list_head_t		bpf_progs;
	list_head_t		interfaces;
	list_head_t		gtp_apn;
	list_head_t		gtp_cdr;
	list_head_t		gtp_proxy_ctx;
	list_head_t		gtp_router_ctx;

	unsigned long		flags;
} data_t;


/* Prototypes */
data_t *alloc_daemon_data(void);
void free_daemon_data(void);
