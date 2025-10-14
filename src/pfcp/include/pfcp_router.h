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

#include "pfcp_server.h"
#include "gtp_bpf_prog.h"

#define PFCP_ROUTER_DELAYED	2

enum pfcp_flags {
	PFCP_ROUTER_FL_LISTEN_BIT,
};

enum pfcp_debug_flags {
	PFCP_DEBUG_FL_INGRESS_MSG_BIT,
	PFCP_DEBUG_FL_EGRESS_MSG_BIT,
};

struct pfcp_router {
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	struct gtp_bpf_prog	*bpf_prog;
	struct pfcp_server	s;
	unsigned long		debug;

	char			node_id[GTP_NAME_MAX_LEN];
	uint32_t		recovery_ts;

	unsigned long		flags;

	struct list_head	next;
};

/* Prototypes */
int pfcp_router_ingress_init(struct inet_server *srv);
int pfcp_router_ingress_process(struct inet_server *srv,
			        struct sockaddr_storage *addr_from);
size_t pfcp_router_dump(struct pfcp_router *ctx, char *buffer, size_t bsize);
bool pfcp_router_inuse(void);
void pfcp_router_foreach(int (*hdl) (struct pfcp_router *, void *), void *arg);
struct pfcp_router *pfcp_router_get(const char *name);
struct pfcp_router *pfcp_router_alloc(const char *name);
int pfcp_router_ctx_destroy(struct pfcp_router *ctx);
int pfcp_router_destroy(void);
