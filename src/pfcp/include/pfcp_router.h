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

#include "gtp_stddef.h"
#include "inet_server.h"
#include "list_head.h"

enum pfcp_flags {
	PFCP_ROUTER_FL_SHUTDOWN_BIT,
};

struct pfcp_router {
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	struct inet_server	s;

	/* metrics */


	struct list_head	next;

	unsigned long		flags;
};

/* Prototypes */
int pfcp_router_dump(struct pfcp_router *c, char *buffer, size_t bsize);
struct pfcp_router *pfcp_router_get_by_name(const char *name);
void pfcp_router_release(struct pfcp_router *c);
struct pfcp_router *pfcp_router_alloc(const char *name);
int pfcp_router_init(void);
int pfcp_router_destroy(void);
