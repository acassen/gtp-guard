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

#include "gtp_server.h"
#include "gtp_bpf_prog.h"

#define GTP_ROUTER_DELAYED	2

typedef struct gtp_router {
	char			name[GTP_NAME_MAX_LEN];
	gtp_bpf_prog_t		*bpf_prog;
	gtp_server_t		gtpc;
	gtp_server_t		gtpu;

	unsigned long		flags;
	uint32_t		refcnt;

	list_head_t		next;
} gtp_router_t;


/* Prototypes */
int gtp_router_ingress_init(inet_server_t *srv);
int gtp_router_ingress_process(inet_server_t *srv,
			       struct sockaddr_storage *addr_from);
bool gtp_router_inuse(void);
void gtp_router_foreach(int (*hdl) (gtp_router_t *, void *), void *arg);
gtp_router_t *gtp_router_get(const char *name);
gtp_router_t *gtp_router_init(const char *name);
int gtp_router_ctx_destroy(gtp_router_t *ctx);
int gtp_router_server_destroy(void);
int gtp_router_destroy(void);
int gtp_router_vty_init(void);
