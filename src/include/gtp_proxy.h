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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <stdint.h>
#include "gtp_htab.h"
#include "gtp_server.h"
#include "gtp_resolv.h"
#include "gtp_iptnl.h"
#include "gtp_teid.h"
#include "gtp_bpf_prog.h"

/* GTP Proxy context */
struct gtp_proxy {
	char			name[GTP_NAME_MAX_LEN];
	struct gtp_bpf_prog	*bpf_prog;
	struct gtp_server	gtpc;
	struct gtp_server	gtpc_egress;
	struct gtp_server	gtpu;
	struct gtp_server	gtpu_egress;
	int			session_delete_to;

	struct gtp_htab		gtpc_teid_tab;	/* GTP-C teid hashtab */
	struct gtp_htab		gtpu_teid_tab;	/* GTP-U teid hashtab */
	struct gtp_htab		vteid_tab;	/* virtual teid hashtab */
	struct gtp_htab		vsqn_tab;	/* virtual Seqnum hashtab */
	uint32_t		seqnum;		/* Global context Seqnum */

	struct gtp_naptr	*pgw;
	struct sockaddr_storage	pgw_addr;

	struct gtp_iptnl	iptnl;

	unsigned long		flags;
	uint32_t		refcnt;

	struct list_head	next;
};


/* Prototypes */
int gtp_proxy_gtpc_teid_destroy(struct gtp_teid *teid);
int gtp_proxy_gtpu_teid_destroy(struct gtp_teid *teid);
int gtp_proxy_ingress_init(struct inet_server *srv);
int gtp_proxy_ingress_process(struct inet_server *srv,
			      struct sockaddr_storage *addr_from);
struct gtp_proxy *gtp_proxy_get(const char *name);
struct gtp_proxy *gtp_proxy_init(const char *name);
int gtp_proxy_ctx_server_destroy(struct gtp_proxy *ctx);
int gtp_proxy_ctx_destroy(struct gtp_proxy *ctx);
int gtp_proxy_server_destroy(void);
int gtp_proxy_destroy(void);
int gtp_proxy_vty_init(void);
