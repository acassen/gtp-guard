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

#include <stdint.h>
#include "gtp_server.h"
#include "gtp_resolv.h"
#include "gtp_iptnl.h"
#include "gtp_teid.h"
#include "gtp_interface.h"
#include "gtp_bpf_prog.h"
#include "gtp_bpf_fwd.h"

#define GTP_PROXY_REMOTE_ADDR_HSIZE	1000

struct gtp_bpf_ifrules;
struct gtp_if_rule;

struct gtp_proxy_remote_addr {
	uint32_t		addr;
	struct hlist_node	hlist;
};

/* GTP Proxy context */
struct gtp_proxy {
	char			name[GTP_NAME_MAX_LEN];
	struct gtp_bpf_prog	*bpf_prog;
	struct gtp_bpf_fwd_data *bpf_data;
	struct list_head	bpf_list;

	/* datapath/if_rule */
	struct gtp_bpf_ifrules	*bpf_ifrules;
	struct gtp_interface	*ipip_iface;
	bool			ipip_bind;
	int			ipip_xlat;
	bool			ipip_dead;
	struct hlist_head	*ipip_ingress_tab;
	struct hlist_head	*ipip_egress_tab;
	int			ipip_rules_set;

	struct gtp_server	gtpc;
	struct gtp_server	gtpc_egress;
	struct gtp_server	gtpu;
	struct gtp_server	gtpu_egress;
	int			session_delete_to;

	struct hlist_head	*gtpc_teid_tab;	/* GTP-C teid hashtab */
	struct hlist_head	*gtpu_teid_tab;	/* GTP-U teid hashtab */
	struct hlist_head	*vteid_tab;	/* virtual teid hashtab */
	struct hlist_head	*vsqn_tab;	/* virtual Seqnum hashtab */
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
void gtp_proxy_iface_tun_event_cb(struct gtp_interface *iface,
				  enum gtp_interface_event type,
				  void *ud, void *arg);
int gtp_proxy_rules_show_key(const struct gtp_if_rule *r, char *buf,
			     int size, bool short_out);
int gtp_proxy_rules_remote_exists(struct gtp_proxy *ctx,
				  __be32 addr, bool *egress);
void gtp_proxy_rules_remote_set(struct gtp_proxy *ctx, __be32 addr,
				int action, bool egress);
void gtp_proxy_rules_tun_set(struct gtp_proxy *ctx);
struct gtp_proxy *gtp_proxy_get(const char *name);
struct gtp_proxy *gtp_proxy_alloc(const char *name);
void gtp_proxy_ctx_destroy(struct gtp_proxy *ctx);
void gtp_proxy_server_stop(void);
void gtp_proxy_destroy(void);
