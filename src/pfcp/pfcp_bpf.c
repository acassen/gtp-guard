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

#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pfcp_bpf.h"
#include "pfcp_router.h"
#include "pfcp_teid.h"
#include "gtp_bpf_utils.h"
#include "list_head.h"
#include "bitops.h"


/* Extern data */
extern struct data *daemon_data;


int
pfcp_bpf_teid_action(struct pfcp_router *r, int action, struct pfcp_teid *t,
		     struct ue_ip_address *ue)
{
	char ue_str[INET6_ADDRSTRLEN];
	char gtpu_str[INET6_ADDRSTRLEN];

	if (!t)
		return -1;


	/* NOTE: t->id is stored in host byte order. Any matching
	 * MUST convert it into network by order. htonl() is then
	 * used during PFCP protcol F-TEID IE creation */

	/* Egress rules :
	 * NOTE: Egress direction is a simple GTP-U decap + forwarding
	 * NOTE: You can also implement strict GTP-U endpoint by
	 * validating every incoming pkt with pfcp_teid->ipv{4,6}
	 */
	if (__test_bit(PFCP_TEID_F_EGRESS, &t->flags)) {
		printf("%s(): '%s' UPF bpf 'egress' rule for teid:0x%.8x",
		       __FUNCTION__,
		       (action == RULE_ADD) ? "adding" : "removing", t->id);
		return 0;
	}

	/* Ingress rules :
	 * NOTE: Ingress direction is more complicated. IPv4 and/or IPv6 iph->daddr
	 * MUST match ue_ip_address. If so, then encap into GTP-U and forward pkt
	 * to remote GTP-U endpoint as present in pfcp_teid->ipv{4,6}.
	 */
	if (__test_bit(PFCP_TEID_F_INGRESS, &t->flags)) {
		/* At least v4 or v6... */
		if (!ue->flags)
			return -1;

		if (ue->flags & UE_IPV4) {
			printf("%s(): '%s' UPF bpf 'ingress' rule matching ue:'%s'\n"
			       "\t-> GTP-U encap : teid:0x%.8x gtpu_endpoint:%s",
			       __FUNCTION__,
			       (action == RULE_ADD) ? "adding" : "removing",
			       inet_ntop(AF_INET, &ue->v4, ue_str, INET6_ADDRSTRLEN),
			       t->id,
			       inet_ntop(AF_INET, &t->ipv4, gtpu_str, INET6_ADDRSTRLEN));
		}

		if (ue->flags & UE_IPV6) {
			printf("%s(): '%s' UPF bpf 'ingress' rule matching ue:'%s'\n"
			       "\t-> GTP-U encap : teid:0x%.8x gtpu_endpoint:%s",
			       __FUNCTION__,
			       (action == RULE_ADD) ? "adding" : "removing",
			       inet_ntop(AF_INET6, &ue->v6, ue_str, INET6_ADDRSTRLEN),
			       t->id,
			       inet_ntop(AF_INET, &t->ipv4, gtpu_str, INET6_ADDRSTRLEN));
		}
	}

	return 0;
}


static void *
pfcp_bpf_alloc(struct gtp_bpf_prog *p)
{
	struct pfcp_bpf_data *bd;

	bd = calloc(1, sizeof (*bd));
	if (bd == NULL)
		return NULL;

	INIT_LIST_HEAD(&bd->pfcp_router_list);
	return bd;
}

static void
pfcp_bpf_release(struct gtp_bpf_prog *p, void *udata)
{
	struct pfcp_bpf_data *bd = udata;
	struct pfcp_router *c, *tmp;

	list_for_each_entry_safe(c, tmp, &bd->pfcp_router_list, bpf_list) {
		c->bpf_prog = NULL;
		c->bpf_data = NULL;
		list_del_init(&c->bpf_list);
	}
	free(bd);
}

static int
pfcp_bpf_load_maps(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct pfcp_bpf_data *bd = udata;

	bd->teid_rule = gtp_bpf_prog_load_map(p->load.obj, "teid_rule");
	if (!bd->teid_rule)
		return -1;

	return 0;
}


static struct gtp_bpf_prog_tpl pfcp_bpf_tpl = {
	.name = "upf",
	.description = "3GPP User Plane Function",
	.alloc = pfcp_bpf_alloc,
	.loaded = pfcp_bpf_load_maps,
	.release = pfcp_bpf_release,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&pfcp_bpf_tpl);
}
