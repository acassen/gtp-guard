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
#include "logger.h"
#include "table.h"
#include "bpf/lib/upf-def.h"


/* Extern data */
extern struct data *daemon_data;


static int
_set_egress_rule(struct pfcp_router *r, struct pfcp_teid *t)
{
	uint32_t nr_cpus = bpf_num_possible_cpus();
	struct upf_user_egress u[nr_cpus];
	struct upf_user_egress_key key = {
		.teid = htonl(t->id),
		.gtpu_remote_addr = t->ipv4.s_addr,
		.gtpu_remote_port = htons(GTP_U_PORT),
	};
	int err;

	memset(u, 0x00, sizeof (u));
	err = bpf_map__update_elem(r->bpf_data->user_egress, &key, sizeof (key),
				   u, sizeof (u), BPF_NOEXIST);
	if (err) {
		log_message(LOG_INFO, "pfcp_bpf: cannot insert "
			    "egress rule teid 0x%08x (%m)", key.teid);
		return -1;
	}

	return 0;
}

static int
_unset_egress_rule(struct pfcp_router *r, struct pfcp_teid *t)
{
	struct upf_user_egress_key key = {
		.teid = htonl(t->id),
		.gtpu_remote_addr = t->ipv4.s_addr,
		.gtpu_remote_port = htons(GTP_U_PORT),
	};
	int err;

	err = bpf_map__delete_elem(r->bpf_data->user_egress, &key, sizeof(key), 0);
	if (err) {
		log_message(LOG_INFO, "pfcp_bpf: cannot delete "
			    "egress rule teid 0x%08x (%m)", key.teid);
		return -1;
	}
	return 0;
}


static int
_set_ingress_rule(struct pfcp_router *r, struct pfcp_teid *t, struct ue_ip_address *ue)
{
	uint32_t nr_cpus = bpf_num_possible_cpus();
	struct upf_user_ingress u[nr_cpus];
	struct upf_user_ingress_key key = {};
	int i, err;

	memset(u, 0x00, sizeof (u));
	for (i = 0; i < nr_cpus; i++) {
		u[i].teid = htonl(t->id);
		u[i].gtpu_remote_addr = t->ipv4.s_addr;
		u[i].gtpu_remote_port = htons(GTP_U_PORT);
	}

	if (ue->flags & UE_IPV4) {
		key.flags = UE_IPV4;
		key.ue_addr.ip4 = ue->v4.s_addr;

		err = bpf_map__update_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key),
					   u, sizeof (u), BPF_NOEXIST);
		if (err) {
			log_message(LOG_INFO, "pfcp_bpf: cannot insert "
				    "user_ingress v4 teid 0x%08x (%m)", u[0].teid);
			return -1;
		}
	}

	if (ue->flags & UE_IPV6) {
		key.flags = UE_IPV6;
		memcpy(&key.ue_addr.ip6, &ue->v6, sizeof (ue->v6));

		err = bpf_map__update_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key),
					   u, sizeof (u), BPF_NOEXIST);
		if (err) {
			log_message(LOG_INFO, "pfcp_bpf: cannot insert "
				    "user_ingress v6 teid 0x%08x (%m)", u[0].teid);
			return -1;
		}
	}

	return 0;
}


static int
_unset_ingress_rule(struct pfcp_router *r, struct pfcp_teid *t, struct ue_ip_address *ue)
{
	struct upf_user_ingress_key key = {};
	int err;

	if (ue->flags & UE_IPV4) {
		key.flags = UE_IPV4;
		key.ue_addr.ip4 = ue->v4.s_addr;

		err = bpf_map__delete_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key), 0);
		if (err) {
			log_message(LOG_INFO, "pfcp_bpf: cant delete "
				    "user_ingress v4 (%m)");
			return -1;
		}
	}

	if (ue->flags & UE_IPV6) {
		key.flags = UE_IPV6;
		memcpy(&key.ue_addr.ip6, &ue->v6, sizeof (ue->v6));

		err = bpf_map__delete_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key), 0);
		if (err) {
			log_message(LOG_INFO, "pfcp_bpf: cant delete "
				    "user_ingress v6 (%m)");
			return -1;
		}
	}

	return 0;
}




int
pfcp_bpf_teid_action(struct pfcp_router *r, int action, struct pfcp_teid *t,
		     struct ue_ip_address *ue)
{
	char ue_str[INET6_ADDRSTRLEN];
	char gtpu_str[INET6_ADDRSTRLEN];
	int err;

	if (!t || !r->bpf_data)
		return -1;

	if (__test_bit(PFCP_TEID_F_EGRESS, &t->flags)) {
		if (action == RULE_ADD)
			err = _set_egress_rule(r, t);
		else
			err = _unset_egress_rule(r, t);
		printf("UPF bpf: %s 'egress' rule for teid:0x%.8x, ret:%d\n",
		       (action == RULE_ADD) ? "adding" : "removing", t->id, err);
		return err;
	}

	if (__test_bit(PFCP_TEID_F_INGRESS, &t->flags)) {
		if (action == RULE_ADD)
			err = _set_ingress_rule(r, t, ue);
		else
			err = _unset_ingress_rule(r, t, ue);
		if (ue->flags & UE_IPV4) {
			printf("%s(): '%s' UPF bpf 'ingress' rule matching ue:'%s'\n"
			       "\t-> GTP-U encap : teid:0x%.8x gtpu_endpoint:%s, ret:%d\n",
			       __FUNCTION__,
			       (action == RULE_ADD) ? "adding" : "removing",
			       inet_ntop(AF_INET, &ue->v4, ue_str, INET6_ADDRSTRLEN),
			       t->id,
			       inet_ntop(AF_INET, &t->ipv4, gtpu_str, INET6_ADDRSTRLEN),
			       err);
		}

		if (ue->flags & UE_IPV6) {
			printf("%s(): '%s' UPF bpf 'ingress' rule matching ue:'%s'\n"
			       "\t-> GTP-U encap : teid:0x%.8x gtpu_endpoint:%s, ret:%d\n",
			       __FUNCTION__,
			       (action == RULE_ADD) ? "adding" : "removing",
			       inet_ntop(AF_INET6, &ue->v6, ue_str, INET6_ADDRSTRLEN),
			       t->id,
			       inet_ntop(AF_INET, &t->ipv4, gtpu_str, INET6_ADDRSTRLEN),
			       err);
		}
		return err;
	}

	/* should be either egress or ingress */
	return -1;
}


int
pfcp_bpf_vty(struct gtp_bpf_prog *p, void *arg)
{
	struct pfcp_bpf_data *bd = gtp_bpf_prog_tpl_data_get(p, "upf");
	struct vty *vty = arg;
	struct table *tbl;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct upf_user_egress_key ek = {};
	struct upf_user_ingress_key ik = {};
	struct upf_user_egress eu[nr_cpus];
	struct upf_user_ingress iu[nr_cpus];
	union addr addr, addr_ue;
	char buf1[26], buf2[40];
	uint32_t key = 0;
	int err = 0, i;

	if (!bd || !bd->user_ingress || !bd->user_egress)
		return -1;

	tbl = table_init(5, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "TEID", "UE Endpoint", "GTP-U Endpoint", "Packets", "Bytes");

	vty_out(vty, "bpf-program '%s', ingress:\n", p->name);

	/* Walk hashtab */
	memset(iu, 0x00, sizeof(iu));
	while (!bpf_map__get_next_key(bd->user_ingress, &ik, &ik, sizeof(ik))) {
		err = bpf_map__lookup_elem(bd->user_ingress, &ik, sizeof(ik),
					   iu, sizeof (iu), 0);
		if (err) {
			vty_out(vty, "%% error fetching value for "
				"teid_key:0x%.8x (%m)\n", key);
			break;
		}

		for (i = 1; i < nr_cpus; i++) {
			iu[0].packets += iu[i].packets;
			iu[0].bytes += iu[i].bytes;
		}

		addr_fromip4(&addr, iu[0].gtpu_remote_addr);
		addr_set_port(&addr, ntohs(iu[0].gtpu_remote_port));
		addr_fromip4(&addr_ue, ik.ue_addr.ip4);
		table_add_row_fmt(tbl, "0x%.8x|%s|%s|%lld|%lld",
				  ntohl(iu[0].teid),
				  addr_stringify(&addr_ue, buf2, sizeof (buf2)),
				  addr_stringify(&addr, buf1, sizeof (buf1)),
				  iu[0].packets, iu[0].bytes);
	}
	table_vty_out(tbl, vty);
	table_destroy(tbl);

	tbl = table_init(4, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "TEID", "GTP-U Endpoint", "Packets", "Bytes");

	vty_out(vty, "egress:\n");

	/* Walk hashtab */
	memset(eu, 0x00, sizeof(eu));
	while (!bpf_map__get_next_key(bd->user_egress, &ek, &ek, sizeof(ek))) {
		err = bpf_map__lookup_elem(bd->user_egress, &ek, sizeof(ek),
					   eu, sizeof (eu), 0);
		if (err) {
			vty_out(vty, "%% error fetching value for "
				"teid_key:0x%.8x (%m)\n", key);
			break;
		}

		for (i = 1; i < nr_cpus; i++) {
			eu[0].packets += eu[i].packets;
			eu[0].bytes += eu[i].bytes;
		}

		addr_fromip4(&addr, ek.gtpu_remote_addr);
		addr_set_port(&addr, ntohs(ek.gtpu_remote_port));
		table_add_row_fmt(tbl, "0x%.8x|%s|%lld|%lld",
				  ntohl(ek.teid),
				  addr_stringify(&addr, buf1, sizeof (buf1)),
				  eu[0].packets, eu[0].bytes);
	}
	table_vty_out(tbl, vty);
	table_destroy(tbl);

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

	bd->user_egress = gtp_bpf_prog_load_map(p->load.obj, "user_egress");
	bd->user_ingress = gtp_bpf_prog_load_map(p->load.obj, "user_ingress");
	if (bd->user_egress == NULL || bd->user_ingress == NULL)
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
