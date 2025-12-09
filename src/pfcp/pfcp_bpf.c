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

#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pfcp_bpf.h"
#include "pfcp_router.h"
#include "pfcp_teid.h"
#include "gtp_bpf_utils.h"
#include "list_head.h"
#include "addr.h"
#include "logger.h"
#include "table.h"
#include "bpf/lib/upf-def.h"


/* Extern data */
extern struct data *daemon_data;


static void
_log_egress_rule(int action, struct upf_fwd_rule *u, struct pfcp_teid *t, int err)
{
	char gtpu_str[INET6_ADDRSTRLEN];
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char action_str[60] = {};

	if (err)
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);

	if (action == RULE_ADD &&
	    (u->flags & UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) ==
	    UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) {
		snprintf(action_str, sizeof (action_str),
			 "fwd to teid:0x%.8x remote:'%s'",
			 u->gtpu_remote_teid,
			 inet_ntop(AF_INET, &u->gtpu_remote_addr,
				   gtpu_str, INET6_ADDRSTRLEN));
	} else {
		snprintf(action_str, sizeof(action_str), "%s%s",
			 (u->flags & UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER) ? "decap|" : "",
			 (u->flags & UPF_FWD_FL_ACT_FWD) ? "fwd" : "drop");
	}

	log_message(LOG_INFO, "pfcp_bpf: %s%s XDP 'egress' rule "
		    "{local_teid:0x%.8x, local_gtpu:'%s', %s} %s",
		    (err) ? "Error " : "",
		    (action == RULE_ADD) ? "adding" : "deleting",
		    t->id,
		    inet_ntop(AF_INET, &t->ipv4, gtpu_str, INET6_ADDRSTRLEN),
		    action_str,
		    (err) ? errmsg : "");
}

static int
_update_egress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct pfcp_teid *t,
		 __u64 flags)
{
	uint32_t nr_cpus = bpf_num_possible_cpus();
	struct upf_fwd_rule rule[nr_cpus];
	struct upf_egress_key key = {
		.gtpu_local_teid = htonl(t->id),
		.gtpu_local_addr = t->ipv4.s_addr,
		.gtpu_local_port = htons(GTP_U_PORT),
	};
	int err, i;

	for (i = 0; i < nr_cpus; i++)
		rule[i] = *u;

	err = bpf_map__update_elem(r->bpf_data->user_egress, &key, sizeof(key),
				   rule, sizeof(rule), flags);
	_log_egress_rule(RULE_ADD, u, t, err);

	return err ? -1 : 0;
}

static int
_delete_egress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct pfcp_teid *t)
{
	struct upf_egress_key key = {
		.gtpu_local_teid = htonl(t->id),
		.gtpu_local_addr = t->ipv4.s_addr,
		.gtpu_local_port = htons(GTP_U_PORT),
	};
	int err = bpf_map__delete_elem(r->bpf_data->user_egress, &key,
				       sizeof(key), 0);
	_log_egress_rule(RULE_DEL, u, t, err);

	return err ? -1 : 0;
}

static int
_log_ingress_rule(int action, int type, struct upf_fwd_rule *u, struct ue_ip_address *ue,
		  int err)
{
	char ue_str[INET6_ADDRSTRLEN];
	char gtpu_str[INET6_ADDRSTRLEN];
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char action_str[60] = {};
	sa_family_t family = 0;

	if (err)
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);

	if (type == UE_IPV4 && ue->flags & UE_IPV4)
		family = AF_INET;

	if (type == UE_IPV6 && ue->flags & UE_IPV6)
		family = AF_INET6;

	if (!family)
		return -1;

	snprintf(action_str, sizeof(action_str), "%s%s",
		 (u->flags & UPF_FWD_FL_ACT_CREATE_OUTER_HEADER) ? "encap|" : "",
		 (u->flags & UPF_FWD_FL_ACT_FWD) ? "fwd" : "drop");

	log_message(LOG_INFO, "pfcp_bpf: %s%s XDP 'ingress' rule "
		    "{ue_ipv%d:'%s', remote_teid:0x%.8x, remote_gtpu:'%s', %s} %s",
		    (err) ? "Error " : "",
		    (action == RULE_ADD) ? "adding" : "deleting",
		    (family == AF_INET) ? 4 : 6,
		    inet_ntop(family, (family == AF_INET) ? (void *)&ue->v4 : (void *)&ue->v6,
			      ue_str, INET6_ADDRSTRLEN),
		    ntohl(u->gtpu_remote_teid),
		    inet_ntop(AF_INET, &u->gtpu_remote_addr, gtpu_str, INET6_ADDRSTRLEN),
		    action_str,
		    (err) ? errmsg : "");

	return 0;
}

static int
_update_ingress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct ue_ip_address *ue,
		     __u64 flags)
{
	uint32_t nr_cpus = bpf_num_possible_cpus();
	struct upf_fwd_rule rule[nr_cpus];
	struct upf_ingress_key key = {};
	int i, err = 0, err_cnt = 0;

	for (i = 0; i < nr_cpus; i++)
		rule[i] = *u;

	if (ue->flags & UE_IPV4) {
		key.flags = UE_IPV4;
		key.ue_addr.ip4 = ue->v4.s_addr;

		err = bpf_map__update_elem(r->bpf_data->user_ingress,
					   &key, sizeof(key),
					   rule, sizeof(rule), flags);
		_log_ingress_rule(RULE_ADD, UE_IPV4, u, ue, err);
		err_cnt += (bool) err;
	}

	if (ue->flags & UE_IPV6) {
		key.flags = UE_IPV6;
		memcpy(&key.ue_addr.ip6, &ue->v6, sizeof (ue->v6));

		err = bpf_map__update_elem(r->bpf_data->user_ingress,
					   &key, sizeof(key),
					   rule, sizeof(rule), flags);
		_log_ingress_rule(RULE_ADD, UE_IPV6, u, ue, err);
		err_cnt += (bool) err;
	}

	return err_cnt ? -1 : 0;
}

static int
_delete_ingress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct ue_ip_address *ue)
{
	struct upf_ingress_key key = {};
	int err = 0, err_cnt = 0;

	if (ue->flags & UE_IPV4) {
		key.flags = UE_IPV4;
		key.ue_addr.ip4 = ue->v4.s_addr;

		err = bpf_map__delete_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key), 0);
		_log_ingress_rule(RULE_DEL, UE_IPV4, u, ue, err);
		err_cnt += (bool) err;
	}

	if (ue->flags & UE_IPV6) {
		key.flags = UE_IPV6;
		memcpy(&key.ue_addr.ip6, &ue->v6, sizeof (ue->v6));

		err = bpf_map__delete_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key), 0);
		_log_ingress_rule(RULE_DEL, UE_IPV6, u, ue, err);
		err_cnt += (bool) err;
	}

	return err_cnt ? -1 : 0;
}

int
pfcp_bpf_action(struct pfcp_router *rtr, struct pfcp_fwd_rule *r,
		struct pfcp_teid *t, struct ue_ip_address *ue)
{
	struct upf_fwd_rule *u = &r->rule;
	int err = -1;

	if (!rtr->bpf_data || !rtr->bpf_data->user_ingress)
		return -1;

	switch (r->action) {
	case PFCP_ACT_CREATE:
		if (u->flags & UPF_FWD_FL_EGRESS)
			err = _update_egress_rule(rtr, u, t, BPF_NOEXIST);
		else if (u->flags & UPF_FWD_FL_INGRESS)
			err = _update_ingress_rule(rtr, u, ue, BPF_NOEXIST);
		break;

	case PFCP_ACT_UPDATE:
		if (u->flags & UPF_FWD_FL_EGRESS)
			err = _update_egress_rule(rtr, u, t, BPF_EXIST);
		else if (u->flags & UPF_FWD_FL_INGRESS)
			err = _update_ingress_rule(rtr, u, ue, BPF_EXIST);
		break;

	case PFCP_ACT_DELETE:
		if (u->flags & UPF_FWD_FL_EGRESS)
			err = _delete_egress_rule(rtr, u, t);
		else if (u->flags & UPF_FWD_FL_INGRESS)
			err = _delete_ingress_rule(rtr, u, ue);
		break;

	default:
		return -1;
	}

	return err;
}

static int
pfcp_bpf_counter_coalese(struct upf_fwd_rule *rule)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int i;

	for (i = 1; i < nr_cpus; i++) {
		rule[0].fwd_packets += rule[i].fwd_packets;
		rule[0].fwd_bytes += rule[i].fwd_bytes;
		rule[0].drop_packets += rule[i].drop_packets;
		rule[0].drop_bytes += rule[i].drop_bytes;
	}

	return 0;
}

int
pfcp_bpf_teid_vty(struct vty *vty, struct gtp_bpf_prog *p, int dir,
		  struct ue_ip_address *ue, struct pfcp_teid *t)
{
	struct pfcp_bpf_data *bd = gtp_bpf_prog_tpl_data_get(p, "upf");
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct upf_egress_key ek = {};
	struct upf_ingress_key ik = {};
	struct upf_fwd_rule rule[nr_cpus];
	int err;

	if (dir == UPF_FWD_FL_EGRESS) {
		memset(rule, 0, sizeof(rule));
		ek.gtpu_local_teid = htonl(t->id);
		ek.gtpu_local_addr = t->ipv4.s_addr;
		ek.gtpu_local_port = htons(GTP_U_PORT);

		err = bpf_map__lookup_elem(bd->user_egress, &ek, sizeof(ek),
					   rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "            no data-plane ?!!%s"
				   , VTY_NEWLINE);
			return -1;
		}

		pfcp_bpf_counter_coalese(rule);
		vty_out(vty, "            packets:%lld bytes:%lld%s"
			     "            drop:%lld drop_bytes:%lld%s"
			   , rule[0].fwd_packets, rule[0].fwd_bytes, VTY_NEWLINE
			   , rule[0].drop_packets, rule[0].drop_bytes, VTY_NEWLINE);
		return 0;
	}

	if (dir != UPF_FWD_FL_INGRESS)
		return -1;

	if (ue->flags & UE_IPV4) {
		memset(rule, 0, sizeof(rule));
		ik.flags = UE_IPV4;
		ik.ue_addr.ip4 = ue->v4.s_addr;
		err = bpf_map__lookup_elem(bd->user_ingress, &ik, sizeof(ik),
					   rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "              IPv4 - no data-plane ?!!%s"
				   , VTY_NEWLINE);
		} else {
			pfcp_bpf_counter_coalese(rule);
			vty_out(vty, "              IPv4 - packets:%lld bytes:%lld%s"
				     "                     drop:%lld drop_bytes:%lld%s"
				   , rule[0].fwd_packets, rule[0].fwd_bytes, VTY_NEWLINE
				   , rule[0].drop_packets, rule[0].drop_bytes, VTY_NEWLINE);
		}
	}

	if (ue->flags & UE_IPV6) {
		memset(rule, 0, sizeof(rule));
		ik.flags = UE_IPV6;
		memcpy(&ik.ue_addr.ip6, &ue->v6, sizeof(ue->v6));
		err = bpf_map__lookup_elem(bd->user_ingress, &ik, sizeof(ik),
					   rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "              IPv6 - no data-plane ?!!%s"
				   , VTY_NEWLINE);
		} else {
			pfcp_bpf_counter_coalese(rule);
			vty_out(vty, "              IPv6 - packets:%lld bytes:%lld%s"
				     "                     drop:%lld drop_bytes:%lld%s"
				   , rule[0].fwd_packets, rule[0].fwd_bytes, VTY_NEWLINE
				   , rule[0].drop_packets, rule[0].drop_bytes, VTY_NEWLINE);
		}
	}

	return 0;
}

static void
pfcp_bpf_vty(struct gtp_bpf_prog *p, void *ud, struct vty *vty,
		int argc, const char **argv)
{
	struct pfcp_bpf_data *bd = ud;
	struct table *tbl;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct upf_egress_key ek = {};
	struct upf_ingress_key ik = {};
	struct upf_fwd_rule rule[nr_cpus];
	union addr addr, laddr, addr_ue;
	char buf1[26], buf2[40], buf3[26], action_str[40];
	uint32_t key = 0;
	int err = 0;

	if (!bd->user_ingress || !bd->user_egress)
		return;

	tbl = table_init(6, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "TEID Remote", "UE Endpoint", "GTP-U Remote E.", "GTP-U Local E.",
			 "Packets", "Bytes");

	vty_out(vty, "bpf-program '%s', downlink (ingress):\n", p->name);

	/* Walk hashtab */
	memset(rule, 0, sizeof(rule));
	while (!bpf_map__get_next_key(bd->user_ingress, &ik, &ik, sizeof(ik))) {
		err = bpf_map__lookup_elem(bd->user_ingress, &ik, sizeof(ik),
					   rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "%% error fetching value for "
				"teid_key:0x%.8x (%m)\n", key);
			break;
		}

		if (ik.flags & UE_IPV4)
			addr_fromip4(&addr_ue, ik.ue_addr.ip4);
		else if (ik.flags & UE_IPV6)
			addr_fromip6b(&addr_ue, ik.ue_addr.ip6.addr);
		addr_fromip4(&addr, rule[0].gtpu_remote_addr);
		addr_set_port(&addr, ntohs(rule[0].gtpu_remote_port));
		addr_fromip4(&laddr, rule[0].gtpu_local_addr);
		addr_set_port(&laddr, ntohs(rule[0].gtpu_local_port));
		pfcp_bpf_counter_coalese(rule);
		table_add_row_fmt(tbl, "0x%.8x|%s|%s|%s|%lld|%lld",
				  ntohl(rule[0].gtpu_remote_teid),
				  addr_stringify(&addr_ue, buf2, sizeof (buf2)),
				  addr_stringify(&addr, buf1, sizeof (buf1)),
				  addr_stringify(&laddr, buf3, sizeof (buf3)),
				  rule[0].fwd_packets, rule[0].fwd_bytes);
	}
	table_vty_out(tbl, vty);
	table_destroy(tbl);

	tbl = table_init(5, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "TEID Local", "GTP-U Local E.", "Action",
			 "Packets", "Bytes");

	vty_out(vty, "uplink (egress):\n");

	/* Walk hashtab */
	memset(rule, 0, sizeof(rule));
	while (!bpf_map__get_next_key(bd->user_egress, &ek, &ek, sizeof(ek))) {
		err = bpf_map__lookup_elem(bd->user_egress, &ek, sizeof(ek),
					   rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "%% error fetching value for "
				"teid_key:0x%.8x (%m)\n", key);
			break;
		}

		if ((rule[0].flags & UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) ==
		    UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) {
			snprintf(action_str, sizeof (action_str),
				 "Fwd to teid 0x%08x",
				 ntohl(rule[0].gtpu_remote_teid));
		} else {
			snprintf(action_str, sizeof(action_str), "Decap");
		}

		addr_fromip4(&addr, ek.gtpu_local_addr);
		addr_set_port(&addr, ntohs(ek.gtpu_local_port));
		pfcp_bpf_counter_coalese(rule);
		table_add_row_fmt(tbl, "0x%.8x|%s|%s|%lld|%lld",
				  ntohl(ek.gtpu_local_teid),
				  addr_stringify(&addr, buf1, sizeof (buf1)),
				  action_str,
				  rule[0].fwd_packets, rule[0].fwd_bytes);
	}
	table_vty_out(tbl, vty);
	table_destroy(tbl);
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

	bd->user_egress = gtp_bpf_prog_load_map(p->obj_load, "user_egress");
	bd->user_ingress = gtp_bpf_prog_load_map(p->obj_load, "user_ingress");
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
	.vty_out = pfcp_bpf_vty,
};

static void __attribute__((constructor))
pfcp_bpf_init(void)
{
	gtp_bpf_prog_tpl_register(&pfcp_bpf_tpl);
}
