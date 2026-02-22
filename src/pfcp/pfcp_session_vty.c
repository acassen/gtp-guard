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

#include <inttypes.h>
#include <arpa/inet.h>
#include "pfcp_router.h"
#include "pfcp_session.h"
#include "pfcp_teid.h"
#include "pfcp_utils.h"
#include "pfcp_bpf.h"
#include "command.h"
#include "table.h"


/*
 *	VTY Command
 */
static int
_pfcp_session_te_vty(struct vty *vty, struct pfcp_session *s)
{
	struct gtp_bpf_prog *prg = s->router->bpf_prog;
	struct pfcp_fwd_rule *r;
	struct upf_fwd_rule *u;
	struct pdr *p;
	struct pfcp_teid *t;
	char addr_str[INET6_ADDRSTRLEN];

	list_for_each_entry(p, &s->pdr_list, next) {
		r = p->fwd_rule;

		/* NOTE: Only support Optimized PDI */
		if (!r || !p->te)
			continue;

		vty_out(vty, " . Traffic-Endpoint:%d 3GPP-Interface-Type:%s%s"
			   , p->te->id
			   , pfcp_3GPP_interface2str(p->te->interface_type)
			   , VTY_NEWLINE);

		t = p->te->teid;
		u = &r->rule;

		if (u->flags & UPF_FWD_FL_EGRESS && t) {
			vty_out(vty, "   [uplink] local-teid:0x%.8x remote-gtpu:'%s'%s"
				   , t->id
				   , inet_ntop(AF_INET, &t->ipv4, addr_str, INET6_ADDRSTRLEN)
				   , VTY_NEWLINE);
			pfcp_bpf_teid_vty(vty, prg, UPF_FWD_FL_EGRESS, &s->ue_ip, t);
		}

		if (u->flags & UPF_FWD_FL_INGRESS) {
			vty_out(vty, "   [downlink] remote-teid:0x%.8x remote-gtpu:'%s'%s"
				   , u->gtpu_remote_teid
				   , inet_ntop(AF_INET, &u->gtpu_remote_addr, addr_str,
					       INET6_ADDRSTRLEN)
				   , VTY_NEWLINE);
			pfcp_bpf_teid_vty(vty, prg, UPF_FWD_FL_INGRESS, &s->ue_ip, t);
		}
	}

	return 0;
}

int
pfcp_session_vty(struct vty *vty, struct gtp_conn *c, void *arg)
{
	struct list_head *l = &c->pfcp_sessions;
	struct pfcp_session *s;
	struct ue_ip_address *ue;
	time_t timeout = 0;
	char addr_str[INET6_ADDRSTRLEN];
	struct tm *t;

	/* Walk the line */
	list_for_each_entry(s, l, next) {
		if (s->timer) {
			timeout = s->timer->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);

		}

		t = &s->creation_time;
		vty_out(vty, " imsi:%ld seid:0x%lx remote-seid:0x%lx apn:%s"
			     " creation:%.2d/%.2d/%.2d-%.2d:%.2d:%.2d expire:%s%s"
			   , c->imsi, s->seid, be64toh(s->remote_seid.id), s->apn->name
			   , t->tm_mday, t->tm_mon+1, t->tm_year+1900
			   , t->tm_hour, t->tm_min, t->tm_sec
			   , s->timer ? s->tmp_str : "never"
			   , VTY_NEWLINE);

		ue = &s->ue_ip;
		if (ue->flags & UE_IPV4)
			vty_out(vty, " . UE IPv4: %s%s"
				   , inet_ntop(AF_INET, &ue->v4, addr_str, INET6_ADDRSTRLEN)
				   , VTY_NEWLINE);
		if (ue->flags & UE_IPV6)
			vty_out(vty, " . UE IPv6: %s%s"
				   , inet_ntop(AF_INET6, &ue->v6, addr_str, INET6_ADDRSTRLEN)
				   , VTY_NEWLINE);

		_pfcp_session_te_vty(vty, s);
	}
	return 0;
}

int
pfcp_session_summary_vty(struct vty *vty, struct gtp_conn *c, void *arg)
{
	struct list_head *l = &c->pfcp_sessions;
	struct table *tbl = arg;
	struct pfcp_session *s;
	time_t timeout = 0;
	struct gtp_apn *apn = NULL;

	if (!tbl)
		return -1;

	/* Walk the line */
	list_for_each_entry(s, l, next) {
		if (s->timer) {
			timeout = s->timer->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);
		}

		if (!apn) {
			table_add_row_fmt(tbl, "%ld|%s|seid:0x%lx #teid:%.2d expiration:%s"
					     , c->imsi, s->apn->name, s->seid, s->teid_cnt
					     , s->timer ? s->tmp_str : "never");
			apn = s->apn;
			continue;
		}

		table_add_row_fmt(tbl, "%s|%s|seid:0x%lx #teid:%.2d expiration:%s"
				     , "", (apn == s->apn) ? "" : s->apn->name
				     , s->seid, s->teid_cnt
				     , s->timer ? s->tmp_str : "never");
		apn = s->apn;
	}

	return 0;
}

DEFUN(show_pfcp_session,
      show_pfcp_session_cmd,
      "show pfcp session [INTEGER]",
      SHOW_STR
      "PFCP related informations\n"
      "PFCP Session tracking\n"
      "IMSI to look for (none for all)\n")
{
	struct table *tbl;
	uint64_t imsi;

	if (argc) {
		imsi = strtoull(argv[0], NULL, 10);
		gtp_conn_vty(vty, pfcp_session_vty, imsi, NULL);
		return CMD_SUCCESS;
	}

	tbl = table_init(3, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "IMSI", "APN", "PFCP Sessions Informations");
	table_set_column_align(tbl, ALIGN_RIGHT, ALIGN_RIGHT, ALIGN_LEFT);

	gtp_conn_vty(vty, pfcp_session_summary_vty, 0, tbl);

	table_vty_out(tbl, vty);
	table_destroy(tbl);

	return CMD_SUCCESS;
}

DEFUN(clear_pfcp_session,
      clear_pfcp_session_cmd,
      "clear pfcp session [INTEGER]",
      "Clear PFCP related\n"
      "PFCP session\n"
      "PFCP Session\n"
      "IMSI\n")
{
	struct gtp_conn *c;
	uint64_t imsi = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	imsi = strtoull(argv[0], NULL, 10);
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		vty_out(vty, "%% unknown imsi:%ld%s", imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	pfcp_sessions_release(c);
	gtp_conn_put(c);
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
cmd_ext_pfcp_session_install(void)
{
	/* Install show commands */
	install_element(VIEW_NODE, &show_pfcp_session_cmd);
	install_element(ENABLE_NODE, &show_pfcp_session_cmd);
	install_element(ENABLE_NODE, &clear_pfcp_session_cmd);

	return 0;
}

static struct cmd_ext cmd_ext_pfcp_session = {
	.install = cmd_ext_pfcp_session_install,
};

static void __attribute__((constructor))
pfcp_session_vty_init(void)
{
	cmd_ext_register(&cmd_ext_pfcp_session);
}
