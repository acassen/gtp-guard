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
#include "utils.h"
#include "command.h"
#include "table.h"
#include "pfcp_router.h"
#include "pfcp_session.h"
#include "pfcp_teid.h"
#include "pfcp_utils.h"
#include "pfcp_bpf.h"


/*
 *	VTY Command
 */
static void
_pfcp_session_urr_vty(struct vty *vty, struct urr *urr)
{
	const union pfcp_reporting_triggers *tr = &urr->triggers;
	char mmb[64];
	int k = 0;

	if (urr->measurement_method.durat)
		k += scnprintf(mmb + k, sizeof (mmb) - k, "%s,", "duration");
	if (urr->measurement_method.volum)
		k += scnprintf(mmb + k, sizeof (mmb) - k, "%s,", "volume");
	if (urr->measurement_method.event)
		k += scnprintf(mmb + k, sizeof (mmb) - k, "%s,", "event");
	mmb[k ? k - 1 : 0] = 0;

	vty_out(vty, " . URR[%d] measure: %s",
		ntohl(urr->id), mmb);
	if (tr->triggers)
		vty_out(vty, ", triggers:\n");
	else
		vty_out(vty, "%s", VTY_NEWLINE);

	if (tr->perio)
		vty_out(vty, "     PERIO (Periodic Reporting)\n");
	if (tr->volth) {
		vty_out(vty, "     VOLTH ");
		if (urr->volume_threshold_to)
			vty_out(vty, " Total:%ld", urr->volume_threshold_to);
		if (urr->volume_threshold_ul)
			vty_out(vty, " Uplink:%ld", urr->volume_threshold_ul);
		if (urr->volume_threshold_dl)
			vty_out(vty, " Downlink:%ld", urr->volume_threshold_dl);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	if (tr->timth)
		vty_out(vty, "     TIMTH (Time Threshold)\n");
	if (tr->quhti)
		vty_out(vty, "     QUHTI (Quota Holding Time)\n");
	if (tr->start)
		vty_out(vty, "     START (Start of Traffic)\n");
	if (tr->stopt)
		vty_out(vty, "     STOPT (Stop of Traffic)\n");
	if (tr->droth)
		vty_out(vty, "     DROTH (Dropped DL Traffic Threshold)\n");
	if (tr->liusa)
		vty_out(vty, "     LIUSA (Linked Usage Reporting)\n");
	if (tr->volqu)
		vty_out(vty, "     VOLQU (Volume Quota)\n");
	if (tr->timqu)
		vty_out(vty, "     TIMQU (Time Quota)\n");
	if (tr->envcl)
		vty_out(vty, "     ENVCL (Envelope Closure)\n");
	if (tr->macar)
		vty_out(vty, "     MACAR (MAC Addresses Reporting)\n");
	if (tr->eveth)
		vty_out(vty, "     EVETH (Event Threshold)\n");
	if (tr->evequ)
		vty_out(vty, "     EVEQU (Event Quota)\n");
	if (tr->ipmjl)
		vty_out(vty, "     IPMJL (IP Multicast Join/Leave)\n");
	if (tr->quvti)
		vty_out(vty, "     QUVTI (Quota Validity Time)\n");


}

static void
_pfcp_session_pdr_vty(struct vty *vty, struct pfcp_session *s, bool details)
{
	struct gtp_bpf_prog *prg = s->router->bpf_prog;
	struct upf_fwd_rule *u;
	struct pdr *p;
	struct pfcp_teid *t;
	char addr_str[INET6_ADDRSTRLEN];
	int i;

	list_for_each_entry(p, &s->pdr_list, next) {
		if (p->te)
			vty_out(vty, " . Traffic-Endpoint:%d "
				"3GPP-Interface-Type:%s\n", p->te->id,
				pfcp_3GPP_interface2str(p->te->interface_type));

		if (!p->fwd_rule)
			continue;
		u = &p->fwd_rule->rule;
		t = p->teid ?: (p->te ? p->te->teid : NULL);

		if (u->flags & UPF_FWD_FL_EGRESS && t) {
			vty_out(vty, "   [uplink] local-teid:0x%.8x local-gtpu:'%s'%s"
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

		if (details) {
			vty_out(vty, "            ref-urr:");
			for (i = 0; i < PFCP_MAX_NR_ELEM && p->urr[i]; i++)
				vty_out(vty, " %d", p->urr[i]->id);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}
}

int
pfcp_session_vty(struct vty *vty, struct gtp_conn *c, void *arg)
{
	struct pfcp_session *s;
	struct ue_ip_address *ue;
	struct urr *u;
	time_t timeout = 0;
	char addr_str[INET6_ADDRSTRLEN];
	struct tm *t;
	bool details = arg != NULL;

	/* Walk the line */
	list_for_each_entry(s, &c->pfcp_sessions, next) {
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

		if (details) {
			list_for_each_entry(u, &s->urr_list, next)
				_pfcp_session_urr_vty(vty, u);
		}

		ue = &s->ue_ip;
		if (ue->flags & UE_IPV4)
			vty_out(vty, " . UE IPv4: %s%s"
				   , inet_ntop(AF_INET, &ue->v4, addr_str, INET6_ADDRSTRLEN)
				   , VTY_NEWLINE);
		if (ue->flags & UE_IPV6)
			vty_out(vty, " . UE IPv6: %s%s"
				   , inet_ntop(AF_INET6, &ue->v6, addr_str, INET6_ADDRSTRLEN)
				   , VTY_NEWLINE);

		_pfcp_session_pdr_vty(vty, s, details);
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
      "show pfcp session [IMSI DETAILS]",
      SHOW_STR
      "PFCP related informations\n"
      "PFCP Session tracking\n"
      "IMSI to look for (none for all)\n")
{
	struct table *tbl;
	uint64_t imsi;

	if (argc) {
		imsi = strtoull(argv[0], NULL, 10);
		gtp_conn_vty(vty, pfcp_session_vty, imsi,
			     argc > 1 ? (void *)1 : NULL);
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
      "clear pfcp session IMSI",
      "Clear PFCP related\n"
      "PFCP session\n"
      "PFCP Session\n"
      "IMSI\n")
{
	struct gtp_conn *c;
	uint64_t imsi = 0;

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


/* Capture */
DEFUN(capture_start_pfcp,
      capture_start_pfcp_cmd,
      "capture pfcp (imsi|imei|msisdn) USER start "
      "[CAPENTRY side (input|output|access|core|all) caplen <32-10000>]",
      "Capture menu\n"
      "Capture pfcp submenu\n")
{
	struct pfcp_session *s;
	struct gtp_conn *c = NULL;
	uint64_t v = atoll(argv[1]);
	char capname[64];
	int caplen = 0;

	if (!strcmp(argv[0], "imsi"))
		c = gtp_conn_get_by_imsi(v);
	else if (!strcmp(argv[0], "imei"))
		c = gtp_conn_get_by_imei(v);
	else if (!strcmp(argv[0], "msisdn"))
		c = gtp_conn_get_by_msisdn(v);

	if (c == NULL) {
		vty_out(vty, "%% Cannot find user '%s' by %s\n", argv[1], argv[0]);
		return CMD_WARNING;
	}

	if (list_empty(&c->pfcp_sessions)) {
		vty_out(vty, "%% No established pfcp session for user %s\n", argv[0]);
		return CMD_WARNING;
	}

	/* XXX: no support for multiple pfcp session per conn */
	s = list_first_entry(&c->pfcp_sessions, struct pfcp_session, next);

	if (argc > 2)
		snprintf(capname, sizeof (capname), "%s", argv[2]);
	else
		snprintf(capname, sizeof (capname), "%ld", v);

	if (argc > 3) {
		if (!strcmp(argv[3], "input"))
			s->capture.flags = GTP_CAPTURE_FL_INPUT;
		else if (!strcmp(argv[3], "output"))
			s->capture.flags = GTP_CAPTURE_FL_OUTPUT;
		else if (!strcmp(argv[3], "core"))
			s->capture.flags = GTP_CAPTURE_FL_CORE;
		else if (!strcmp(argv[3], "access"))
			s->capture.flags = GTP_CAPTURE_FL_ACCESS;
		else if (!strcmp(argv[3], "all"))
			s->capture.flags = GTP_CAPTURE_FL_DIRECTION_MASK;
	} else {
		s->capture.flags = GTP_CAPTURE_FL_INPUT;
	}

	if (argc > 6)
		VTY_GET_INTEGER_RANGE("caplen", caplen, argv[6], 32, 10000);
	s->capture.cap_len = caplen;

	if (gtp_capture_start(&s->capture, s->router->bpf_prog, capname)) {
		vty_out(vty, "%% Error starting pfcp trace\n");
		return CMD_WARNING;
	}
	pfcp_session_update_fwd_rules(s);

	return CMD_SUCCESS;
}

DEFUN(capture_stop_pfcp,
      capture_stop_pfcp_cmd,
      "capture pfcp (imsi|imei|msisdn) USER stop",
      "Capture menu\n"
      "Capture interface submenu\n"
      "Interface name\n"
      "Stop capture\n")
{
	struct pfcp_session *s;
	struct gtp_conn *c = NULL;
	uint64_t v = atoll(argv[1]);

	if (!strcmp(argv[0], "imsi"))
		c = gtp_conn_get_by_imsi(v);
	else if (!strcmp(argv[0], "imei"))
		c = gtp_conn_get_by_imei(v);
	else if (!strcmp(argv[0], "msisdn"))
		c = gtp_conn_get_by_msisdn(v);

	if (c == NULL) {
		vty_out(vty, "%% Cannot find user '%s' by %s\n", argv[1], argv[0]);
		return CMD_WARNING;
	}

	list_for_each_entry(s, &c->pfcp_sessions, next) {
		gtp_capture_stop(&s->capture);
		pfcp_session_update_fwd_rules(s);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
cmd_ext_pfcp_session_install(void)
{
	install_element(ENABLE_NODE, &capture_start_pfcp_cmd);
	install_element(ENABLE_NODE, &capture_stop_pfcp_cmd);

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
