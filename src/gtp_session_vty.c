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

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	VTY Command
 */
static int
__gtp_session_teid_cp_vty(vty_t *vty, list_head_t *l)
{
	gtp_teid_t *t;

	/* Walk the line */
	list_for_each_entry(t, l, next) {
		if (__test_bit(GTP_TEID_FL_FWD, &t->flags))
			vty_out(vty, "  [CP] vteid:0x%.8x teid:0x%.8x vsqn:0x%.8x sqn:0x%.8x"
				     " ipaddr:%u.%u.%u.%u sGW:%u.%u.%u.%u pGW:%u.%u.%u.%u%s"
				   , t->vid, ntohl(t->id), t->vsqn, t->sqn, NIPQUAD(t->ipv4)
				   , NIPQUAD(t->sgw_addr.sin_addr.s_addr)
				   , NIPQUAD(t->pgw_addr.sin_addr.s_addr)
				   , VTY_NEWLINE);
		else if (__test_bit(GTP_TEID_FL_RT, &t->flags))
			vty_out(vty, "  [CP] teid:0x%.8x sqn:0x%.8x"
				     " ipaddr:%u.%u.%u.%u sGW:%u.%u.%u.%u%s"
				   , ntohl(t->id), t->sqn, NIPQUAD(t->ipv4)
				   , NIPQUAD(t->sgw_addr.sin_addr.s_addr)
				   , VTY_NEWLINE);
	}
	return 0;
}

static int
__gtp_session_teid_up_vty(vty_t *vty, list_head_t *l)
{
	gtp_teid_t *t;

	/* Walk the line */
	list_for_each_entry(t, l, next) {
		if (__test_bit(GTP_TEID_FL_FWD, &t->flags)) {
			vty_out(vty, "  [UP] vteid:0x%.8x teid:0x%.8x sqn:0x%.8x"
				     " bearer-id:0x%.2x remote_ipaddr:%u.%u.%u.%u%s"
				   , t->vid, ntohl(t->id), t->sqn, t->bearer_id, NIPQUAD(t->ipv4)
				   , VTY_NEWLINE);
			if (t->vid)
				gtp_bpf_fwd_teid_vty(vty, t);
		} else if (__test_bit(GTP_TEID_FL_RT, &t->flags)) {
			vty_out(vty, "  [UP] teid:0x%.8x"
				     " bearer-id:0x%.2x remote_ipaddr:%u.%u.%u.%u%s"
				   , ntohl(t->id), t->bearer_id, NIPQUAD(t->ipv4)
				   , VTY_NEWLINE);
			gtp_bpf_rt_teid_vty(vty, t);
		}
	}
	return 0;
}

int
gtp_session_vty(vty_t *vty, gtp_conn_t *c)
{
	list_head_t *l = &c->gtp_sessions;
	time_t timeout = 0;
	gtp_session_t *s;
	struct tm *t;

	/* Walk the line */
	list_for_each_entry(s, l, next) {
		if (s->timer) {
			timeout = s->timer->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);

		}

		t = &s->creation_time;
		vty_out(vty, " session-id:0x%.8x apn:%s imsi:%ld creation:%.2d/%.2d/%.2d-%.2d:%.2d:%.2d expire:%s"
			   , s->id, s->apn->name
			   , c->imsi
			   , t->tm_mday, t->tm_mon+1, t->tm_year+1900
			   , t->tm_hour, t->tm_min, t->tm_sec
			   , s->timer ? s->tmp_str : "never");
		if (c->pppoe_cnt)
			vty_out(vty, " pppoe cnt:%d" , c->pppoe_cnt);
		vty_out(vty, "%s" , VTY_NEWLINE);

		if (s->s_pppoe)
			vty_out(vty, "  pppuser:%s%s" , s->s_pppoe->gtp_username , VTY_NEWLINE);
		__gtp_session_teid_cp_vty(vty, &s->gtpc_teid);
		__gtp_session_teid_up_vty(vty, &s->gtpu_teid);
	}
	return 0;
}

int
gtp_session_summary_vty(vty_t *vty, gtp_conn_t *c)
{
	list_head_t *l = &c->gtp_sessions;
	time_t timeout = 0;
	gtp_session_t *s;
	gtp_apn_t *apn = NULL;

	/* Walk the line */
	list_for_each_entry(s, l, next) {
		if (s->timer) {
			timeout = s->timer->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);
		}

		if (!apn) {
			vty_out(vty, "| %.15ld | %10s |  session-id:0x%.8x #teid:%.2d expiration:%11s |%s"
				   , c->imsi, s->apn->name, s->id, s->refcnt
				   , s->timer ? s->tmp_str : "never"
				   , VTY_NEWLINE);
			apn = s->apn;
			continue;
		}

		vty_out(vty, "|                 | %10s |  session-id:0x%.8x #teid:%.2d expiration:%11s |%s"
			   , (apn == s->apn) ? "" : s->apn->name
			   , s->id, s->refcnt
			   , s->timer ? s->tmp_str : "never"
			   , VTY_NEWLINE);
		apn = s->apn;
	}

	/* Footer */
	vty_out(vty, "+-----------------+------------+--------------------------------------------------------+%s"
		   , VTY_NEWLINE);
	return 0;
}

DEFUN(show_gtp_session,
      show_gtp_session_cmd,
      "show gtp session [INTEGER]",
      SHOW_STR
      "GTP related informations\n"
      "GTP Session tracking\n"
      "IMSI to look for (none for all)\n")
{
	uint64_t imsi;

	if (argc) {
		imsi = strtoull(argv[0], NULL, 10);
		gtp_conn_vty(vty, gtp_session_vty, imsi);
		return CMD_SUCCESS;
	}

	/* Header */
	vty_out(vty, "+-----------------+------------+--------------------------------------------------------+%s"
		     "|      IMSI       |    APN     |                GTP Session Informations                |%s"
		     "+-----------------+------------+--------------------------------------------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	gtp_conn_vty(vty, gtp_session_summary_vty, 0);
	return CMD_SUCCESS;
}

DEFUN(clear_gtp_session,
      clear_gtp_session_cmd,
      "clear gtp session [INTEGER]",
      "Clear GTP related\n"
      "GTP session\n"
      "GTP Session\n"
      "IMSI\n")
{
	uint64_t imsi = 0;
	gtp_conn_t *c;

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

	gtp_sessions_release(c);
	gtp_conn_put(c);
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
cmd_ext_gtp_session_install(void)
{
	/* Install show commands */
	install_element(VIEW_NODE, &show_gtp_session_cmd);
	install_element(ENABLE_NODE, &show_gtp_session_cmd);
	install_element(ENABLE_NODE, &clear_gtp_session_cmd);

	return 0;
}

static cmd_ext_t cmd_ext_gtp_session = {
	.install = cmd_ext_gtp_session_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_gtp_session);
}
