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

#include <unistd.h>
#include <sys/un.h>

#include "gtp_data.h"
#include "gtp.h"
#include "gtp_metrics.h"
#include "gtp_utils.h"
#include "gtp_interface.h"
#include "gtp_router_metrics.h"
#include "json_reader.h"
#include "inet_server.h"
#include "logger.h"

/* Extern data */
extern struct data *daemon_data;


/*
 *	Utilities
 */
int
gtp_metrics_rx(struct gtp_metrics_msg *m, uint8_t msg_type)
{
	m->rx[msg_type].count++;
	return 0;
}

int
gtp_metrics_rx_notsup(struct gtp_metrics_msg *m, uint8_t msg_type)
{
	m->rx[msg_type].unsupported++;
	return 0;
}

int
gtp_metrics_tx(struct gtp_metrics_msg *m, uint8_t msg_type)
{
	m->tx[msg_type].count++;
	return 0;
}

int
gtp_metrics_tx_notsup(struct gtp_metrics_msg *m, uint8_t msg_type)
{
	m->tx[msg_type].unsupported++;
	return 0;
}

int
gtp_metrics_pkt_update(struct gtp_metrics_pkt *m, ssize_t nbytes)
{
	if (nbytes <= 0)
		return -1;

	m->bytes += nbytes;
	m->count++;
	return 0;
}

int
gtp_metrics_cause_update(struct gtp_metrics_cause *m, struct pkt_buffer *pbuff)
{
	struct gtp_ie_cause *ie_cause;
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, pbuff);
	if (!cp)
		return -1;

	ie_cause = (struct gtp_ie_cause *) cp;
	m->cause[ie_cause->value]++;
	return 0;
}


/*
 *	Metrics dump
 */
static int
gtp_sessions_metrics_tmpl_dump(struct gtp_apn *apn, void *arg)
{
	fprintf((FILE *) arg, "%s{apn=\"%s\"} %d\n"
			    , "gtpguard_gtp_sessions_current"
			    , apn->name, apn->session_count);
	return 0;
}

static int
gtp_metrics_dump(FILE *fp)
{
	fprintf(fp, "# HELP gtpguard_gtp_sessions_current Number of current GTP sessions\n"
		    "# TYPE gtpguard_gtp_sessions_current gauge\n");
	fprintf(fp, "gtpguard_gtp_sessions_current %d\n", gtp_sessions_count_read());
	gtp_apn_foreach(gtp_sessions_metrics_tmpl_dump, fp);
	fprintf(fp, "\n");
	return 0;
}


/*
 *	Handle request
 */
static int
gtp_metrics_json_parse_cmd(struct inet_cnx *c, struct json_node *json)
{
	char *cmd_str = NULL;

	if (!json_find_member_strvalue(json, "cmd", &cmd_str)) {
		fprintf(c->fp, "ERROR\n");
		goto end;
	}

	if (strncmp(cmd_str, "metrics", 7)) {
		fprintf(c->fp, "Unknown command:'%s'\n", cmd_str);
		goto end;
	}

	/* metrics */
	gtp_interface_metrics_dump(c->fp);
	vrrp_metrics_dump(c->fp);
	pppoe_metrics_dump(c->fp);
	gtp_metrics_dump(c->fp);
	gtp_router_metrics_dump(c->fp);

  end:
	return 0;
}


/*
 *	Request listener init
 */
int
gtp_metrics_cnx_process(struct inet_cnx *c)
{
	struct json_node *json;

	json = json_decode(c->buffer_in);
	if (!json) {
		log_message(LOG_INFO, "%s(): Error parsing JSON string : [%s]"
				    , __FUNCTION__
				    , c->buffer_in);
		return -1;
	}

	gtp_metrics_json_parse_cmd(c, json);
	json_destroy(json);
	return 0;
}

int
gtp_metrics_srv_prepare(struct inet_server *s)
{
	struct sockaddr_storage	*addr = &s->addr;

	if (addr->ss_family == AF_UNIX)
		unlink(((struct sockaddr_un *) addr)->sun_path);

	return 0;
}


/*
 *	GTP Metrics init
 */
int
gtp_metrics_init(void)
{
	struct inet_server *s = &daemon_data->metrics_channel;

	s->init = &gtp_metrics_srv_prepare;
	s->destroy = &gtp_metrics_srv_prepare;
	s->cnx_rcv = &inet_http_read;
	s->cnx_process = &gtp_metrics_cnx_process;

	inet_server_init(s, SOCK_STREAM);
	return inet_server_start(s, NULL);
}

int
gtp_metrics_destroy(void)
{
	return inet_server_destroy(&daemon_data->metrics_channel);
}
