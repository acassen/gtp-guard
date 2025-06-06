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

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Handle request
 */
static int
gtp_request_json_parse_cmd(inet_cnx_t *c, json_node_t *json)
{
	char *cmd_str = NULL, *apn_str = NULL, *imsi_str = NULL;
	char addr_str[INET6_ADDRSTRLEN];
	json_writer_t *jwriter = c->arg;
	gtp_apn_t *apn;
	gtp_conn_t *conn;
	uint8_t imsi_swap[8];
	uint64_t imsi;

	jsonw_start_object(jwriter);

	if (!json_find_member_strvalue(json, "cmd", &cmd_str)) {
		jsonw_string_field(jwriter, "Error", "No command specified");
		goto end;
	}

	if (strncmp(cmd_str, "imsi_info", 9)) {
		jsonw_string_field_fmt(jwriter, "Error", "Unknown command %s", cmd_str);
		goto end;
	}

	if (!json_find_member_strvalue(json, "apn", &apn_str)) {
		jsonw_string_field(jwriter, "Error", "No Access-Point-Name specified");
		goto end;
	}

	if (!json_find_member_strvalue(json, "imsi", &imsi_str)) {
		jsonw_string_field(jwriter, "Error", "No IMSI specified");
		goto end;
	}

	gtp_apn_extract_ni(apn_str, strlen(apn_str), c->buffer_out, INET_BUFFER_SIZE);
	apn = gtp_apn_get(c->buffer_out);
	if (!apn) {
		jsonw_string_field(jwriter, "Error", "Unknown Access-Point-Name");
		goto end;
	}

	memset(imsi_swap, 0, 8);
	str_imsi_to_bcd_swap(imsi_str, strlen(imsi_str), imsi_swap);
	gtp_imsi_rewrite(apn, imsi_swap);
	imsi = bcd_to_int64(imsi_swap, 8);
	conn = gtp_conn_get_by_imsi(imsi);
	if (!conn) {
		jsonw_string_field(jwriter, "Error", "Unknown IMSI");
		goto end;
	}

	jsonw_string_field_fmt(jwriter, "sgw-ip-address", "%u.%u.%u.%u"
					 , NIPQUAD(conn->sgw_addr.sin_addr.s_addr));

	log_message(LOG_INFO, "%s(): imsi_info:={imsi:%s sgw-ip-address:%u.%u.%u.%u} with peer [%s]:%d"
			    , __FUNCTION__
			    , imsi_str
			    ,  NIPQUAD(conn->sgw_addr.sin_addr.s_addr)
			    , inet_sockaddrtos2(&c->addr, addr_str)
			    , ntohs(inet_sockaddrport(&c->addr)));

	gtp_conn_put(conn);
  end:
	jsonw_end_object(jwriter);
	return 0;
}


/*
 *	Request listener init
 */
static int
gtp_request_cnx_process(inet_cnx_t *c)
{
	json_node_t *json;

	json = json_decode(c->buffer_in);
	if (!json) {
		log_message(LOG_INFO, "%s(): Error parsing JSON string : [%s]"
				    , __FUNCTION__
				    , c->buffer_in);
		return -1;
	}

	gtp_request_json_parse_cmd(c, json);
	json_destroy(json);
	return 0;
}

static int
gtp_request_cnx_init(inet_cnx_t *c)
{
	json_writer_t *jwriter = jsonw_new(c->fp);
	c->arg = jwriter;
	return 0;
}

static int
gtp_request_cnx_destroy(inet_cnx_t *c)
{
	json_writer_t *jwriter = c->arg;
	jsonw_destroy(&jwriter);
	return 0;
}


/*
 *	GTP Request init
 */
int
gtp_request_init(void)
{
	inet_server_t *srv = &daemon_data->request_channel;

	srv->cnx_init = gtp_request_cnx_init;
	srv->cnx_destroy = gtp_request_cnx_destroy;
	srv->cnx_rcv = inet_http_read;
	srv->cnx_process = gtp_request_cnx_process;

	return inet_server_worker_start(srv);
}

int
gtp_request_destroy(void)
{
	return inet_server_destroy(&daemon_data->request_channel);
}
