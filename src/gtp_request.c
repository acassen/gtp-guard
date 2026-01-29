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

#include <string.h>

#include "gtp_data.h"
#include "gtp_apn.h"
#include "gtp_conn.h"
#include "gtp_utils.h"
#include "json_reader.h"
#include "json_writer.h"
#include "inet_utils.h"
#include "logger.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Handle request
 */
static int
gtp_request_json_parse_cmd(struct inet_cnx *c, struct json_node *json)
{
	struct json_writer *jwriter = c->arg;
	struct gtp_apn *apn;
	struct gtp_conn *conn;
	char *cmd_str = NULL, *apn_str = NULL, *imsi_str = NULL;
	char addr_str[INET6_ADDRSTRLEN];
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

	gtp_apn_extract_str_ni(apn_str, strlen(apn_str), c->buffer_out, DEFAULT_PKT_BUFFER_SIZE);
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
int
gtp_request_cnx_process(struct inet_cnx *c)
{
	struct json_node *json;

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

int
gtp_request_cnx_init(struct inet_cnx *c)
{
	struct json_writer *jwriter = jsonw_new(c->fp);
	c->arg = jwriter;
	return 0;
}

int
gtp_request_cnx_destroy(struct inet_cnx *c)
{
	struct json_writer *jwriter = c->arg;
	jsonw_destroy(&jwriter);
	return 0;
}


/*
 *	GTP Request init
 */
int
gtp_request_init(void)
{
	struct inet_server *s = &daemon_data->request_channel;

	s->cnx_init = &gtp_request_cnx_init;
	s->cnx_destroy = &gtp_request_cnx_destroy;
	s->cnx_rcv = &inet_http_read;
	s->cnx_process = &gtp_request_cnx_process;

	inet_server_init(s, SOCK_STREAM);
	return inet_server_start(s, NULL);
}

int
gtp_request_destroy(void)
{
	return inet_server_destroy(&daemon_data->request_channel);
}
