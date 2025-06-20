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
#include <sys/un.h>
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
gtp_metrics_json_parse_cmd(inet_cnx_t *c, json_node_t *json)
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

	/* TODO: Add metrics txt output */
	gtp_interface_metrics_dump(c->fp);
	vrrp_metrics_dump(c->fp);

  end:
	return 0;
}


/*
 *	Request listener init
 */
int
gtp_metrics_cnx_process(inet_cnx_t *c)
{
	json_node_t *json;

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
gtp_metrics_srv_prepare(inet_server_t *s)
{
	struct sockaddr_storage	*addr = &s->addr;

	if (addr->ss_family == AF_UNIX)
		unlink(((struct sockaddr_un *) addr)->sun_path);

	return 0;
}


/*
 *	GTP Request init
 */
int
gtp_metrics_init(void)
{
	inet_server_t *s = &daemon_data->metrics_channel;

	s->init = &gtp_metrics_srv_prepare;
	s->destroy = &gtp_metrics_srv_prepare;
	s->cnx_rcv = &inet_http_read;
	s->cnx_process = &gtp_metrics_cnx_process;

	inet_server_init(s);
	return inet_server_worker_start(s);
}

int
gtp_metrics_destroy(void)
{
	return inet_server_destroy(&daemon_data->metrics_channel);
}
