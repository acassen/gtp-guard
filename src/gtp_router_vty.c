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
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <pthread.h>
#include <sys/stat.h>
#include <net/if.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

cmd_node_t gtp_router_node = {
        GTP_ROUTER_NODE,
        "%s(gtp-router)# ",
        1,
};


/*
 *	Command
 */
DEFUN(gtp_router,
      gtp_router_cmd,
      "gtp-router WORD",
      "Configure GTP routing context\n"
      "Context Name")
{
	gtp_router_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = gtp_router_get(argv[0]);
	if (!new)
		new = gtp_router_init(argv[0]);

	vty->node = GTP_ROUTER_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_gtp_router,
      no_gtp_router_cmd,
      "no gtp-router WORD",
      "Configure GTP routing context\n"
      "Context Name")
{
	gtp_router_t *ctx;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	ctx = gtp_router_get(argv[0]);
	if (!ctx) {
		vty_out(vty, "%% unknown gtp-router %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_router_ctx_destroy(ctx);
	FREE(ctx);

	return CMD_SUCCESS;
}

DEFUN(gtpc_router_tunnel_endpoint,
      gtpc_router_tunnel_endpoint_cmd,
      "gtpc-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535> [listener-count [INTEGER]]",
      "GTP Control channel tunnel endpoint\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "listening UDP Port\n"
      "Number\n")
{
        gtp_router_t *ctx = vty->index;
        gtp_server_t *srv = &ctx->gtpc;
	struct sockaddr_storage *addr = &srv->addr;
	int port = 0, ret = 0;

        if (argc < 1) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

        if (argc == 2) {
                VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);
                if (port) {}; /* dummy test */
        	ret = inet_stosockaddr(argv[0], argv[1], addr);
        } else {
        	ret = inet_stosockaddr(argv[0], "2123", addr);
        }

	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	srv->thread_cnt = (argc == 3) ? strtoul(argv[2], NULL, 10) : GTP_DEFAULT_THREAD_CNT;
	__set_bit(GTP_FL_CTL_BIT, &srv->flags);
	gtp_server_init(srv, ctx, gtp_router_ingress_init, gtp_router_ingress_process);
	gtp_server_start(srv);

	return CMD_SUCCESS;
}

DEFUN(gtpu_router_tunnel_endpoint,
      gtpu_router_tunnel_endpoint_cmd,
      "gtpu-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535>",
      "GTP Userplane channel tunnel endpoint\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "listening UDP Port\n"
      "Number\n")
{
	gtp_router_t *ctx = vty->index;
	gtp_server_t *srv = &ctx->gtpu;
	struct sockaddr_storage *addr = &srv->addr;
	int port, ret = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc == 2) {
		VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);
		if (port) {}; /* dummy test */
		ret = inet_stosockaddr(argv[0], argv[1], addr);
	} else {
		ret = inet_stosockaddr(argv[0], "2152", addr);
	}

	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	srv->thread_cnt = GTP_DEFAULT_THREAD_CNT;
	__set_bit(GTP_FL_UPF_BIT, &srv->flags);
	gtp_server_init(srv, ctx, gtp_router_ingress_init, gtp_router_ingress_process);
	gtp_server_start(srv);

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
gtp_config_write(vty_t *vty)
{
        list_head_t *l = &daemon_data->gtp_router_ctx;
        gtp_server_t *srv;
        gtp_router_t *ctx;

        list_for_each_entry(ctx, l, next) {
        	vty_out(vty, "gtp-router %s%s", ctx->name, VTY_NEWLINE);
		srv = &ctx->gtpc;
		if (__test_bit(GTP_FL_CTL_BIT, &srv->flags))
			vty_out(vty, " gtpc-tunnel-endpoint %s port %d%s"
				   , inet_sockaddrtos(&srv->addr)
				   , ntohs(inet_sockaddrport(&srv->addr))
				   , VTY_NEWLINE);
		srv = &ctx->gtpu;
		if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
			vty_out(vty, " gtpu-tunnel-endpoint %s port %d%s"
				   , inet_sockaddrtos(&srv->addr)
				   , ntohs(inet_sockaddrport(&srv->addr))
				   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_router_vty_init(void)
{
	/* Install PDN commands. */
	install_node(&gtp_router_node, gtp_config_write);
	install_element(CONFIG_NODE, &gtp_router_cmd);
	install_element(CONFIG_NODE, &no_gtp_router_cmd);

	install_default(GTP_ROUTER_NODE);
	install_element(GTP_ROUTER_NODE, &gtpc_router_tunnel_endpoint_cmd);
	install_element(GTP_ROUTER_NODE, &gtpu_router_tunnel_endpoint_cmd);

	return 0;
}
