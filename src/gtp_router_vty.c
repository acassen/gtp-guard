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

#include <inttypes.h>

#include "gtp_data.h"
#include "gtp_router.h"
#include "gtp_utils.h"
#include "gtp_bpf_rt.h"
#include "gtp.h"
#include "command.h"
#include "memory.h"
#include "bitops.h"
#include "inet_utils.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Command
 */
DEFUN(gtp_router,
      gtp_router_cmd,
      "gtp-router WORD",
      "Configure GTP routing context\n"
      "Context Name")
{
	struct gtp_router *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = gtp_router_get(argv[0]);
	new = (new) ? : gtp_router_init(argv[0]);
	if (!new) {
		vty_out(vty, "%% Error allocating gtp-router:%s !!!%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

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
	struct gtp_router *ctx;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}


	ctx = gtp_router_get(argv[0]);
	if (!ctx) {
		vty_out(vty, "%% unknown gtp-router %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_router_ctx_destroy(ctx);
	FREE(ctx);

	return CMD_SUCCESS;
}

DEFUN(gtp_router_bpf_program,
      gtp_router_bpf_program_cmd,
      "bpf-program WORD",
      "Use BPF Program\n"
      "BPF Program name")
{
	struct gtp_router *ctx = vty->index;
	struct gtp_bpf_prog *p;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ctx->bpf_prog = p;
	return CMD_SUCCESS;
}

DEFUN(gtpc_router_tunnel_endpoint,
      gtpc_router_tunnel_endpoint_cmd,
      "gtpc-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535>",
      "GTP Control channel tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2123)\n"
      "Number\n")
{
	struct gtp_router *ctx = vty->index;
	struct gtp_server *srv = &ctx->gtpc;
	struct sockaddr_storage *addr = &srv->s.addr;
	int port = 2123, err = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
		vty_out(vty, "%% GTPc already configured!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc == 2)
		VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);

	err = inet_stosockaddr(argv[0], port, addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	__set_bit(GTP_FL_CTL_BIT, &srv->flags);
	err = gtp_server_init(srv, ctx, gtp_router_ingress_init, gtp_router_ingress_process);
	if (err) {
		vty_out(vty, "%% Error initializing GTP-C listener on [%s]:%d%s"
			   , argv[0], port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(gtpu_router_tunnel_endpoint,
      gtpu_router_tunnel_endpoint_cmd,
      "gtpu-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535>",
      "GTP Userplane channel tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2152)\n"
      "Number\n")
{
	struct gtp_router *ctx = vty->index;
	struct gtp_server *srv = &ctx->gtpu;
	struct sockaddr_storage *addr = &srv->s.addr;
	int port = GTP_U_PORT, err = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_FL_UPF_BIT, &srv->flags)) {
		vty_out(vty, "%% GTPu already configured!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc == 2)
		VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);

	err = inet_stosockaddr(argv[0], port, addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	err = gtp_server_init(srv, ctx, gtp_router_ingress_init, gtp_router_ingress_process);
	if (err) {
		vty_out(vty, "%% Error initializing GTP-U listener on [%s]:%d%s"
			   , argv[0], port, VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}
	__set_bit(GTP_FL_UPF_BIT, &srv->flags);

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
gtp_config_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->gtp_router_ctx;
	struct gtp_server *srv;
	struct gtp_router *ctx;

	list_for_each_entry(ctx, l, next) {
		vty_out(vty, "gtp-router %s%s", ctx->name, VTY_NEWLINE);
		if (ctx->bpf_prog)
			vty_out(vty, " bpf-program %s%s"
				   , ctx->bpf_prog->name, VTY_NEWLINE);
		srv = &ctx->gtpc;
		if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
			vty_out(vty, " gtpc-tunnel-endpoint %s port %d%s"
				   , inet_sockaddrtos(&srv->s.addr)
				   , ntohs(inet_sockaddrport(&srv->s.addr))
				   , VTY_NEWLINE);
		}
		srv = &ctx->gtpu;
		if (__test_bit(GTP_FL_UPF_BIT, &srv->flags)) {
			vty_out(vty, " gtpu-tunnel-endpoint %s port %d%s"
				   , inet_sockaddrtos(&srv->s.addr)
				   , ntohs(inet_sockaddrport(&srv->s.addr))
				   , VTY_NEWLINE);
		}
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

static int
vty_server(struct vty *vty, struct gtp_server *srv, const char *gtplane)
{
	char flags2str[BUFSIZ];
	int i, type = -1;

	/* Can only be GTP-C OR GTP-U */
	if (__test_bit(GTP_FL_CTL_BIT, &srv->flags))
		type = GTP_FL_CTL_BIT;
	else if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
		type = GTP_FL_UPF_BIT;

	vty_out(vty, "  %s: %s port %d%s"
		     "   flags:0x%lx (%s)%s"
		     "   rx:%"PRIu64"packets %"PRIu64"bytes | tx:%"PRIu64"packets %"PRIu64"bytes%s"
		   , gtplane
		   , inet_sockaddrtos(&srv->s.addr)
		   , ntohs(inet_sockaddrport(&srv->s.addr))
		   , VTY_NEWLINE
		   , srv->flags, gtp_flags2str(flags2str, sizeof(flags2str), srv->flags)
		   , VTY_NEWLINE
		   , srv->rx_metrics.count, srv->rx_metrics.bytes
		   , srv->tx_metrics.count, srv->tx_metrics.bytes
		   , VTY_NEWLINE);

	vty_out(vty, "    RX:%s", VTY_NEWLINE);
	for (i = 0; i < GTP_METRIC_MAX_MSG; i++) {
		if (srv->msg_metrics.rx[i].count)
			vty_out(vty, "     %s(%d): %d%s"
				   , gtp_msgtype2str(type, i)
				   , i
				   , srv->msg_metrics.rx[i].count
				   , VTY_NEWLINE);

		if (srv->msg_metrics.rx[i].unsupported)
			vty_out(vty, "     %s(%d): %d (not supported)%s"
				   , gtp_msgtype2str(type, i)
				   , i
				   , srv->msg_metrics.rx[i].unsupported
				   , VTY_NEWLINE);

		if (srv->cause_rx_metrics.cause[i])
			vty_out(vty, "     %s(%d): %d%s"
				   , gtpc_cause2str(i)
				   , i
				   , srv->cause_rx_metrics.cause[i]
				   , VTY_NEWLINE);
	}

	vty_out(vty, "    TX:%s", VTY_NEWLINE);
	for (i = 0; i < GTP_METRIC_MAX_MSG; i++) {
		if (srv->msg_metrics.tx[i].count)
			vty_out(vty, "     %s(%d): %d%s"
				   , gtp_msgtype2str(type, i)
				   , i
				   , srv->msg_metrics.tx[i].count
				   , VTY_NEWLINE);

		if (srv->msg_metrics.tx[i].unsupported)
			vty_out(vty, "     %s(%d): %d (not supported)%s"
				   , gtp_msgtype2str(type, i)
				   , i
				   , srv->msg_metrics.tx[i].unsupported
				   , VTY_NEWLINE);

		if (srv->cause_tx_metrics.cause[i])
			vty_out(vty, "     %s(%d): %d%s"
				   , gtpc_cause2str(i)
				   , i
				   , srv->cause_tx_metrics.cause[i]
				   , VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/* Show */
DEFUN(show_gtp_router,
      show_gtp_router_cmd,
      "show gtp-router (*|STRING) [plane (gtpu|gtpc|both)]",
      SHOW_STR
      "workers tasks\n"
      "gtp-router gtpc and gtpu workers\n"
      "all workers\n"
      "Router name\n"
      "GTPu\n"
      "GTPc\n"
      "both GTPu and GTPc\n")
{
	const struct list_head *l = &daemon_data->gtp_router_ctx;
	const char *name =  (argc > 0) ? argv[0] : "*";
	const char *plane = (argc > 2) ? argv[2] : "both";
	struct gtp_router *ctx;
	struct gtp_server *srv;

	list_for_each_entry(ctx, l, next) {
		char flags2str[BUFSIZ];

		if ((name[0] != '*') && (strcmp(name, ctx->name) != 0))
			continue;

		vty_out(vty, "gtp-router %s refcnt:%d%s"
			     " flags:0x%lx (%s)%s"
			   , ctx->name
			   , ctx->refcnt
			   , VTY_NEWLINE
			   , ctx->flags, gtp_flags2str(flags2str, sizeof(flags2str), ctx->flags)
			   , VTY_NEWLINE);

		if (!strncmp(plane, "both", 4) || !strncmp(plane, "gtpc", 4)) {
			srv = &ctx->gtpc;
			if (__test_bit(GTP_FL_CTL_BIT, &srv->flags))
				vty_server(vty, srv, "gtpc");
			else
				vty_out(vty, "  gtpc: none%s", VTY_NEWLINE);
		}

		if (!strncmp(plane, "both", 4) || !strncmp(plane, "gtpu", 4)) {
			srv = &ctx->gtpu;
			if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
				vty_server(vty, srv, "gtpu");
			else
				vty_out(vty, "  gtpu: none%s", VTY_NEWLINE);
		}
	}

	return CMD_SUCCESS;
}

DEFUN(show_bpf_routing,
      show_bpf_routing_cmd,
      "show bpf routing",
      SHOW_STR
      "BPF GTP Routing Dataplane ruleset\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_rt_vty, vty, "gtp_route");
	return CMD_SUCCESS;
}

DEFUN(show_bpf_routing_iptnl,
      show_bpf_routing_iptnl_cmd,
      "show bpf routing iptunnel",
      SHOW_STR
      "BPF GTP Routing IPIP Tunnel ruleset\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_rt_iptnl_vty, vty, "gtp_route");
	return CMD_SUCCESS;
}

DEFUN(show_bpf_routing_lladdr,
      show_bpf_routing_lladdr_cmd,
      "show bpf routing lladdr",
      SHOW_STR
      "BPF GTP Routing link-layer Address\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_rt_lladdr_vty, vty, "gtp_route");
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
cmd_ext_gtp_router_install(void)
{
	/* Install PDN commands. */
	install_element(CONFIG_NODE, &gtp_router_cmd);
	install_element(CONFIG_NODE, &no_gtp_router_cmd);

	install_default(GTP_ROUTER_NODE);
	install_element(GTP_ROUTER_NODE, &gtp_router_bpf_program_cmd);
	install_element(GTP_ROUTER_NODE, &gtpc_router_tunnel_endpoint_cmd);
	install_element(GTP_ROUTER_NODE, &gtpu_router_tunnel_endpoint_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_gtp_router_cmd);
	install_element(VIEW_NODE, &show_bpf_routing_cmd);
	install_element(VIEW_NODE, &show_bpf_routing_iptnl_cmd);
	install_element(VIEW_NODE, &show_bpf_routing_lladdr_cmd);
	install_element(ENABLE_NODE, &show_gtp_router_cmd);
	install_element(ENABLE_NODE, &show_bpf_routing_cmd);
	install_element(ENABLE_NODE, &show_bpf_routing_iptnl_cmd);
	install_element(ENABLE_NODE, &show_bpf_routing_lladdr_cmd);

	return 0;
}

struct cmd_node gtp_router_node = {
	.node = GTP_ROUTER_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(gtp-router)# ",
	.config_write = gtp_config_write,
};

static struct cmd_ext cmd_ext_gtp_router = {
	.node = &gtp_router_node,
	.install = cmd_ext_gtp_router_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_gtp_router);
}
