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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <net/if.h>

#include "gtp_data.h"
#include "gtp_proxy.h"
#include "gtp_dpd.h"
#include "gtp_bpf_utils.h"
#include "gtp_bpf_fwd.h"
#include "command.h"
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "inet_utils.h"


/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Command
 */
DEFUN(gtp_proxy,
      gtp_proxy_cmd,
      "gtp-proxy WORD",
      "Configure GTP proxying context\n"
      "Context Name")
{
	struct gtp_proxy *ctx;

	if (!strcmp(argv[0], "all")) {
		vty_out(vty, "%% gtp-proxy cannot be named 'all'\n");
		return CMD_WARNING;
	}

	/* Already existing ? */
	ctx = gtp_proxy_get(argv[0]);
	ctx = ctx ?: gtp_proxy_alloc(argv[0]);
	if (!ctx) {
		vty_out(vty, "%% Error allocating gtp-proxy:%s !!!\n", argv[0]);
		return CMD_WARNING;
	}

	vty->node = GTP_PROXY_NODE;
	vty->index = ctx;
	return CMD_SUCCESS;
}

DEFUN(no_gtp_proxy,
      no_gtp_proxy_cmd,
      "no gtp-proxy WORD",
      "Configure GTP proxying context\n"
      "Context Name")
{
	struct list_head *l = &daemon_data->gtp_proxy_ctx;
	struct gtp_proxy *ctx, *ctx_tmp;

	/* Remove all instances */
	if (!strcmp(argv[0], "all")) {
		list_for_each_entry_safe(ctx, ctx_tmp, l, next)
			gtp_proxy_ctx_destroy(ctx);
		return CMD_SUCCESS;
	}

	/* Already existing ? */
	ctx = gtp_proxy_get(argv[0]);
	if (!ctx) {
		vty_out(vty, "%% unknown gtp-proxy %s\n", argv[0]);
		return CMD_WARNING;
	}

	gtp_proxy_ctx_destroy(ctx);

	return CMD_SUCCESS;
}

DEFUN(gtp_proxy_bpf_program,
      gtp_proxy_bpf_program_cmd,
      "bpf-program WORD",
      "Use BPF Program\n"
      "BPF Program name")
{
	struct gtp_proxy *ctx = vty->index;
	struct gtp_bpf_prog *p;

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ctx->bpf_prog = p;
	ctx->bpf_data = gtp_bpf_prog_tpl_data_get(p, "gtp_fwd");
	list_add(&ctx->bpf_list, &ctx->bpf_data->gtp_proxy_list);

	return CMD_SUCCESS;
}

DEFUN(gtp_proxy_session_expiration_timeout_delete,
      gtp_proxy_session_expiration_timeout_delete_cmd,
      "session-expiration-on-delete-timeout <5-300>",
      "Force session expiration if delete response is timeout\n"
      "number of seconds\n")
{
	struct gtp_proxy *ctx = vty->index;
	int timeout;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Expiration Timeout", timeout, argv[0], 5, 300);
	ctx->session_delete_to = timeout;

	__set_bit(GTP_FL_SESSION_EXPIRATION_DELETE_TO_BIT, &ctx->flags);
	return CMD_SUCCESS;
}

DEFUN(gtpc_proxy_tunnel_endpoint,
      gtpc_proxy_tunnel_endpoint_cmd,
      "gtpc-tunnel-endpoint (A.B.C.D|X:X::X:X) port <1024-65535>",
      "GTP Control channel ingress tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2123)\n"
      "Number\n")
{
	struct gtp_proxy *ctx = vty->index;
	struct gtp_server *srv = &ctx->gtpc;
	struct sockaddr_storage *addr = &srv->s.addr;
	int port = 2123, err = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
		vty_out(vty, "%% GTP-C already configured!%s", VTY_NEWLINE);
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
	__set_bit(GTP_FL_GTPC_INGRESS_BIT, &srv->flags);
	err = gtp_server_init(srv, ctx, gtp_proxy_ingress_init, gtp_proxy_ingress_process);
	if (err) {
		vty_out(vty, "%% Error initializing Ingress GTP-C Proxy listener on [%s]:%d%s"
			   , argv[0], port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(gtpc_proxy_egress_tunnel_endpoint,
      gtpc_proxy_egress_tunnel_endpoint_cmd,
      "gtpc-egress-tunnel-endpoint (A.B.C.D|X:X::X:X) port <1024-65535>",
      "GTP Control channel egress tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2123)\n"
      "Number\n")
{
	struct gtp_proxy *ctx = vty->index;
	struct gtp_server *srv = &ctx->gtpc_egress;
	struct sockaddr_storage *addr = &srv->s.addr;
	int port = 2123, err = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
		vty_out(vty, "%% GTP-C egress already configured!%s", VTY_NEWLINE);
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
	__set_bit(GTP_FL_GTPC_EGRESS_BIT, &srv->flags);
	err = gtp_server_init(srv, ctx, gtp_proxy_ingress_init, gtp_proxy_ingress_process);
	if (err) {
		vty_out(vty, "%% Error initializing Egress GTP-C Proxy listener on [%s]:%d%s"
			   , argv[0], port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(gtpc_force_pgw_selection,
      gtpc_force_pgw_selection_cmd,
      "force-pgw-selection (A.B.C.D|X:X:X:X)",
      "Force pGW Selection\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	struct gtp_proxy *ctx = vty->index;
	struct sockaddr_storage *addr = &ctx->pgw_addr;
	int ret;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_stosockaddr(argv[0], 2123, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	__set_bit(GTP_FL_FORCE_PGW_BIT, &ctx->flags);
	return CMD_SUCCESS;
}

DEFUN(gtpu_proxy_tunnel_endpoint,
      gtpu_proxy_tunnel_endpoint_cmd,
      "gtpu-tunnel-endpoint (A.B.C.D|X:X::X:X) (ingress|egress|both-sides) interfaces .IFACE",
      "GTP Userplane channel tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "ingress side\n"
      "egress side\n"
      "both sides\n"
      "Use interface\n"
      "Interface name\n"
      "listening UDP Port (default = 2152)\n"
      "Number\n")
{
	struct gtp_proxy *ctx = vty->index;
	struct gtp_interface *iface;
	struct gtp_server *srv;
	const char *bind_addr_str = argv[0];
	union addr bind_addr;
	bool ingress = !strcmp(argv[1], "ingress") || !strcmp(argv[1], "both-sides");
	bool egress = !strcmp(argv[1], "egress") || !strcmp(argv[1], "both-sides");
	char buf[100];
	int i, err = 0;

	if (!ctx->bpf_prog) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!\n");
		return CMD_WARNING;
	}

	/* build bind-address for gtp-u socket */
	err = addr_parse(bind_addr_str, &bind_addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s\n", bind_addr_str);
		return CMD_WARNING;
	}
	if (!addr_get_port(&bind_addr))
		addr_set_port(&bind_addr, GTP_U_PORT);

	for (i = 2; i < argc; i++) {
		iface = gtp_interface_get(argv[i], true);
		if (iface == NULL) {
			vty_out(vty, "%% cannot find interface %s\n", argv[i]);
			return CMD_WARNING;
		}

		if (ingress) {
			err = gtp_interface_rules_ctx_add(ctx->irules, iface, true);
			if (err && errno == EEXIST) {
				vty_out(vty, "%% interface %s already added as ingress\n",
					argv[i]);
				return CMD_WARNING;
			}
		}
		if (egress) {
			err = gtp_interface_rules_ctx_add(ctx->irules, iface, false);
			if (err && errno == EEXIST) {
				vty_out(vty, "%% interface %s already added as egress\n",
					argv[i]);
				return CMD_WARNING;
			}
		}
	}

	/* bind service */
	if (egress && !ingress)
		srv = &ctx->gtpu_egress;
	else
		srv = &ctx->gtpu;
	srv->s.addr = bind_addr.ss;
	__set_bit(GTP_FL_UPF_BIT, &srv->flags);
	err = gtp_server_init(srv, ctx, gtp_proxy_ingress_init, gtp_proxy_ingress_process);
	if (err) {
		vty_out(vty, "%% Error initializing %s GTP-U Proxy listener on %s\n",
			argv[1], addr_stringify(&bind_addr, buf, sizeof (buf)));
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(gtpu_debug,
      gtpu_debug_cmd,
      "gtpu debug (on|off)",
      "GTP Userplane\n"
      "Be more verbose in log messages\n"
      "On\n"
      "Off\n")
{
	struct gtp_proxy *ctx = vty->index;

	ctx->debug = !strcmp(argv[0], "on");
	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip,
      gtpu_ipip_cmd,
      "gtpu-ipip interface IFACE view (ingress|egress|xlat-before|xlat-after)",
      "GTP Userplane IPIP tunnel\n")
{
	struct gtp_proxy *ctx = vty->index;
	struct gtp_interface *iface;

	if (!ctx->bpf_prog) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!\n");
		return CMD_WARNING;
	}

	iface = gtp_interface_get(argv[0], true);
	if (iface == NULL) {
		vty_out(vty, "%% cannot find interface %s\n", argv[0]);
		return CMD_WARNING;
	}

	if (ctx->ipip_iface) {
		vty_out(vty, "%% gtpu endpoint ipip already set\n");
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "ingress"))
		ctx->ipip_xlat = 1;
	else if (!strcmp(argv[1], "egress"))
		ctx->ipip_xlat = 2;
	else if (!strcmp(argv[1], "xlat-before"))
		ctx->ipip_xlat = 3;
	else if (!strcmp(argv[1], "xlat-after"))
		ctx->ipip_xlat = 4;

	ctx->ipip_iface = iface;
	gtp_interface_register_event(iface, gtp_proxy_iface_tun_event_cb, ctx);

	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip_dead_peer_detection,
      gtpu_ipip_dead_peer_detection_cmd,
      "gtpu-ipip dead-peer-detection <3-15> src-addr (A.B.C.D|X:X:X:X) interface STRING payload-length <128-4096>",
      "GTP Userplane IPIP tunnel\n"
      "GTP-U IPIP tunnel Dead Peer Detection\n"
      "Dead Credit in seconds\n"
      "IP Src to use for DPD packets\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Interface running cBPF to catch DPD packet\n"
      "Name\n"
      "Payload attached to DPD GTP packet\n"
      "Number\n")
{
	struct gtp_proxy *ctx = vty->index;
	struct gtp_iptnl *t = &ctx->iptnl;
	int credit, ifindex, plen, err;
	uint32_t saddr;

	if (!ctx->bpf_prog) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!\n");
		return CMD_WARNING;
	}

	if (t->flags & IPTNL_FL_DPD)
		return CMD_SUCCESS;

	if (argc < 3) {
		vty_out(vty, "%% Invalid arguments%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Credit handling */
	t->credit = 3 * TIMER_HZ;
	VTY_GET_INTEGER_RANGE("Dead Credit", credit, argv[0], 3, 15);
	t->credit = credit * TIMER_HZ;
	t->expire = timer_long(time_now) + t->credit;

	/* Dead-Peer-Detection Src IP Address */
	err = inet_ston(argv[1], &saddr);
	if (!err) {
		vty_out(vty, "%% malformed Local IP address %s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	t->dpd_saddr = saddr;

	/* Interface handling */
	ifindex = if_nametoindex(argv[2]);
	if (!ifindex) {
		vty_out(vty, "%% Error with interface %s (%s)%s"
			   , argv[1]
			   , strerror(errno)
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}
	t->ifindex = ifindex;

	/* Payload handling */
	t->payload_len = DEFAULT_DPD_LENGTH;
	if (argc == 4) {
		VTY_GET_INTEGER_RANGE("Payload Length", plen, argv[3], 128, 4096);
		t->payload_len = plen;
	}

	err = gtp_dpd_init(ctx);
	if (err) {
		vty_out(vty, "%% Error starting Dead-Peer-Detection on interface %s (%s)%s"
			   , argv[1]
			   , strerror(errno)
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	t->flags |= IPTNL_FL_DPD;

	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip_debug_set_teid,
      gtpu_ipip_debug_set_teid_cmd,
      "gtpu-ipip debug teid (add|del) VTEID TEID ENDPTADDR (egress|ingress)",
      "GTP Userplane IPIP tunnel\n"
      "Debug command\n")
{
	struct gtp_proxy *ctx = vty->index;
	int action = !strcmp(argv[0], "add") ? RULE_ADD : RULE_DEL;
	struct gtp_teid t = {};
	union addr a;

	t.vid = atoi(argv[1]);
	t.id = htonl(atoi(argv[2]));
	addr_parse(argv[3], &a);
	t.ipv4 = a.sin.sin_addr.s_addr;
	__set_bit(!strcmp(argv[4], "ingress") ?
		  GTP_TEID_FL_INGRESS : GTP_TEID_FL_EGRESS, &t.flags);

	gtp_bpf_teid_action(ctx, action, &t);

	return CMD_SUCCESS;
}


/* Show */
DEFUN(show_bpf_forwarding,
      show_bpf_forwarding_cmd,
      "show bpf forwarding",
      SHOW_STR
      "BPF GTP Fowarding Dataplane ruleset\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_fwd_vty, vty, "gtp_fwd");
	return CMD_SUCCESS;
}


/* Configuration writer */
static int
gtp_config_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->gtp_proxy_ctx;
	struct gtp_server *srv;
	struct gtp_proxy *ctx;
	char ifname[IF_NAMESIZE];
	int nin, neg, nbo, i, j, port;
	struct gtp_interface *ifin[8], *ifeg[8], *ifbo[8];
	char sport[10];


	list_for_each_entry(ctx, l, next) {
		vty_out(vty, "gtp-proxy %s%s", ctx->name, VTY_NEWLINE);
		if (ctx->bpf_prog)
			vty_out(vty, " bpf-program %s%s"
				   , ctx->bpf_prog->name
				   , VTY_NEWLINE);
		if (__test_bit(GTP_FL_SESSION_EXPIRATION_DELETE_TO_BIT, &ctx->flags))
			vty_out(vty, " session-expiration-on-delete-timeout %d%s"
				   , ctx->session_delete_to, VTY_NEWLINE);
		srv = &ctx->gtpc;
		if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
			vty_out(vty, " gtpc-tunnel-endpoint %s port %d%s"
				   , inet_sockaddrtos(&srv->s.addr)
				   , ntohs(inet_sockaddrport(&srv->s.addr))
				   , VTY_NEWLINE);
		}
		srv = &ctx->gtpc_egress;
		if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
			vty_out(vty, " gtpc-egress-tunnel-endpoint %s port %d%s"
				   , inet_sockaddrtos(&srv->s.addr)
				   , ntohs(inet_sockaddrport(&srv->s.addr))
				   , VTY_NEWLINE);
		}
		nin = gtp_interface_rules_ctx_list_bound(ctx->irules, true, ifin,
						       ARRAY_SIZE(ifin));
		neg = gtp_interface_rules_ctx_list_bound(ctx->irules, false, ifeg,
						       ARRAY_SIZE(ifeg));
		for (i = 0, nbo = 0; i < nin; i++) {
			for (j = 0; j < neg; j++) {
				if (ifeg[j] == ifin[i]) {
					ifbo[nbo++] = ifin[i];
					ifin[i--] = ifin[--nin];
					ifeg[j--] = ifeg[--neg];
				}
			}
		}
		if (nin || nbo) {
			srv = &ctx->gtpu;
			port = ntohs(inet_sockaddrport(&srv->s.addr));
			sport[0] = 0;
			if (port != GTP_U_PORT)
				sprintf(sport, ":%d", port);
		}
		if (nin) {
			vty_out(vty, " gtpu-tunnel-endpoint %s%s ingress interfaces",
				inet_sockaddrtos(&srv->s.addr), sport);
			for (i = 0; i < nin; i++)
				vty_out(vty, " %s", ifin[i]->ifname);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		if (nbo) {
			vty_out(vty, " gtpu-tunnel-endpoint %s%s both-sides interfaces",
				inet_sockaddrtos(&srv->s.addr), sport);
			for (i = 0; i < nbo; i++)
				vty_out(vty, " %s", ifbo[i]->ifname);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		if (neg) {
			srv = &ctx->gtpu;
			port = ntohs(inet_sockaddrport(&srv->s.addr));
			sport[0] = 0;
			if (port != GTP_U_PORT)
				sprintf(sport, ":%d", port);
			vty_out(vty, " gtpu-tunnel-endpoint %s%s egress interfaces",
				inet_sockaddrtos(&srv->s.addr), sport);
			for (i = 0; i < neg; i++)
				vty_out(vty, " %s", ifeg[i]->ifname);
			vty_out(vty, "%s", VTY_NEWLINE);
		}

		if (__test_bit(GTP_FL_FORCE_PGW_BIT, &ctx->flags))
			vty_out(vty, " pgw-force-selection %s%s"
				   , inet_sockaddrtos(&ctx->pgw_addr)
				   , VTY_NEWLINE);
		if (ctx->ipip_iface) {
			vty_out(vty, " gtpu-ipip interface %s view %s\n"
				   , ctx->ipip_iface->ifname
				   , ctx->ipip_xlat == 1 ? "ingress" :
				     ctx->ipip_xlat == 2 ? "egress" :
				     ctx->ipip_xlat == 3 ? "xlat-before" :
				     ctx->ipip_xlat == 4 ? "xlat-after" : "unset");
		}
		if (ctx->iptnl.flags & IPTNL_FL_DPD)
			vty_out(vty, " gtpu-ipip dead-peer-detection %ld src-addr %u.%u.%u.%u interface %s%s"
				   , ctx->iptnl.credit / TIMER_HZ
				   , NIPQUAD(ctx->iptnl.dpd_saddr)
				   , if_indextoname(ctx->iptnl.ifindex, ifname)
				   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
cmd_ext_gtp_proxy_install(void)
{
	/* Install gtp-proxy commands. */
	install_element(CONFIG_NODE, &gtp_proxy_cmd);
	install_element(CONFIG_NODE, &no_gtp_proxy_cmd);

	install_default(GTP_PROXY_NODE);
	install_element(GTP_PROXY_NODE, &gtp_proxy_bpf_program_cmd);
	install_element(GTP_PROXY_NODE, &gtp_proxy_session_expiration_timeout_delete_cmd);
	install_element(GTP_PROXY_NODE, &gtpc_proxy_tunnel_endpoint_cmd);
	install_element(GTP_PROXY_NODE, &gtpc_proxy_egress_tunnel_endpoint_cmd);
	install_element(GTP_PROXY_NODE, &gtpc_force_pgw_selection_cmd);
	install_element(GTP_PROXY_NODE, &gtpu_proxy_tunnel_endpoint_cmd);
	install_element(GTP_PROXY_NODE, &gtpu_debug_cmd);
	install_element(GTP_PROXY_NODE, &gtpu_ipip_cmd);
	install_element(GTP_PROXY_NODE, &gtpu_ipip_dead_peer_detection_cmd);
	install_element(GTP_PROXY_NODE, &gtpu_ipip_debug_set_teid_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_bpf_forwarding_cmd);
	install_element(ENABLE_NODE, &show_bpf_forwarding_cmd);

	return 0;
}

struct cmd_node gtp_proxy_node = {
	.node = GTP_PROXY_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(gtp-proxy)# ",
	.config_write = gtp_config_write,
};

static struct cmd_ext cmd_ext_gtp_proxy = {
	.node = &gtp_proxy_node,
	.install = cmd_ext_gtp_proxy_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_gtp_proxy);
}
