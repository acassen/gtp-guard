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

static int gtp_config_write(vty_t *vty);
cmd_node_t gtp_switch_node = {
        .node = GTP_SWITCH_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(gtp-switch)# ",
        .config_write = gtp_config_write,
};


/*
 *	Command
 */
DEFUN(gtp_switch,
      gtp_switch_cmd,
      "gtp-switch WORD",
      "Configure GTP switching context\n"
      "Context Name")
{
	gtp_switch_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = gtp_switch_get(argv[0]);
	if (!new)
		new = gtp_switch_init(argv[0]);

	vty->node = GTP_SWITCH_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_gtp_switch,
      no_gtp_switch_cmd,
      "no gtp-switch WORD",
      "Configure GTP switching context\n"
      "Context Name")
{
	gtp_switch_t *ctx;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	ctx = gtp_switch_get(argv[0]);
	if (!ctx) {
		vty_out(vty, "%% unknown gtp-switch %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_switch_ctx_destroy(ctx);
	FREE(ctx);

	return CMD_SUCCESS;
}

DEFUN(gtpc_switch_tunnel_endpoint,
      gtpc_switch_tunnel_endpoint_cmd,
      "gtpc-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535> [listener-count [INTEGER]]",
      "GTP Control channel ingress tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2123)\n"
      "Number\n"
      "max UDP listener pthreads\n"
      "Number pthreads (default = "STR(GTP_DEFAULT_THREAD_CNT)")\n")
{
        gtp_switch_t *ctx = vty->index;
        gtp_server_t *srv = &ctx->gtpc;
	struct sockaddr_storage *addr = &srv->addr;
	int port = 2123, ret = 0;

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

	ret = inet_stosockaddr(argv[0], port, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	/* argv[3] is listnener-count */
	srv->thread_cnt = (argc == 4) ? strtoul(argv[3], NULL, 10) : GTP_DEFAULT_THREAD_CNT;
	srv->thread_cnt = (srv->thread_cnt < 1) ? 1 : srv->thread_cnt;
	__set_bit(GTP_FL_CTL_BIT, &srv->flags);
	gtp_server_init(srv, ctx, gtp_switch_ingress_init, gtp_switch_ingress_process);
	gtp_server_start(srv);

	return CMD_SUCCESS;
}

DEFUN(gtpu_switch_tunnel_endpoint,
      gtpu_switch_tunnel_endpoint_cmd,
      "gtpu-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535> [listener-count [INTEGER]]",
      "GTP Userplane channel tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2152)\n"
      "Number\n"
      "max UDP listener pthreads\n"
      "Number pthreads (default = "STR(GTP_DEFAULT_THREAD_CNT)")\n")
{
        gtp_switch_t *ctx = vty->index;
        gtp_server_t *srv = &ctx->gtpu;
	struct sockaddr_storage *addr = &srv->addr;
	int port = 2152, ret = 0;

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

	ret = inet_stosockaddr(argv[0], port, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	/* argv[3] is listnener-count */
        srv->thread_cnt = (argc == 4) ? strtoul(argv[3], NULL, 10) : GTP_DEFAULT_THREAD_CNT;
        srv->thread_cnt = (srv->thread_cnt < 1) ? 1 : srv->thread_cnt;
        __set_bit(GTP_FL_UPF_BIT, &srv->flags);
        gtp_server_init(srv, ctx, gtp_switch_ingress_init, gtp_switch_ingress_process);
        gtp_server_start(srv);

	return CMD_SUCCESS;
}

DEFUN(gtpc_force_pgw_selection,
      gtpc_force_pgw_selection_cmd,
      "force-pgw-selection (A.B.C.D|X:X:X:X)",
      "Force pGW Selection\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
        gtp_switch_t *ctx = vty->index;
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

DEFUN(gtpu_ipip,
      gtpu_ipip_cmd,
      "gtpu-ipip traffic-selector (A.B.C.D|X:X:X:X) local (A.B.C.D|X:X:X:X) remote (A.B.C.D|X:X:X:X) [vlan <1-4095>]",
      "GTP Userplane IPIP tunnel\n"
      "GTP-U local L3 destination address\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Local Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Remote Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Vlan ID\n"
      "Number\n")
{
        gtp_switch_t *ctx = vty->index;
	gtp_iptnl_t *t = &ctx->iptnl;
	uint32_t saddr, laddr, raddr;
	int ret = 0, vlan = 0;

	if (!__test_bit(GTP_FL_GTP_FORWARD_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc < 3) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
        }

	ret = inet_ston(argv[0], &saddr);
	if (!ret) {
		vty_out(vty, "%% malformed Local IP address %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_ston(argv[1], &laddr);
	if (!ret) {
		vty_out(vty, "%% malformed Local IP address %s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_ston(argv[2], &raddr);
	if (!ret) {
		vty_out(vty, "%% malformed Remote IP address %s%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc == 5) {
                VTY_GET_INTEGER_RANGE("Vlan ID", vlan, argv[4], 1, 4095);
                if (vlan) {} ; /* dummy test */
	}

	t->selector_addr = saddr;
	t->local_addr = laddr;
	t->remote_addr = raddr;
	t->encap_vlan_id = vlan;
	ret = gtp_xdp_fwd_iptnl_action(RULE_ADD, t);
	if (ret < 0) {
		vty_out(vty, "%% Unable to create XDP IPIP-Tunnel%s", VTY_NEWLINE);
		memset(t, 0, sizeof(gtp_iptnl_t));
		return CMD_WARNING;
	}

        __set_bit(GTP_FL_IPTNL_BIT, &ctx->flags);

	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip_dead_peer_detection,
      gtpu_ipip_dead_peer_detection_cmd,
      "gtpu-ipip dead-peer-detection <3-15> interface STRING payload-length <128-4096>",
      "GTP Userplane IPIP tunnel\n"
      "GTP-U IPIP tunnel Dead Peer Detection\n"
      "Dead Credit in seconds\n"
      "Interface running cBPF to catch DPD packet\n"
      "Name\n"
      "Payload attached to DPD GTP packet\n"
      "Number\n")
{
	gtp_switch_t *ctx = vty->index;
	gtp_iptnl_t *t = &ctx->iptnl;
	int credit, ifindex, plen, ret;

	if (!__test_bit(GTP_FL_GTP_FORWARD_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (t->flags & IPTNL_FL_DPD)
		return CMD_SUCCESS;

	if (argc < 2) {
		vty_out(vty, "%% You MUST provide Dead Credit and interface%s"
		           , VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Credit handling */
	t->credit = 3 * TIMER_HZ;
	VTY_GET_INTEGER_RANGE("Dead Credit", credit, argv[0], 3, 15);
	t->credit = credit * TIMER_HZ;
	t->expire = timer_long(time_now) + t->credit;

	/* Payload handling */
	if (argc == 3) {
		VTY_GET_INTEGER_RANGE("Payload Length", plen, argv[2], 128, 4096);
		t->payload_len = plen;
	}

	/* Interface handling */
	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		vty_out(vty, "%% Error with interface %s (%s)%s"
			   , argv[1]
			   , strerror(errno)
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}
	t->ifindex = ifindex;

	ret = gtp_dpd_init(&ctx->iptnl);
	if (ret < 0) {
		vty_out(vty, "%% Error starting Dead-Peer-Detection on interface %s (%s)%s"
			   , argv[1]
			   , strerror(errno)
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	t->flags |= IPTNL_FL_DPD;

	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip_transparent_ingress_encap,
      gtpu_ipip_transparent_ingress_encap_cmd,
      "gtpu-ipip transparent-ingress-encap",
      "GTP Userplane IPIP tunnel\n"
      "GTP-U Transparent ingress encapsulation mode\n")
{
        gtp_switch_t *ctx = vty->index;
	gtp_iptnl_t *t = &ctx->iptnl;
	int ret;

	if (!__test_bit(GTP_FL_GTP_FORWARD_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!t->selector_addr && !t->local_addr && !t->remote_addr) {
		vty_out(vty, "%% You MUST configure IPIP-Tunnel before%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	t->flags |= IPTNL_FL_TRANSPARENT_INGRESS_ENCAP;
	ret = gtp_xdp_fwd_iptnl_action(RULE_UPDATE, t);
	if (ret < 0) {
		vty_out(vty, "%% Unable to update XDP IPIP-Tunnel%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip_transparent_egress_encap,
      gtpu_ipip_transparent_egress_encap_cmd,
      "gtpu-ipip transparent-egress-encap",
      "GTP Userplane IPIP tunnel\n"
      "GTP-U Transparent egress encapsulation mode\n")
{
        gtp_switch_t *ctx = vty->index;
	gtp_iptnl_t *t = &ctx->iptnl;
	int ret;

	if (!__test_bit(GTP_FL_GTP_FORWARD_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!t->selector_addr && !t->local_addr && !t->remote_addr) {
		vty_out(vty, "%% You MUST configure IPIP-Tunnel before%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	t->flags |= IPTNL_FL_TRANSPARENT_EGRESS_ENCAP;
	ret = gtp_xdp_fwd_iptnl_action(RULE_UPDATE, t);
	if (ret < 0) {
		vty_out(vty, "%% Unable to update XDP IPIP-Tunnel%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip_decap_untag_vlan,
      gtpu_ipip_decap_untag_vlan_cmd,
      "gtpu-ipip decap-untag-vlan",
      "GTP Userplane IPIP tunnel\n"
      "GTP-U Untag VLAN header during decap\n")
{
        gtp_switch_t *ctx = vty->index;
	gtp_iptnl_t *t = &ctx->iptnl;
	int ret;

	if (!__test_bit(GTP_FL_GTP_FORWARD_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!t->selector_addr && !t->local_addr && !t->remote_addr) {
		vty_out(vty, "%% You MUST configure IPIP-Tunnel before%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	t->flags |= IPTNL_FL_UNTAG_VLAN;
	ret = gtp_xdp_fwd_iptnl_action(RULE_UPDATE, t);
	if (ret < 0) {
		vty_out(vty, "%% Unable to update XDP IPIP-Tunnel%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(gtpu_ipip_decap_tag_vlan,
      gtpu_ipip_decap_tag_vlan_cmd,
      "gtpu-ipip decap-tag-vlan <1-4095>",
      "GTP Userplane IPIP tunnel\n"
      "GTP-U Untag VLAN header during decap\n")
{
        gtp_switch_t *ctx = vty->index;
	gtp_iptnl_t *t = &ctx->iptnl;
	int ret, vlan;

	if (!__test_bit(GTP_FL_GTP_FORWARD_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-FORWARD program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc < 1) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

	if (!t->selector_addr && !t->local_addr && !t->remote_addr) {
		vty_out(vty, "%% You MUST configure IPIP-Tunnel before%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Vlan ID", vlan, argv[0], 1, 4095);
	if (vlan) {} ; /* dummy test */

	t->flags |= IPTNL_FL_TAG_VLAN;
	t->decap_vlan_id = vlan;
	ret = gtp_xdp_fwd_iptnl_action(RULE_UPDATE, t);
	if (ret < 0) {
		vty_out(vty, "%% Unable to update XDP IPIP-Tunnel%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}




/* Configuration writer */
static int
gtp_config_write(vty_t *vty)
{
        list_head_t *l = &daemon_data->gtp_switch_ctx;
        gtp_server_t *srv;
        gtp_switch_t *ctx;

        list_for_each_entry(ctx, l, next) {
        	vty_out(vty, "gtp-switch %s%s", ctx->name, VTY_NEWLINE);
		srv = &ctx->gtpc;
		if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
			vty_out(vty, " gtpc-tunnel-endpoint %s port %d"
				   , inet_sockaddrtos(&srv->addr)
				   , ntohs(inet_sockaddrport(&srv->addr)));
			if (srv->thread_cnt != GTP_DEFAULT_THREAD_CNT)
				vty_out(vty, " listener-count %d"
					   , srv->thread_cnt);
			vty_out(vty, "%s" , VTY_NEWLINE);
		}
		srv = &ctx->gtpu;
		if (__test_bit(GTP_FL_UPF_BIT, &srv->flags)) {
			vty_out(vty, " gtpu-tunnel-endpoint %s port %d"
				   , inet_sockaddrtos(&srv->addr)
				   , ntohs(inet_sockaddrport(&srv->addr)));
			if (srv->thread_cnt != GTP_DEFAULT_THREAD_CNT)
				vty_out(vty, " listener-count %d"
					   , srv->thread_cnt);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		if (__test_bit(GTP_FL_FORCE_PGW_BIT, &ctx->flags))
			vty_out(vty, " pgw-force-selection %s%s"
	                           , inet_sockaddrtos(&ctx->pgw_addr)
        			   , VTY_NEWLINE);
		if (__test_bit(GTP_FL_IPTNL_BIT, &ctx->flags)) {
			vty_out(vty, " gtpu-ipip traffic-selector %u.%u.%u.%u local %u.%u.%u.%u remote %u.%u.%u.%u"
	                           , NIPQUAD(ctx->iptnl.selector_addr)
	                           , NIPQUAD(ctx->iptnl.local_addr)
	                           , NIPQUAD(ctx->iptnl.remote_addr));
	                if (ctx->iptnl.encap_vlan_id)
			        vty_out(vty, " vlan %u"
	                           , ctx->iptnl.encap_vlan_id);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		if (ctx->iptnl.flags & IPTNL_FL_TRANSPARENT_INGRESS_ENCAP)
			vty_out(vty, " gtpu-ipip transparent-ingress-encap%s", VTY_NEWLINE);
		if (ctx->iptnl.flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP)
			vty_out(vty, " gtpu-ipip transparent-egress-encap%s", VTY_NEWLINE);
		if (ctx->iptnl.flags & IPTNL_FL_UNTAG_VLAN)
			vty_out(vty, " gtpu-ipip decap-untag-vlan%s", VTY_NEWLINE);
		if (ctx->iptnl.flags & IPTNL_FL_TAG_VLAN)
			vty_out(vty, " gtpu-ipip decap-tag-vlan %d%s"
				   , ctx->iptnl.decap_vlan_id, VTY_NEWLINE);
		if (ctx->iptnl.flags & IPTNL_FL_DPD)
			vty_out(vty, " gtpu-ipip dead-peer-detection %ld%s"
				   , ctx->iptnl.credit / TIMER_HZ
				   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_switch_vty_init(void)
{

	/* Install PDN commands. */
	install_node(&gtp_switch_node);
	install_element(CONFIG_NODE, &gtp_switch_cmd);
	install_element(CONFIG_NODE, &no_gtp_switch_cmd);

	install_default(GTP_SWITCH_NODE);
	install_element(GTP_SWITCH_NODE, &gtpc_switch_tunnel_endpoint_cmd);
	install_element(GTP_SWITCH_NODE, &gtpu_switch_tunnel_endpoint_cmd);
	install_element(GTP_SWITCH_NODE, &gtpc_force_pgw_selection_cmd);
	install_element(GTP_SWITCH_NODE, &gtpu_ipip_cmd);
	install_element(GTP_SWITCH_NODE, &gtpu_ipip_dead_peer_detection_cmd);
	install_element(GTP_SWITCH_NODE, &gtpu_ipip_transparent_ingress_encap_cmd);
	install_element(GTP_SWITCH_NODE, &gtpu_ipip_transparent_egress_encap_cmd);
	install_element(GTP_SWITCH_NODE, &gtpu_ipip_decap_untag_vlan_cmd);
	install_element(GTP_SWITCH_NODE, &gtpu_ipip_decap_tag_vlan_cmd);

	/* Install show commands */
//	install_element(VIEW_NODE, &show_gtp_cmd);
//	install_element(ENABLE_NODE, &show_gtp_cmd);


	return 0;
}
