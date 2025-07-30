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

static int pdn_config_write(vty_t *vty);
cmd_node_t pdn_node = {
	.node = PDN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(pdn)# ",
	.config_write = pdn_config_write,
};


/*
 *	Command
 */
DEFUN(pdn,
      pdn_cmd,
      "pdn",
      "Configure Global PDN data\n")
{
	vty->node = PDN_NODE;
	return CMD_SUCCESS;
}

DEFUN(pdn_realm,
      pdn_realm_cmd,
      "realm STRING",
      "Set Global PDN Realm\n"
      "name\n")
{
	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strncpy(daemon_data->realm, argv[0], GTP_STR_MAX_LEN-1);

	return CMD_SUCCESS;
}

DEFUN(pdn_nameserver,
      pdn_nameserver_cmd,
      "nameserver (A.B.C.D|X:X:X:X)",
      "Set Global PDN nameserver\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	struct sockaddr_storage *addr = &daemon_data->nameserver;
	int ret;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_stosockaddr(argv[0], 53, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	gtp_resolv_init();

	return CMD_SUCCESS;
}

DEFUN(restart_counter_file,
      restart_counter_file_cmd,
      "restart-counter-file STRING",
      "GTP-C Local restart counter file\n"
      "path to restart counter file\n")
{
	int ret;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strncpy(daemon_data->restart_counter_filename, argv[0], GTP_STR_MAX_LEN-1);

	ret = gtp_disk_read_restart_counter();
	if (ret < 0) {
		daemon_data->restart_counter = 1;
	} else {
		daemon_data->restart_counter = ret + 1;
	}
	gtp_disk_write_restart_counter();

	vty_out(vty, "Success loading restart_counter:%d%s"
		   , daemon_data->restart_counter
		   , VTY_NEWLINE);
	__set_bit(GTP_FL_RESTART_COUNTER_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

static int
pdn_channel_prepare(int argc, const char **argv, vty_t *vty, inet_server_t *srv)
{
	struct sockaddr_storage *addr = &srv->addr;
	int port = 0, err = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* UNIX socket */
	if (*argv[0] == '/')
		goto end;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("TCP Port", port, argv[1], 1024, 65535);

  end:
	err = inet_stosockaddr(argv[0], port, addr);
	if (err) {
		vty_out(vty, "%% malformed address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(request_channel,
      request_channel_cmd,
      "request-channel (A.B.C.D|X:X:X:X) port <1024-65535>",
      "JSON Request channel\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "listening TCP Port\n"
      "Number\n")
{
	inet_server_t *srv = &daemon_data->request_channel;
	int err = pdn_channel_prepare(argc, argv, vty, srv);

	if (err != CMD_SUCCESS)
		return err;

	srv->thread_cnt = 1;
	gtp_request_init();
	return CMD_SUCCESS;
}

DEFUN(metrics_channel,
      metrics_channel_cmd,
      "metrics-channel (A.B.C.D|X:X:X:X) port <1024-65535>",
      "Prometheus metrics channel\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Filesystem path\n"
      "listening TCP Port\n"
      "Number\n")
{
	inet_server_t *srv = &daemon_data->metrics_channel;
	int err = pdn_channel_prepare(argc, argv, vty, srv);

	if (err != CMD_SUCCESS)
		return err;

	srv->thread_cnt = 1;
	gtp_metrics_init();
	return CMD_SUCCESS;
}


/*
 *	Show
 */
DEFUN(show_xdp_forwarding,
      show_xdp_forwarding_cmd,
      "show xdp forwarding",
      SHOW_STR
      "XDP GTP Fowarding Dataplane ruleset\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_fwd_vty, vty, BPF_PROG_MODE_GTP_FORWARD);
	return CMD_SUCCESS;
}

DEFUN(show_xdp_forwarding_iptnl,
      show_xdp_forwarding_iptnl_cmd,
      "show xdp forwarding iptunnel",
      SHOW_STR
      "GTP XDP Forwarding IPIP Tunnel ruleset\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_fwd_iptnl_vty, vty, BPF_PROG_MODE_GTP_FORWARD);
	return CMD_SUCCESS;
}

DEFUN(show_xdp_routing,
      show_xdp_routing_cmd,
      "show xdp routing",
      SHOW_STR
      "GTP XDP Routing Dataplane ruleset\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_rt_vty, vty, BPF_PROG_MODE_GTP_ROUTE);
	return CMD_SUCCESS;
}

DEFUN(show_xdp_routing_iptnl,
      show_xdp_routing_iptnl_cmd,
      "show xdp routing iptunnel",
      SHOW_STR
      "GTP XDP Routing IPIP Tunnel ruleset\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_rt_iptnl_vty, vty, BPF_PROG_MODE_GTP_ROUTE);
	return CMD_SUCCESS;
}

DEFUN(show_xdp_routing_lladdr,
      show_xdp_routing_lladdr_cmd,
      "show xdp routing lladdr",
      SHOW_STR
      "GTP XDP Routing link-layer Address\n")
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_rt_lladdr_vty, vty, BPF_PROG_MODE_GTP_ROUTE);
	return CMD_SUCCESS;
}

/*
 *	Command
 */
DEFUN(gtp_send_echo_request_standard,
      gtp_send_echo_request_standard_cmd,
      "gtp send echo-request standard version (1|2) remote-peer (A.B.C.D|X:X:X:X) remote-port <1024-65535> [count <1-20>]",
      "Tool to send GTP-C or GTP-U Echo-Request Protocol messages\n"
      "Send Action\n"
      "Echo Request message\n"
      "Basic mode\n"
      "GTP Protocol Version\n"
      "Version 1\n"
      "Version 2\n"
      "Remote GTP Peer\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Remote GTP Peer Port\n"
      "Port between 1024 and 65535\n"
      "Number of message to send\n"
      "Number between 1 and 20\n")
{
	gtp_cmd_args_t *gtp_cmd_args;
	int version, port, err = 0, count = 3;

	if (argc < 3) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	PMALLOC(gtp_cmd_args);

	VTY_GET_INTEGER_RANGE("Protocol Version", version, argv[0], 1, 2);
	if (version) {} ; /* Dummy test */

	VTY_GET_INTEGER_RANGE("remote-port", port, argv[2], 1024, 65535);

	err = inet_stosockaddr(argv[1], port, &gtp_cmd_args->dst_addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[1], VTY_NEWLINE);
		FREE(gtp_cmd_args);
		return CMD_WARNING;
	}

	if (argc > 4) {
		VTY_GET_INTEGER_RANGE("count", count, argv[4], 1, 20);
		if (count) {} ; /* Dummy test */
	}

	gtp_cmd_args->type = GTP_CMD_ECHO_REQUEST;
	gtp_cmd_args->version = version;
	gtp_cmd_args->count = count;
	gtp_cmd_args->sqn = 0x2bad;
	gtp_cmd_args->vty = vty;
	gtp_cmd_echo_request(gtp_cmd_args);
	return CMD_SUCCESS;
}

DEFUN(gtp_send_echo_request_extended,
      gtp_send_echo_request_extended_cmd,
      "gtp send echo-request extended interface STRING version (1|2) ip-src (A.B.C.D|X:X:X:X) port-src <1024-65535> ip-dst (A.B.C.D|X:X:X:X) port-dst <1024-65535> [count <1-20>]",
      "Tool to send GTP-C or GTP-U Echo-Request Protocol messages\n"
      "Send Action\n"
      "Echo Request message\n"
      "Expert mode\n"
      "System Interface\n"
      "interface name\n"
      "GTP Protocol Version\n"
      "Version 1\n"
      "Version 2\n"
      "Local GTP IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Local GTP UDP Port\n"
      "Port between 1024 and 65535\n"
      "Remote GTP IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Remote GTP UDP Port\n"
      "Port between 1024 and 65535\n"
      "Number of message to send\n"
      "Number between 1 and 20\n")
{
	gtp_cmd_args_t *gtp_cmd_args;
	int version, port, err = 0, count = 3, ifindex;

	if (argc < 6) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ifindex = if_nametoindex(argv[0]);
	if (!ifindex) {
		vty_out(vty, "%% interface %s not found on local system%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	PMALLOC(gtp_cmd_args);

	VTY_GET_INTEGER_RANGE("Protocol Version", version, argv[1], 1, 2);
	if (version) {} ; /* Dummy test */

	VTY_GET_INTEGER_RANGE("port-src", port, argv[3], 1024, 65535);

	err = inet_stosockaddr(argv[2], port, &gtp_cmd_args->src_addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[2], VTY_NEWLINE);
		FREE(gtp_cmd_args);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("port-dst", port, argv[5], 1024, 65535);

	err = inet_stosockaddr(argv[4], port, &gtp_cmd_args->dst_addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[4], VTY_NEWLINE);
		FREE(gtp_cmd_args);
		return CMD_WARNING;
	}

	if (argc > 6) {
		VTY_GET_INTEGER_RANGE("count", count, argv[7], 1, 20);
		if (count) {} ; /* Dummy test */
	}

	gtp_cmd_args->type = GTP_CMD_ECHO_REQUEST_EXTENDED;
	gtp_cmd_args->version = version;
	gtp_cmd_args->ifindex = ifindex;
	gtp_cmd_args->count = count;
	gtp_cmd_args->sqn = 0x2bad;
	gtp_cmd_args->vty = vty;
	gtp_cmd_echo_request(gtp_cmd_args);
	return CMD_SUCCESS;
}

static int
vty_request_worker(inet_worker_t *w, void *arg)
{
	vty_t *vty = (vty_t *) arg;
	char flags2str[BUFSIZ];
	char fdpath[PATH_MAX];

	vty_out(vty, "  Worker:#%.2d task:0x%lx fd:%d(%s)%s"
		       "    flags:%s%s"
		     , w->id
		     , w->task
		     , w->fd, (w->fd < 0) ? "none" : inet_fd2str(w->fd, fdpath, PATH_MAX)
		     , VTY_NEWLINE
		     , gtp_flags2str(flags2str, sizeof(flags2str), w->flags)
		     , VTY_NEWLINE);
	return 0;
}

DEFUN(show_workers_request_channel,
      show_workers_request_channel_cmd,
      "show workers request-channel",
      SHOW_STR
      "workers tasks\n"
      "pdn request-channel workers\n")
{
	inet_server_t *srv = &daemon_data->request_channel;
	char addr_str[INET6_ADDRSTRLEN];
	char flags2str[BUFSIZ];

	if (!srv) {
		vty_out(vty, "%% missing settings: pdn request-channel%s"
			     , VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "pdn request-channel:%s port:%d with %d threads%s"
		     "  flags:%s%s"
		     , inet_sockaddrtos2(&srv->addr, addr_str)
		     , ntohs(inet_sockaddrport(&srv->addr))
		     , srv->thread_cnt
		     , VTY_NEWLINE
		     , gtp_flags2str(flags2str, sizeof(flags2str), srv->flags)
		     , VTY_NEWLINE);
	inet_server_for_each_worker(srv, vty_request_worker, vty);

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
pdn_config_write(vty_t *vty)
{
	vty_out(vty, "pdn%s", VTY_NEWLINE);
	if (daemon_data->nameserver.ss_family)
		vty_out(vty, " nameserver %s%s", inet_sockaddrtos(&daemon_data->nameserver), VTY_NEWLINE);
	if (daemon_data->realm[0])
		vty_out(vty, " realm %s%s", daemon_data->realm, VTY_NEWLINE);
	if (__test_bit(GTP_FL_RESTART_COUNTER_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, " restart-counter-file %s%s"
			     , daemon_data->restart_counter_filename
			     , VTY_NEWLINE);
	}
	vty_out(vty, "!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_vty_init(void)
{
	/* Install PDN commands. */
	install_node(&pdn_node);
	install_element(CONFIG_NODE, &pdn_cmd);

	install_default(PDN_NODE);
	install_element(PDN_NODE, &pdn_nameserver_cmd);
	install_element(PDN_NODE, &pdn_realm_cmd);
	install_element(PDN_NODE, &restart_counter_file_cmd);
	install_element(PDN_NODE, &request_channel_cmd);
	install_element(PDN_NODE, &metrics_channel_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_xdp_forwarding_cmd);
	install_element(VIEW_NODE, &show_xdp_forwarding_iptnl_cmd);
	install_element(VIEW_NODE, &show_xdp_routing_cmd);
	install_element(VIEW_NODE, &show_xdp_routing_iptnl_cmd);
	install_element(VIEW_NODE, &show_xdp_routing_lladdr_cmd);
	install_element(VIEW_NODE, &show_workers_request_channel_cmd);
	install_element(VIEW_NODE, &gtp_send_echo_request_standard_cmd);
	install_element(VIEW_NODE, &gtp_send_echo_request_extended_cmd);
	install_element(ENABLE_NODE, &show_xdp_forwarding_cmd);
	install_element(ENABLE_NODE, &show_xdp_forwarding_iptnl_cmd);
	install_element(ENABLE_NODE, &show_xdp_routing_cmd);
	install_element(ENABLE_NODE, &show_xdp_routing_iptnl_cmd);
	install_element(ENABLE_NODE, &show_xdp_routing_lladdr_cmd);
	install_element(ENABLE_NODE, &show_workers_request_channel_cmd);
	install_element(ENABLE_NODE, &gtp_send_echo_request_standard_cmd);
	install_element(ENABLE_NODE, &gtp_send_echo_request_extended_cmd);

	/* Install other VTY */
	gtp_bpf_prog_vty_init();
	gtp_interface_vty_init();
	gtp_mirror_vty_init();
	pppoe_vty_init();
	cgn_vty_init();
	gtp_vrf_vty_init();
	gtp_cdr_vty_init();
	gtp_apn_vty_init();
	gtp_proxy_vty_init();
	gtp_router_vty_init();
	gtp_session_vty_init();
	return 0;
}
