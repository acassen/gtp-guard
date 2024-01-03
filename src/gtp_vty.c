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

cmd_node_t pdn_node = {
        PDN_NODE,
        "%s(pdn)# ",
        1,
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

	ret = inet_stosockaddr(argv[0], "53", addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	gtp_resolv_init();

        return CMD_SUCCESS;
}

DEFUN(pdn_xdp_gtp_route,
      pdn_xdp_gtp_route_cmd,
      "xdp-gtp-route STRING interface STRING [xdp-prog STRING]",
      "GTP Routing channel XDP program\n"
      "path to BPF file\n"
      "Interface name\n"
      "Name"
      "XDP Program Name"
      "Name")
{
	gtp_bpf_opts_t *opts = &daemon_data->xdp_gtp_route;
        int ret, ifindex;

        if (argc < 2) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

	strncpy(opts->filename, argv[0], GTP_STR_MAX_LEN-1);
	ifindex = if_nametoindex(argv[1]);
	if (argc == 3)
		strncpy(opts->progname, argv[2], GTP_STR_MAX_LEN-1);
	if (!ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}
	opts->ifindex = ifindex;
	opts->vty = vty;

        ret = gtp_xdp_rt_load(opts);
        if (ret < 0) {
                vty_out(vty, "%% Error loading eBPF program:%s on ifindex:%d%s"
                           , opts->filename
                           , opts->ifindex
                           , VTY_NEWLINE);
                /* Reset data */
		memset(opts, 0, sizeof(gtp_bpf_opts_t));
                return CMD_WARNING;
        }

        vty_out(vty, "Success loading eBPF program:%s on ifindex:%d%s"
                   , opts->filename
		   , opts->ifindex
                   , VTY_NEWLINE);
	__set_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags);
        return CMD_SUCCESS;
}

DEFUN(no_pdn_xdp_gtp_route,
      no_pdn_xdp_gtp_route_cmd,
      "no xdp-gtp-route",
      "GTP Routing channel XDP program\n")
{
	gtp_bpf_opts_t *opts = &daemon_data->xdp_gtp_route;

        if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags)) {
                vty_out(vty, "%% No GTP-ROUTE XDP program is currently configured. Ignoring%s"
                           , VTY_NEWLINE);
                return CMD_WARNING;
        }

        gtp_xdp_rt_unload(opts);

        /* Reset data */
	memset(opts, 0, sizeof(gtp_bpf_opts_t));

        vty_out(vty, "Success unloading eBPF program:%s%s"
                   , opts->filename
                   , VTY_NEWLINE);
	__clear_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(pdn_xdp_gtpu,
      pdn_xdp_gtpu_cmd,
      "xdp-gtpu STRING interface STRING [xdp-prog STRING]",
      "GTP Userplane channel XDP program\n"
      "path to BPF file\n"
      "Interface name\n"
      "Name"
      "XDP Program Name"
      "Name")
{
	gtp_bpf_opts_t *opts = &daemon_data->xdp_gtpu;
        int ret, ifindex;

        if (argc < 2) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

	strncpy(opts->filename, argv[0], GTP_STR_MAX_LEN-1);
	ifindex = if_nametoindex(argv[1]);
	if (argc == 3)
		strncpy(opts->progname, argv[2], GTP_STR_MAX_LEN-1);
	if (!ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}
	opts->ifindex = ifindex;
	opts->vty = vty;

        ret = gtp_xdp_fwd_load(opts);
        if (ret < 0) {
                vty_out(vty, "%% Error loading eBPF program:%s on ifindex:%d%s"
                           , opts->filename
                           , opts->ifindex
                           , VTY_NEWLINE);
                /* Reset data */
		memset(opts, 0, sizeof(gtp_bpf_opts_t));
                return CMD_WARNING;
        }

        vty_out(vty, "Success loading eBPF program:%s on ifindex:%d%s"
                   , opts->filename
		   , opts->ifindex
                   , VTY_NEWLINE);
	__set_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags);
        return CMD_SUCCESS;
}

DEFUN(no_pdn_xdp_gtpu,
      no_pdn_xdp_gtpu_cmd,
      "no xdp-gtpu",
      "GTP Userplane channel XDP program\n")
{
	gtp_bpf_opts_t *opts = &daemon_data->xdp_gtpu;

        if (!__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags)) {
                vty_out(vty, "%% No GTP-U XDP program is currently configured. Ignoring%s"
                           , VTY_NEWLINE);
                return CMD_WARNING;
        }

        gtp_xdp_fwd_unload(opts);

        /* Reset data */
	memset(opts, 0, sizeof(gtp_bpf_opts_t));

        vty_out(vty, "Success unloading eBPF program:%s%s"
                   , opts->filename
                   , VTY_NEWLINE);
	__clear_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(pdn_xdp_mirror,
      pdn_xdp_mirror_cmd,
      "xdp-mirror STRING interface STRING [xdp-prog STRING]",
      "GTP mirroring XDP program\n"
      "path to BPF file\n"
      "Interface name\n"
      "Name"
      "XDP Program Name"
      "Name")
{
	gtp_bpf_opts_t *opts = &daemon_data->xdp_mirror;
	int ret, ifindex;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strncpy(opts->filename, argv[0], GTP_STR_MAX_LEN-1);
	ifindex = if_nametoindex(argv[1]);
	if (argc == 3)
		strncpy(opts->progname, argv[2], GTP_STR_MAX_LEN-1);
	if (!ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}
	opts->ifindex = ifindex;
	opts->vty = vty;

	ret = gtp_xdp_mirror_load(opts);
	if (ret < 0) {
		vty_out(vty, "%% Error loading eBPF program:%s on ifindex:%d%s"
			   , opts->filename
			   , opts->ifindex
			   , VTY_NEWLINE);
		/* Reset data */
		memset(opts, 0, sizeof(gtp_bpf_opts_t));
		return CMD_WARNING;
	}

	vty_out(vty, "Success loading eBPF program:%s on ifindex:%d Qdisc%s"
		   , opts->filename
		   , opts->ifindex
		   , VTY_NEWLINE);
	__set_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(no_pdn_xdp_mirror,
      no_pdn_xdp_mirror_cmd,
      "no xdp-mirror",
      "GTP mirroring XDP program\n")
{
	gtp_bpf_opts_t *opts = &daemon_data->xdp_mirror;

	if (!__test_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% No Mirroring XDP program is currently configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

        gtp_xdp_mirror_unload(opts);

        /* Reset data */
	memset(opts, 0, sizeof(gtp_bpf_opts_t));

        vty_out(vty, "Success unloading eBPF program:%s%s"
                   , opts->filename
                   , VTY_NEWLINE);
	__clear_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags);
        return CMD_SUCCESS;
}

static int
pdn_mirror_prepare(int argc, const char **argv, vty_t *vty,
		   struct sockaddr_storage *addr, uint8_t *protocol, int *ifindex)
{
	int ret, port;

	if (!__test_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% No Mirroring XDP program is currently configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc < 4) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

        VTY_GET_INTEGER_RANGE("Port", port, argv[1], 1024, 65535);
	if (port) ; /* Dummy test */
        ret = inet_stosockaddr(argv[0], argv[1], addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* FIXME: complete support to IPv6 mirroring */
	if (addr->ss_family != AF_INET) {
		vty_out(vty, "%% shame on me, only IPv4 is currently supported%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strstr(argv[2], "UDP"))
		*protocol = IPPROTO_UDP;
	else if (strstr(argv[2], "TCP"))
		*protocol = IPPROTO_TCP;
	else {
		vty_out(vty, "%% Protocol %s not supported%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	*ifindex = if_nametoindex(argv[3]);
	if (!*ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[3]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


DEFUN(pdn_mirror,
      pdn_mirror_cmd,
      "mirror (A.B.C.D|X:X:X:X) port <1024-65535> protocol STRING interface STRING",
      "Mirroring rule\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "UDP Port\n"
      "Number\n"
      "IP Protocol\n"
      "UDP or TCP\n"
      "Interface to redirect mirrored traffic to\n"
      "Name\n")
{
	gtp_mirror_rule_t *r;
	struct sockaddr_storage addr;
	uint8_t protocol;
	int ifindex, ret;

	ret = pdn_mirror_prepare(argc, argv, vty, &addr, &protocol, &ifindex);
	if (ret != CMD_SUCCESS)
		return ret;

	r = gtp_mirror_rule_get(&addr, protocol, ifindex);
	if (r) {
		vty_out(vty, "%% Same mirroring rule already set%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	r = gtp_mirror_rule_add(&addr, protocol, ifindex);

	ret = gtp_xdp_mirror_action(RULE_ADD, r);
	if (ret < 0) {
		vty_out(vty, "%% Error while setting XDP mirroring rule%s"
			   , VTY_NEWLINE);
		gtp_mirror_rule_del(r);
		FREE(r);
		return CMD_WARNING;
	}

	r->active = true;

	return CMD_SUCCESS;
}

DEFUN(no_pdn_mirror,
      no_pdn_mirror_cmd,
      "no mirror (A.B.C.D|X:X:X:X) port <1024-65535> protocol STRING interface STRING",
      "Mirroring rule\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "UDP Port\n"
      "Number\n"
      "IP Protocol\n"
      "UDP or TCP\n"
      "Interface to redirect mirrored traffic to\n"
      "Name\n")
{
	gtp_mirror_rule_t *r;
	struct sockaddr_storage addr;
	uint8_t protocol;
	int ifindex, ret;

	ret = pdn_mirror_prepare(argc, argv, vty, &addr, &protocol, &ifindex);
	if (ret != CMD_SUCCESS)
		return ret;

	r = gtp_mirror_rule_get(&addr, protocol, ifindex);
	if (!r) {
		vty_out(vty, "%% No matching rule to remove%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = gtp_xdp_mirror_action(RULE_DEL, r);
	if (ret < 0) {
		vty_out(vty, "%% Error while removing XDP mirroring rule%s"
			   , VTY_NEWLINE);
	}

	gtp_mirror_rule_del(r);
	FREE(r);
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

DEFUN(request_channel,
      request_channel_cmd,
      "request-channel (A.B.C.D|X:X:X:X) port <1024-65535>",
      "GTP-Proxy request channel\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "listening TCP Port\n"
      "Number\n")
{
	gtp_req_channel_t *srv = &daemon_data->request_channel;
	struct sockaddr_storage *addr = &srv->addr;
	int port = 0, ret = 0;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

        VTY_GET_INTEGER_RANGE("TCP Port", port, argv[1], 1024, 65535);
	if (port) ; /* Dummy test */
        ret = inet_stosockaddr(argv[0], argv[1], addr);

	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}


        srv->thread_cnt = GTP_REQUEST_THREAD_CNT_DEFAULT;
        gtp_request_init();
        gtp_request_worker_start();
        return CMD_SUCCESS;
}

/*
 *	Show
 */
DEFUN(show_gtp_fwd,
      show_gtp_fwd_cmd,
      "show gtp fwd",
      SHOW_STR
      "XDP GTP Fowarding Dataplane ruleset\n")
{
	int ret;

	if (!__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP GTP-U is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = gtp_xdp_fwd_vty(vty);
	if (ret < 0) {
		vty_out(vty, "%% Error displaying XDP ruleset%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(show_xdp_fwd_iptnl,
      show_xdp_fwd_iptnl_cmd,
      "show xdp fwd iptunnel",
      SHOW_STR
      "GTP XDP Forwarding IPIP Tunnel ruleset\n")
{
	int ret;

	if (!__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP GTP-U is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = gtp_xdp_fwd_iptnl_vty(vty);
	if (ret < 0) {
		vty_out(vty, "%% Error displaying XDP ruleset%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(show_gtp_rt,
      show_gtp_rt_cmd,
      "show gtp rt",
      SHOW_STR
      "GTP XDP Routing Dataplane ruleset\n")
{
	int ret;

	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP GTP-Route is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = gtp_xdp_rt_vty(vty);
	if (ret < 0) {
		vty_out(vty, "%% Error displaying XDP ruleset%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(show_xdp_rt_iptnl,
      show_xdp_rt_iptnl_cmd,
      "show xdp rt iptunnel",
      SHOW_STR
      "GTP XDP Routing IPIP Tunnel ruleset\n")
{
	int ret;

	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP GTP-Route is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = gtp_xdp_rt_iptnl_vty(vty);
	if (ret < 0) {
		vty_out(vty, "%% Error displaying XDP ruleset%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(show_xdp_mirror,
      show_xdp_mirror_cmd,
      "show xdp mirror",
      SHOW_STR
      "GTP XDP Mirroring ruleset\n")
{
	int ret;

	if (!__test_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP Mirror is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = gtp_xdp_mirror_vty(vty);
	if (ret < 0) {
		vty_out(vty, "%% Error displaying XDP ruleset%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

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
	int version, port, ret = 0, count = 3;

	if (argc < 3) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	PMALLOC(gtp_cmd_args);

	VTY_GET_INTEGER_RANGE("Protocol Version", version, argv[0], 1, 2);
	if (version) ; /* Dummy test */

	VTY_GET_INTEGER_RANGE("remote-port", port, argv[2], 1024, 65535);
	if (port) ; /* Dummy test */
	ret = inet_stosockaddr(argv[1], argv[2], &gtp_cmd_args->dst_addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[1], VTY_NEWLINE);
		FREE(gtp_cmd_args);
		return CMD_WARNING;
	}

	if (argc > 4) {
		VTY_GET_INTEGER_RANGE("count", count, argv[4], 1, 20);
		if (count) ; /* Dummy test */
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
      "gtp send echo-request extended version (1|2) ip-src (A.B.C.D|X:X:X:X) port-src <1024-65535> ip-dst (A.B.C.D|X:X:X:X) port-dst <1024-65535> [count <1-20>]",
      "Tool to send GTP-C or GTP-U Echo-Request Protocol messages\n"
      "Send Action\n"
      "Echo Request message\n"
      "Expert mode\n"
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
	int version, port, ret = 0, count = 3, ifindex;

	if (argc < 5) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	PMALLOC(gtp_cmd_args);

	VTY_GET_INTEGER_RANGE("Protocol Version", version, argv[0], 1, 2);
	if (version) ; /* Dummy test */

	VTY_GET_INTEGER_RANGE("port-src", port, argv[2], 1024, 65535);
	if (port) ; /* Dummy test */
	ret = inet_stosockaddr(argv[1], argv[2], &gtp_cmd_args->src_addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[1], VTY_NEWLINE);
		FREE(gtp_cmd_args);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("port-dst", port, argv[4], 1024, 65535);
	if (port) ; /* Dummy test */
	ret = inet_stosockaddr(argv[3], argv[4], &gtp_cmd_args->dst_addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[1], VTY_NEWLINE);
		FREE(gtp_cmd_args);
		return CMD_WARNING;
	}

	if (argc > 5) {
		VTY_GET_INTEGER_RANGE("count", count, argv[4], 1, 20);
		if (count) ; /* Dummy test */
	}

	ifindex = inet_sockaddrifindex(&gtp_cmd_args->src_addr);
	if (ifindex < 0) {
		vty_out(vty, "%% IP address %s not found on local system%s"
			   , argv[1], VTY_NEWLINE);
		FREE(gtp_cmd_args);
		return CMD_WARNING;
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


/* Configuration writer */
static int
pdn_config_write(vty_t *vty)
{
	gtp_bpf_opts_t *opts;
	char ifname[IF_NAMESIZE];

	vty_out(vty, "pdn%s", VTY_NEWLINE);
	if (daemon_data->nameserver.ss_family)
		vty_out(vty, " nameserver %s%s", inet_sockaddrtos(&daemon_data->nameserver), VTY_NEWLINE);
	if (daemon_data->realm[0])
		vty_out(vty, " realm %s%s", daemon_data->realm, VTY_NEWLINE);
	
	opts = &daemon_data->xdp_gtp_route;
	if (__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags)) {
		if (opts->progname[0])
			vty_out(vty, " xdp-gtp-route %s interface %s progname %s%s"
				   , opts->filename
				   , if_indextoname(opts->ifindex, ifname)
				   , opts->progname
				   , VTY_NEWLINE);
		else
			vty_out(vty, " xdp-gtp-route %s interface %s%s"
				   , opts->filename
				   , if_indextoname(opts->ifindex, ifname)
				   , VTY_NEWLINE);
        }
	opts = &daemon_data->xdp_gtpu;
	if (__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags)) {
		if (opts->progname[0])
			vty_out(vty, " xdp-gtpu %s interface %s progname %s%s"
				   , opts->filename
				   , if_indextoname(opts->ifindex, ifname)
				   , opts->progname
				   , VTY_NEWLINE);
		else
			vty_out(vty, " xdp-gtpu %s interface %s%s"
				   , opts->filename
				   , if_indextoname(opts->ifindex, ifname)
				   , VTY_NEWLINE);
        }
	opts = &daemon_data->xdp_mirror;
	if (__test_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, " xdp-mirror %s interface %s%s"
			   , opts->filename
			   , if_indextoname(opts->ifindex, ifname)
			   , VTY_NEWLINE);
		gtp_mirror_vty(vty);
	}
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
	install_node(&pdn_node, pdn_config_write);
	install_element(CONFIG_NODE, &pdn_cmd);

	install_default(PDN_NODE);
	install_element(PDN_NODE, &pdn_nameserver_cmd);
	install_element(PDN_NODE, &pdn_realm_cmd);
	install_element(PDN_NODE, &pdn_xdp_gtp_route_cmd);
	install_element(PDN_NODE, &no_pdn_xdp_gtp_route_cmd);
	install_element(PDN_NODE, &pdn_xdp_gtpu_cmd);
	install_element(PDN_NODE, &no_pdn_xdp_gtpu_cmd);
	install_element(PDN_NODE, &pdn_xdp_mirror_cmd);
	install_element(PDN_NODE, &no_pdn_xdp_mirror_cmd);
	install_element(PDN_NODE, &pdn_mirror_cmd);
	install_element(PDN_NODE, &no_pdn_mirror_cmd);
	install_element(PDN_NODE, &restart_counter_file_cmd);
	install_element(PDN_NODE, &request_channel_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_gtp_fwd_cmd);
	install_element(VIEW_NODE, &show_xdp_fwd_iptnl_cmd);
	install_element(VIEW_NODE, &show_gtp_rt_cmd);
	install_element(VIEW_NODE, &show_xdp_rt_iptnl_cmd);
	install_element(VIEW_NODE, &show_xdp_mirror_cmd);
	install_element(VIEW_NODE, &gtp_send_echo_request_standard_cmd);
	install_element(VIEW_NODE, &gtp_send_echo_request_extended_cmd);
	install_element(ENABLE_NODE, &show_gtp_fwd_cmd);
	install_element(ENABLE_NODE, &show_xdp_fwd_iptnl_cmd);
	install_element(ENABLE_NODE, &show_gtp_rt_cmd);
	install_element(ENABLE_NODE, &show_xdp_rt_iptnl_cmd);
	install_element(ENABLE_NODE, &show_xdp_mirror_cmd);
	install_element(ENABLE_NODE, &gtp_send_echo_request_standard_cmd);
	install_element(ENABLE_NODE, &gtp_send_echo_request_extended_cmd);

	/* Install other VTY */
        gtp_vrf_vty_init();
        gtp_apn_vty_init();
        gtp_switch_vty_init();
        gtp_router_vty_init();
        gtp_sessions_vty_init();

	return 0;
}
