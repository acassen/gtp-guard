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
#include <linux/if_link.h>
#include <ctype.h>
#include <netdb.h>
#include <resolv.h>
#include <fnmatch.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int interface_config_write(vty_t *vty);
cmd_node_t interface_node = {
	.node = INTERFACE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(interface)# ",
	.config_write = interface_config_write,
};


/*
 *	VTY helpers
 */
static int
gtp_interface_metrics_show(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	vty_t *vty = arg;

	vty_out(vty, "   %s: packets:%lld bytes:%lld%s"
		   , (direction) ? "TX" : "RX"
		   , m->packets, m->bytes
		   , VTY_NEWLINE);
	vty_out(vty, "       dropped_packets:%lld dropped_bytes:%lld%s"
		   , m->dropped_packets, m->dropped_bytes
		   , VTY_NEWLINE);
	return 0;
}

static int
gtp_interface_show(gtp_interface_t *iface, void *arg)
{
	gtp_bpf_prog_t *p = daemon_data->xdp_gtp_route;
	vty_t *vty = arg;
	char addr_str[INET6_ADDRSTRLEN];

	vty_out(vty, "interface %s%s"
		   , iface->ifname
		   , VTY_NEWLINE);
	vty_out(vty, " ll_addr:" ETHER_FMT "%s"
		   , ETHER_BYTES(iface->hw_addr)
		   , VTY_NEWLINE);
	vty_out(vty, " direct-tx-gw:%s ll_addr:" ETHER_FMT "%s"
		   , inet_ipaddresstos(&iface->direct_tx_gw, addr_str)
		   , ETHER_BYTES(iface->direct_tx_hw_addr)
		   , VTY_NEWLINE);
	gtp_bpf_rt_stats_vty(p, iface->ifindex, IF_METRICS_GTP
			      , gtp_interface_metrics_show
			      , vty);
	gtp_bpf_rt_stats_vty(p, iface->ifindex, IF_METRICS_PPPOE
			      , gtp_interface_metrics_show
			      , vty);
	gtp_bpf_rt_stats_vty(p, iface->ifindex, IF_METRICS_IPIP
			      , gtp_interface_metrics_show
			      , vty);
	vty_out(vty, "%s", VTY_NEWLINE);
	return 0;
}


/*
 *	VTY command
 */
DEFUN(interface,
      interface_cmd,
      "interface STRING",
      "Configure Interface\n"
      "Local system interface name\n")
{
	gtp_interface_t *new;
	int ifindex;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_interface_get(argv[0]);
	if (new) {
		vty->node = APN_NODE;
		vty->index = new;
		gtp_interface_put(new);
		return CMD_SUCCESS;
	}

	ifindex = if_nametoindex(argv[0]);
	if (!ifindex) {
		vty_out(vty, "%% interface %s not found on local system%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_interface_alloc(argv[0], ifindex);
	vty->node = INTERFACE_NODE;
	vty->index = new;
	__set_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &new->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface,
      no_interface_cmd,
      "no interface STRING",
      "Configure interface\n"
      "Local system interface name\n")
{
	gtp_interface_t *iface;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	iface = gtp_interface_get(argv[0]);
	if (!iface) {
		vty_out(vty, "%% unknown interface:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_interface_put(iface);
	gtp_interface_destroy(iface);
	return CMD_SUCCESS;
}

DEFUN(interface_bpf_prog,
      interface_bpf_prog_cmd,
      "bpf-program STRING",
      "Attach a BPF program to the interface\n"
      "BPF program name\n")
{
	gtp_interface_t *iface = vty->index;
	gtp_bpf_prog_t *p;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	iface->bpf_prog = p;
	return CMD_SUCCESS;
}

DEFUN(interface_direct_tx_gw,
      interface_direct_tx_gw_cmd,
      "direct-tx-gw (A.B.C.D|X:X:X:X)",
      "Direct TX mode Gateway IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	gtp_interface_t *iface = vty->index;
	ip_address_t *ip_addr =&iface->direct_tx_gw;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = inet_stoipaddress(argv[0], ip_addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(ip_addr, 0, sizeof(ip_address_t));
		return CMD_WARNING;
	}

	__set_bit(GTP_INTERFACE_FL_DIRECT_TX_GW_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_desciption,
      interface_description_cmd,
      "description STRING",
      "Set Interface description\n"
      "description\n")
{
	gtp_interface_t *iface = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(iface->description, argv[0], GTP_PATH_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(interface_metrics_gtp,
      interface_metrics_gtp_cmd,
      "metrics gtp",
      "Enable GTP metrics\n")
{
	gtp_interface_t *iface = vty->index;

	__set_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface_metrics_gtp,
      no_interface_metrics_gtp_cmd,
      "no metrics gtp",
      "Disable GTP metrics\n")
{
	gtp_interface_t *iface = vty->index;

	__clear_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_metrics_pppoe,
      interface_metrics_pppoe_cmd,
      "metrics pppoe",
      "Enable PPPoE metrics\n")
{
	gtp_interface_t *iface = vty->index;

	__set_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface_metrics_pppoe,
      no_interface_metrics_pppoe_cmd,
      "no metrics pppoe",
      "Disable PPPoE metrics\n")
{
	gtp_interface_t *iface = vty->index;

	__clear_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_metrics_ipip,
      interface_metrics_ipip_cmd,
      "metrics ipip",
      "Enable IPIP metrics\n")
{
	gtp_interface_t *iface = vty->index;

	__set_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface_metrics_ipip,
      no_interface_metrics_ipip_cmd,
      "no metrics ipip",
      "Disable IPIP metrics\n")
{
	gtp_interface_t *iface = vty->index;

	__clear_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_metrics_link,
      interface_metrics_link_cmd,
      "metrics link",
      "Enable link metrics\n")
{
	gtp_interface_t *iface = vty->index;

	if (__test_bit(GTP_INTERFACE_FL_METRICS_LINK_BIT, &iface->flags))
		return CMD_SUCCESS;

	iface->link_metrics = MALLOC(sizeof(struct rtnl_link_stats64));
	__set_bit(GTP_INTERFACE_FL_METRICS_LINK_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface_metrics_link,
      no_interface_metrics_link_cmd,
      "no metrics link",
      "Disable link metrics\n")
{
	gtp_interface_t *iface = vty->index;

	FREE_PTR(iface->link_metrics);
	iface->link_metrics = NULL;
	__clear_bit(GTP_INTERFACE_FL_METRICS_LINK_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_shutdown,
      interface_shutdown_cmd,
      "shutdown",
      "Shutdown interface\n")
{
	gtp_interface_t *iface = vty->index;

	if (__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags)) {
		vty_out(vty, "%% interface:'%s' is already shutdown%s"
			   , iface->ifname
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_interface_unload_bpf(iface);
	__set_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_no_shutdown,
      interface_no_shutdown_cmd,
      "no shutdown",
      "Activate interface\n")
{
	gtp_interface_t *iface = vty->index;
	struct bpf_link *lnk;
	int err = 0;

	if (!__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags)) {
		vty_out(vty, "%% interface:'%s' is already running%s"
			   , iface->ifname
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!iface->bpf_prog) {
		vty_out(vty, "%% no bpf-program configured for interface:'%s'%s"
			   , iface->ifname, VTY_NEWLINE);
		goto end;
	}
	
	lnk = gtp_bpf_prog_attach(iface->bpf_prog, iface->ifindex);
	if (!lnk) {
		vty_out(vty, "%% error attaching bpf-program:'%s' to interface:'%s'%s"
			   , iface->bpf_prog->name, iface->ifname, VTY_NEWLINE);
		return CMD_WARNING;
	}

	iface->bpf_lnk = lnk;
	vty_out(vty, "Success attaching bpf-program:'%s' to interface:'%s'%s"
		   , iface->bpf_prog->name, iface->ifname, VTY_NEWLINE);
	log_message(LOG_INFO, "Success attaching bpf-program:'%s' to interface:'%s'"
			    , iface->bpf_prog->name, iface->ifname);

	/* Metrics init */
	if (__test_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(iface->bpf_prog,
							iface->ifindex, IF_METRICS_GTP);
	if (__test_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(iface->bpf_prog,
							iface->ifindex, IF_METRICS_PPPOE);
	if (__test_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(iface->bpf_prog,
							iface->ifindex, IF_METRICS_IPIP);
	if (err) {
		vty_out(vty, "%% !!!Warning!!! error initializing metrics for interface:'%s'%s"
			   , iface->ifname
			   , VTY_NEWLINE);
	}

  end:
	__clear_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	return CMD_SUCCESS;
}



/* Show */
DEFUN(show_interface,
      show_interface_cmd,
      "show interface [STRING]",
      SHOW_STR
      "Interface\n")
{
	gtp_interface_t *iface = NULL;

	if (argc >= 1) {
		iface = gtp_interface_get(argv[0]);
		if (!iface) {
			vty_out(vty, "%% Unknown interface:'%s'%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}

		gtp_interface_show(iface, vty);
		gtp_interface_put(iface);
		return CMD_SUCCESS;
	}

	gtp_interface_foreach(gtp_interface_show, vty);
	return CMD_SUCCESS;
}


/* Configuration writer */
static int
interface_config_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->interfaces;
	char addr_str[INET6_ADDRSTRLEN];
	gtp_interface_t *iface;

	list_for_each_entry(iface, l, next) {
		vty_out(vty, "interface %s%s", iface->ifname, VTY_NEWLINE);
		if (iface->description[0])
			vty_out(vty, " description %s%s", iface->description, VTY_NEWLINE);
		if (iface->bpf_prog)
			vty_out(vty, " bpf-program %s%s", iface->bpf_prog->name, VTY_NEWLINE);
		if (__test_bit(GTP_INTERFACE_FL_DIRECT_TX_GW_BIT, &iface->flags))
			vty_out(vty, " direct-tx-gw %s%s"
				   , inet_ipaddresstos(&iface->direct_tx_gw, addr_str)
				   , VTY_NEWLINE);
		if (__test_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags))
			vty_out(vty, " metrics gtp%s", VTY_NEWLINE);
		if (__test_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags))
			vty_out(vty, " metrics pppoe%s", VTY_NEWLINE);
		if (__test_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags))
			vty_out(vty, " metrics ipip%s", VTY_NEWLINE);
		if (__test_bit(GTP_INTERFACE_FL_METRICS_LINK_BIT, &iface->flags))
			vty_out(vty, " metrics link%s", VTY_NEWLINE);
  		vty_out(vty, " %sshutdown%s"
			   , __test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ? "" : "no "
			   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_interface_vty_init(void)
{
	/* Install Interface commands. */
	install_node(&interface_node);
	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);

	install_default(INTERFACE_NODE);
	install_element(INTERFACE_NODE, &interface_description_cmd);
	install_element(INTERFACE_NODE, &interface_bpf_prog_cmd);
	install_element(INTERFACE_NODE, &interface_direct_tx_gw_cmd);
	install_element(INTERFACE_NODE, &interface_metrics_gtp_cmd);
	install_element(INTERFACE_NODE, &no_interface_metrics_gtp_cmd);
	install_element(INTERFACE_NODE, &interface_metrics_pppoe_cmd);
	install_element(INTERFACE_NODE, &no_interface_metrics_pppoe_cmd);
	install_element(INTERFACE_NODE, &interface_metrics_ipip_cmd);
	install_element(INTERFACE_NODE, &no_interface_metrics_ipip_cmd);
	install_element(INTERFACE_NODE, &interface_metrics_link_cmd);
	install_element(INTERFACE_NODE, &no_interface_metrics_link_cmd);
	install_element(INTERFACE_NODE, &interface_shutdown_cmd);
	install_element(INTERFACE_NODE, &interface_no_shutdown_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_interface_cmd);
	install_element(ENABLE_NODE, &show_interface_cmd);

	return 0;
}
