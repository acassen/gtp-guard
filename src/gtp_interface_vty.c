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

#include <linux/types.h>
#include <linux/rtnetlink.h>

#include "gtp_data.h"
#include "gtp_bpf_rt.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "command.h"
#include "bitops.h"
#include "utils.h"
#include "memory.h"
#include "logger.h"

/* Extern data */
extern struct data *daemon_data;


/*
 *	VTY helpers
 */
static int
gtp_interface_metrics_show(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	struct vty *vty = arg;

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
gtp_interface_show(struct gtp_interface *iface, void *arg)
{
	struct gtp_bpf_prog *p = iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP].prog;
	struct vty *vty = arg;
	char addr_str[INET6_ADDRSTRLEN];

	vty_out(vty, "interface %s%s"
		   , iface->ifname
		   , VTY_NEWLINE);
	vty_out(vty, " ifindex: %d%s"
		   , iface->ifindex
		   , VTY_NEWLINE);
	vty_out(vty, " ll_addr:" ETHER_FMT "%s"
		   , ETHER_BYTES(iface->hw_addr)
		   , VTY_NEWLINE);
	if (iface->vlan_id)
		vty_out(vty, " vlan-id:%d%s"
			   , iface->vlan_id, VTY_NEWLINE);
	if (iface->direct_tx_gw.family)
		vty_out(vty, " direct-tx-gw:%s ll_addr:" ETHER_FMT "%s"
			   , inet_ipaddresstos(&iface->direct_tx_gw, addr_str)
			   , ETHER_BYTES(iface->direct_tx_hw_addr)
			   , VTY_NEWLINE);
	if (!p)
		goto end;

	gtp_bpf_rt_stats_vty(p, iface->ifindex, IF_METRICS_GTP
			      , gtp_interface_metrics_show
			      , vty);
	gtp_bpf_rt_stats_vty(p, iface->ifindex, IF_METRICS_PPPOE
			      , gtp_interface_metrics_show
			      , vty);
	gtp_bpf_rt_stats_vty(p, iface->ifindex, IF_METRICS_IPIP
			      , gtp_interface_metrics_show
			      , vty);

  end:
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
	struct gtp_interface *new;
	int ifindex;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_interface_get(argv[0]);
	if (new) {
		vty->node = INTERFACE_NODE;
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
	gtp_interface_put(new);
	return CMD_SUCCESS;
}

DEFUN(no_interface,
      no_interface_cmd,
      "no interface STRING",
      "Configure interface\n"
      "Local system interface name\n")
{
	struct gtp_interface *iface;

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
	struct gtp_interface *iface = vty->index;
	struct gtp_bpf_prog *p;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (iface->bpf_prog_attr[p->type].prog) {
		vty_out(vty, "%% bpf-program:'%s' already in-use for type:%s%s"
			   , iface->bpf_prog_attr[p->type].prog->name
			   , (p->type == GTP_BPF_PROG_TYPE_XDP) ? "XDP" : "TC"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	iface->bpf_prog_attr[p->type].prog = p;
	return CMD_SUCCESS;
}

DEFUN(interface_direct_tx_gw,
      interface_direct_tx_gw_cmd,
      "direct-tx-gw (A.B.C.D|X:X:X:X)",
      "Direct TX mode Gateway IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	struct gtp_interface *iface = vty->index;
	struct ip_address *ip_addr = &iface->direct_tx_gw;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = inet_stoipaddress(argv[0], ip_addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(ip_addr, 0, sizeof(struct ip_address));
		return CMD_WARNING;
	}

	__set_bit(GTP_INTERFACE_FL_DIRECT_TX_GW_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_carrier_grade_nat,
      interface_carrier_grade_nat_cmd,
      "carrier-grade-nat CGNBLOCK side (network-in|network-out)",
      "Configure carrier-grade on this interface\n"
      "carrier-grade-nat configuration bloc name\n"
      "Side this interface is handling\n"
      "Network's operator side (private,local,inside)\n"
      "Internet side (public,remote,outside)\n")
{
	struct gtp_interface *iface = vty->index;

	__clear_bit(GTP_INTERFACE_FL_CGNAT_NET_IN_BIT, &iface->flags);
	__clear_bit(GTP_INTERFACE_FL_CGNAT_NET_OUT_BIT, &iface->flags);
	bsd_strlcpy(iface->cgn_name, argv[0], sizeof (iface->cgn_name) - 1);
	if (!strcmp(argv[1], "network-in"))
		__set_bit(GTP_INTERFACE_FL_CGNAT_NET_IN_BIT, &iface->flags);
	else
		__set_bit(GTP_INTERFACE_FL_CGNAT_NET_OUT_BIT, &iface->flags);
	return CMD_SUCCESS;
}


DEFUN(interface_description,
      interface_description_cmd,
      "description STRING",
      "Set Interface description\n"
      "description\n")
{
	struct gtp_interface *iface = vty->index;

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
	struct gtp_interface *iface = vty->index;

	__set_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface_metrics_gtp,
      no_interface_metrics_gtp_cmd,
      "no metrics gtp",
      "Disable GTP metrics\n")
{
	struct gtp_interface *iface = vty->index;

	__clear_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_metrics_pppoe,
      interface_metrics_pppoe_cmd,
      "metrics pppoe",
      "Enable PPPoE metrics\n")
{
	struct gtp_interface *iface = vty->index;

	__set_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface_metrics_pppoe,
      no_interface_metrics_pppoe_cmd,
      "no metrics pppoe",
      "Disable PPPoE metrics\n")
{
	struct gtp_interface *iface = vty->index;

	__clear_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_metrics_ipip,
      interface_metrics_ipip_cmd,
      "metrics ipip",
      "Enable IPIP metrics\n")
{
	struct gtp_interface *iface = vty->index;

	__set_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(no_interface_metrics_ipip,
      no_interface_metrics_ipip_cmd,
      "no metrics ipip",
      "Disable IPIP metrics\n")
{
	struct gtp_interface *iface = vty->index;

	__clear_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_metrics_link,
      interface_metrics_link_cmd,
      "metrics link",
      "Enable link metrics\n")
{
	struct gtp_interface *iface = vty->index;

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
	struct gtp_interface *iface = vty->index;

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
	struct gtp_interface *iface = vty->index;

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
	struct gtp_interface *iface = vty->index;
	struct gtp_bpf_prog *p, *p_xdp = NULL;
	int err = 0, i;

	if (!__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags)) {
		vty_out(vty, "%% interface:'%s' is already running%s"
			   , iface->ifname
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP].prog &&
	    !iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_TC].prog) {
		vty_out(vty, "%% no bpf-program configured for interface:'%s'%s"
			   , iface->ifname, VTY_NEWLINE);
		goto end;
	}

	err = gtp_interface_load_bpf(iface);
	if (err) {
		vty_out(vty, "%% error attaching bpf-program to interface:'%s'%s"
			   , iface->ifname, VTY_NEWLINE);
		return CMD_WARNING;
	}

	for (i = 0; i < GTP_BPF_PROG_TYPE_MAX; i++) {
		p = iface->bpf_prog_attr[i].prog;
		if (!p)
			continue;
		if (p->type == GTP_BPF_PROG_TYPE_XDP)
			p_xdp = p;

		vty_out(vty, "Success attaching bpf-program:'%s' to interface:'%s'%s"
			   , p->name
			   , iface->ifname, VTY_NEWLINE);
		log_message(LOG_INFO, "Success attaching bpf-program:'%s' to interface:'%s'"
				    , p->name
				    , iface->ifname);
	}

	if (!p_xdp)
		goto end;

	/* Metrics init */
	if (__test_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(p_xdp,
							iface->ifindex, IF_METRICS_GTP);
	if (__test_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(p_xdp,
							iface->ifindex, IF_METRICS_PPPOE);
	if (__test_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(p_xdp,
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
	struct gtp_interface *iface = NULL;

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
interface_config_bpf_write(struct vty *vty, struct gtp_interface *iface)
{
	struct gtp_bpf_prog *p;
	int i;

	for (i = 0; i < GTP_BPF_PROG_TYPE_MAX; i++) {
		p = iface->bpf_prog_attr[i].prog;
		if (!p)
			continue;

		vty_out(vty, " bpf-program %s%s", p->name, VTY_NEWLINE);
	}

	return 0;
}

static int
interface_config_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->interfaces;
	char addr_str[INET6_ADDRSTRLEN];
	struct gtp_interface *iface;

	list_for_each_entry(iface, l, next) {
		vty_out(vty, "interface %s%s", iface->ifname, VTY_NEWLINE);
		if (iface->description[0])
			vty_out(vty, " description %s%s", iface->description, VTY_NEWLINE);
		interface_config_bpf_write(vty, iface);
		if (__test_bit(GTP_INTERFACE_FL_DIRECT_TX_GW_BIT, &iface->flags))
			vty_out(vty, " direct-tx-gw %s%s"
				   , inet_ipaddresstos(&iface->direct_tx_gw, addr_str)
				   , VTY_NEWLINE);
		if (__test_bit(GTP_INTERFACE_FL_CGNAT_NET_IN_BIT, &iface->flags))
			vty_out(vty, " carrier-grade-nat %s side network-in%s"
				   , iface->cgn_name
				   , VTY_NEWLINE);
		else if (__test_bit(GTP_INTERFACE_FL_CGNAT_NET_OUT_BIT, &iface->flags))
			vty_out(vty, " carrier-grade-nat %s side network-out%s"
				   , iface->cgn_name
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
static int
cmd_ext_interface_install(void)
{
	/* Install Interface commands. */
	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);

	install_default(INTERFACE_NODE);
	install_element(INTERFACE_NODE, &interface_description_cmd);
	install_element(INTERFACE_NODE, &interface_bpf_prog_cmd);
	install_element(INTERFACE_NODE, &interface_direct_tx_gw_cmd);
	install_element(INTERFACE_NODE, &interface_carrier_grade_nat_cmd);
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

struct cmd_node interface_node = {
	.node = INTERFACE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(interface)# ",
	.config_write = interface_config_write,
};

static struct cmd_ext cmd_ext_interface = {
	.node = &interface_node,
	.install = cmd_ext_interface_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_interface);
}
