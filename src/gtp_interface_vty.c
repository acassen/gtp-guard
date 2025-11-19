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

#include <linux/types.h>
#include <linux/rtnetlink.h>

#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "gtp_bpf_rt.h"
#include "gtp_interface.h"
#include "inet_utils.h"
#include "command.h"
#include "bitops.h"
#include "utils.h"
#include "memory.h"

/* Extern data */
extern struct data *daemon_data;


/*
 *	VTY helpers
 */
static int
gtp_interface_show(struct gtp_interface *iface, void *arg)
{
	struct gtp_bpf_prog *p = iface->bpf_prog;
	struct vty *vty = arg;
	char addr_str[INET6_ADDRSTRLEN];
	char addr2_str[INET6_ADDRSTRLEN];

	vty_out(vty, "interface %s {%s%s }\n"
		   , iface->ifname
		   , __test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ?
		   " shutdown" : ""
		   , __test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags) ?
		   " running" : "");
	vty_out(vty, " ifindex:%d%s"
		   , iface->ifindex
		   , VTY_NEWLINE);
	vty_out(vty, " ll_addr:" ETHER_FMT "%s"
		   , ETHER_BYTES(iface->hw_addr)
		   , VTY_NEWLINE);
	if (iface->vlan_id)
		vty_out(vty, " vlan-id:%d%s"
			   , iface->vlan_id, VTY_NEWLINE);
	if (iface->table_id)
		vty_out(vty, " table-id:%d%s"
			   , iface->table_id, VTY_NEWLINE);
	if (iface->link_iface)
		vty_out(vty, " link-iface:%s%s"
			   , iface->link_iface->ifname, VTY_NEWLINE);
	if (iface->tunnel_mode)
		vty_out(vty, " tunnel-%s: local:%s remote:%s%s"
			   , iface->tunnel_mode == 1 ? "gre" : "ipip"
			   , addr_stringify(&iface->tunnel_local
					    , addr_str, sizeof (addr_str))
			   , addr_stringify(&iface->tunnel_remote
					    , addr2_str, sizeof (addr2_str))
			   , VTY_NEWLINE);
	if (__test_bit(GTP_INTERFACE_FL_BFP_NO_DEFAULT_ROUTE_BIT, &iface->flags))
		vty_out(vty, " bpf-input-pkt: rule-disabled\n");
	if (iface->direct_tx_gw.family)
		vty_out(vty, " direct-tx-gw:%s ll_addr:" ETHER_FMT "%s"
			   , addr_stringify_ip(&iface->direct_tx_gw, addr_str,
					       sizeof (addr_str))
			   , ETHER_BYTES(iface->direct_tx_hw_addr)
			   , VTY_NEWLINE);

	gtp_bpf_rt_stats_vty(p, iface, vty);

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

	new = gtp_interface_get(argv[0], true);
	if (!new) {
		vty_out(vty, "%% cannot get interface %s%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

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

	iface = gtp_interface_get(argv[0], false);
	if (!iface) {
		vty_out(vty, "%% unknown interface:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_interface_put(iface);
	gtp_interface_destroy(iface);
	return CMD_SUCCESS;
}

DEFUN(interface_description,
      interface_description_cmd,
      "description STRING",
      "Set Interface description\n"
      "description\n")
{
	struct gtp_interface *iface = vty->index;

	snprintf(iface->description, sizeof (iface->description), "%s", argv[0]);
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

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (iface->bpf_prog && iface->bpf_prog != p) {
		vty_out(vty, "%% bpf-program:'%s' already loaded on this interface%s"
			   , iface->bpf_prog->name
			   , VTY_NEWLINE);
		gtp_bpf_prog_put(p);
		return CMD_WARNING;
	}

	if (!iface->bpf_prog) {
		iface->bpf_prog = p;
		list_add(&iface->bpf_prog_list, &p->iface_bind_list);
	}

	return CMD_SUCCESS;
}

DEFUN(interface_bpf_pkt,
      interface_bpf_pkt_cmd,
      "bpf-packet input (disable-rule|default)",
      "BPF Program packet handling\n"
      "Set automatic rules that process input packets on this interface\n"
      "Do not set such rules\n"
      "Set default rules\n")
{
	struct gtp_interface *iface = vty->index;
	bool set = !strcmp(argv[0], "default");

	if (set)
		__clear_bit(GTP_INTERFACE_FL_BFP_NO_DEFAULT_ROUTE_BIT, &iface->flags);
	else
		__set_bit(GTP_INTERFACE_FL_BFP_NO_DEFAULT_ROUTE_BIT, &iface->flags);

	gtp_interface_rule_set_auto_input_rule(iface, set);

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
	int err;

	err = addr_parse(argv[0], &iface->direct_tx_gw);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		addr_zero(&iface->direct_tx_gw);
		__clear_bit(GTP_INTERFACE_FL_DIRECT_TX_GW_BIT, &iface->flags);
		return CMD_WARNING;
	}

	__set_bit(GTP_INTERFACE_FL_DIRECT_TX_GW_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_table_id,
      interface_table_id_cmd,
      "ip route table-id <0-32767>",
      "IP Interface\n"
      "Route definition\n"
      "Set IP table used for fib_lookup (0 for main table)\n"
      "IP table-id\n")
{
	struct gtp_interface *iface = vty->index;

	VTY_GET_INTEGER_RANGE("IP table-id", iface->table_id, argv[0], 0, 32767);

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

	gtp_interface_stop(iface);
	__set_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(interface_no_shutdown,
      interface_no_shutdown_cmd,
      "no shutdown",
      "Activate interface\n")
{
	struct gtp_interface *iface = vty->index;

	if (!__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) &&
	    __test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags)) {
		vty_out(vty, "%% interface:'%s' is already running%s"
			   , iface->ifname
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	gtp_interface_start(iface);
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
		iface = gtp_interface_get(argv[0], false);
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
interface_config_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->interfaces;
	char addr_str[INET6_ADDRSTRLEN];
	struct gtp_interface *iface;

	list_for_each_entry(iface, l, next) {
		vty_out(vty, "interface %s%s", iface->ifname, VTY_NEWLINE);
		if (iface->description[0])
			vty_out(vty, " description %s%s", iface->description, VTY_NEWLINE);
		if (iface->bpf_prog)
			vty_out(vty, " bpf-program %s%s", iface->bpf_prog->name, VTY_NEWLINE);
		if (__test_bit(GTP_INTERFACE_FL_BFP_NO_DEFAULT_ROUTE_BIT, &iface->flags))
			vty_out(vty, " bpf-packet input disable-rule\n");
		if (__test_bit(GTP_INTERFACE_FL_DIRECT_TX_GW_BIT, &iface->flags))
			vty_out(vty, " direct-tx-gw %s%s"
				   , addr_stringify_ip(&iface->direct_tx_gw, addr_str,
						       sizeof (addr_str))
				   , VTY_NEWLINE);

		if (iface->table_id)
			vty_out(vty, " ip route table-id %d%s", iface->table_id, VTY_NEWLINE);
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
	install_element(INTERFACE_NODE, &interface_bpf_pkt_cmd);
	install_element(INTERFACE_NODE, &interface_direct_tx_gw_cmd);
	install_element(INTERFACE_NODE, &interface_table_id_cmd);
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
gtp_interface_vty_init(void)
{
	cmd_ext_register(&cmd_ext_interface);
}
