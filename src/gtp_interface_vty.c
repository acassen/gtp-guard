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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>

#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "gtp_bpf_rt.h"
#include "gtp_bpf_ifrules.h"
#include "gtp_interface.h"
#include "gtp_interface_rxq.h"
#include "inet_utils.h"
#include "command.h"
#include "bitops.h"
#include "memory.h"
#include "pci.h"

/* Extern data */
extern struct data *daemon_data;


/*
 *	Interface statistics helpers
 */
static void
bw_format(uint64_t bps, char *buf, size_t len)
{
	if (bps >= 1000000000ULL)
		snprintf(buf, len, "%.2fGbps", (double)bps / 1e9);
	else if (bps >= 1000000ULL)
		snprintf(buf, len, "%.2fMbps", (double)bps / 1e6);
	else if (bps >= 1000ULL)
		snprintf(buf, len, "%.2fKbps", (double)bps / 1e3);
	else
		snprintf(buf, len, "%llubps", (unsigned long long)bps);
}

static int
gtp_interface_stats_show_summary(struct gtp_interface *iface, void *arg)
{
	const struct ethtool_phy_stats *s = &iface->phy_stats;
	struct vty *vty = arg;
	char rxbw[20], txbw[20];

	bw_format(iface->rx_bw_bps, rxbw, sizeof(rxbw));
	bw_format(iface->tx_bw_bps, txbw, sizeof(txbw));
	vty_out(vty, "%-16s  %14llu  %14llu  %14llu  %14llu  %14s  %14s%s",
		iface->ifname,
		(unsigned long long)s->rx_packets,
		(unsigned long long)s->tx_packets,
		(unsigned long long)s->rx_bytes,
		(unsigned long long)s->tx_bytes,
		rxbw, txbw, VTY_NEWLINE);
	return 0;
}

static void
gtp_interface_stats_show_detail(struct vty *vty, struct gtp_interface *iface)
{
	const struct ethtool_phy_stats *p = &iface->phy_stats;
	char rxbw[20], txbw[20];
	uint32_t q, nr;
	int *cpu_per_q;

	bw_format(iface->rx_bw_bps, rxbw, sizeof(rxbw));
	bw_format(iface->tx_bw_bps, txbw, sizeof(txbw));

	vty_out(vty, "Interface %s%s", iface->ifname, VTY_NEWLINE);
	vty_out(vty, "  PHY counters:%s", VTY_NEWLINE);
	vty_out(vty, "    %-24s %-14llu  %-24s %llu%s",
		"rx_packets:", (unsigned long long)p->rx_packets,
		"tx_packets:", (unsigned long long)p->tx_packets, VTY_NEWLINE);
	vty_out(vty, "    %-24s %-14llu  %-24s %llu%s",
		"rx_bytes:", (unsigned long long)p->rx_bytes,
		"tx_bytes:", (unsigned long long)p->tx_bytes, VTY_NEWLINE);
	vty_out(vty, "    %-24s %-14llu  %-24s %llu%s",
		"rx_discards:", (unsigned long long)p->rx_discards,
		"tx_discards:", (unsigned long long)p->tx_discards, VTY_NEWLINE);
	vty_out(vty, "    %-24s %llu%s",
		"tx_errors:", (unsigned long long)p->tx_errors, VTY_NEWLINE);
	vty_out(vty, "  Frame size histogram (rx):%s", VTY_NEWLINE);
	vty_out(vty, "    %-10s %-14llu  %-14s %-14llu  %-16s %llu%s",
		"[64]", (unsigned long long)p->rx_64,
		"[65-127]", (unsigned long long)p->rx_65_127,
		"[128-255]", (unsigned long long)p->rx_128_255, VTY_NEWLINE);
	vty_out(vty, "    %-10s %-14llu  %-14s %-14llu  %-16s %llu%s",
		"[256-511]", (unsigned long long)p->rx_256_511,
		"[512-1023]", (unsigned long long)p->rx_512_1023,
		"[1024-1518]", (unsigned long long)p->rx_1024_1518, VTY_NEWLINE);
	vty_out(vty, "    %-10s %-14llu  %-14s %-14llu  %-16s %llu%s",
		"[1519-2047]", (unsigned long long)p->rx_1519_2047,
		"[2048-4095]", (unsigned long long)p->rx_2048_4095,
		"[4096-8191]", (unsigned long long)p->rx_4096_8191, VTY_NEWLINE);
	vty_out(vty, "    %-10s %llu%s",
		"[8192-10239]", (unsigned long long)p->rx_8192_10239, VTY_NEWLINE);
	vty_out(vty, "  Bandwidth: rx:%s  tx:%s%s", rxbw, txbw, VTY_NEWLINE);

	if (!iface->queue_stats || !(iface->nr_rx_queues | iface->nr_tx_queues)) {
		vty_out(vty, "%s", VTY_NEWLINE);
		return;
	}

	nr = iface->nr_rx_queues > iface->nr_tx_queues ?
	     iface->nr_rx_queues : iface->nr_tx_queues;
	cpu_per_q = calloc(nr, sizeof(*cpu_per_q));
	if (!cpu_per_q) {
		vty_out(vty, "%s", VTY_NEWLINE);
		return;
	}
	memset(cpu_per_q, -1, nr * sizeof(*cpu_per_q));
	gtp_interface_rxq_cpu(iface, cpu_per_q, nr);

	vty_out(vty, "  Per-queue counters:%s", VTY_NEWLINE);
	vty_out(vty, "    %3s  %4s  %14s  %14s  %12s  %14s  %14s%s",
		"q", "cpu", "rx_packets", "rx_bytes", "rx_xdp_drop",
		"tx_packets", "tx_bytes", VTY_NEWLINE);
	for (q = 0; q < nr; q++) {
		const struct ethtool_q_stats *qs = &iface->queue_stats[q];
		vty_out(vty, "    %3u  %4d  %14llu  %14llu  %12llu  %14llu  %14llu%s",
			q, cpu_per_q[q],
			(unsigned long long)qs->rx_packets,
			(unsigned long long)qs->rx_bytes,
			(unsigned long long)qs->rx_xdp_drop,
			(unsigned long long)qs->tx_packets,
			(unsigned long long)qs->tx_bytes, VTY_NEWLINE);
	}
	free(cpu_per_q);

	/* BPF XDP counters */
	if (iface->bpf_ifrules) {
		struct gtp_bpf_ifrule_metrics m;

		if (!gtp_bpf_ifrules_metrics(iface, &m)) {
			vty_out(vty, "  BPF XDP counters:%s", VTY_NEWLINE);
			vty_out(vty, "    %-24s %-14llu  %-24s %-14llu  %-24s %llu%s",
				"pkt_in:", (unsigned long long)m.pkt_in,
				"bytes_in:", (unsigned long long)m.bytes_in,
				"pkt_fwd:", (unsigned long long)m.pkt_fwd,
				VTY_NEWLINE);
			if (p->rx_packets)
				vty_out(vty, "    %-24s %llu%s",
					"sys_rx_pkts:",
					(unsigned long long)(p->rx_packets - m.pkt_in),
					VTY_NEWLINE);
		}
	}
	vty_out(vty, "%s", VTY_NEWLINE);
}


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
	if (__test_bit(GTP_INTERFACE_FL_BPF_NO_DEFAULT_ROUTE_BIT, &iface->flags))
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

	/* BPF-program should only be attached to 'physical' interfaces, in
	 * native mode, for best perfomance. Attaching to veth is also ok for testing.
	 * Warn user if trying to attach to vlan/tunnel interface. */
	if (iface->vlan_id) {
		vty_out(vty, "%% Warning: attaching bpf:%s to vlan interface:%s is "
			"not the right gtp-guard way.\n"
			"You should attach bpf-program only to its master interface '%s'.\n",
			argv[0], iface->ifname,
			iface->link_iface ? iface->link_iface->ifname : "<unset>");
	}
	if (iface->tunnel_mode) {
		vty_out(vty, "%% Warning: attaching bpf:%s to tunnel interface:%s is "
			"not the right gtp-guard way.\n"
			"You should attach bpf-program to physical interfaces where "
			"traffic is expected to come from/come to,\nand this tunnel will "
			"install rules to catch traffic for it.\n",
			argv[0], iface->ifname);
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (iface->bpf_prog && iface->bpf_prog != p) {
		vty_out(vty, "%% bpf-program:'%s' already loaded on this interface%s"
			   , iface->bpf_prog->name
			   , VTY_NEWLINE);
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
		__clear_bit(GTP_INTERFACE_FL_BPF_NO_DEFAULT_ROUTE_BIT, &iface->flags);
	else
		__set_bit(GTP_INTERFACE_FL_BPF_NO_DEFAULT_ROUTE_BIT, &iface->flags);

	gtp_bpf_ifrules_set_auto_input_rule(iface, set);

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

/* Capture */
DEFUN(capture_start_interface,
      capture_start_interface_cmd,
      "capture interface IFNAME start [CAPENTRY side (input|output|both) caplen <32-10000>]",
      "Capture menu\n"
      "Capture interface submenu\n"
      "Interface name\n"
      "Start capture\n"
      "Capture file entry\n"
      "Capture side, on interface entry and/or exit\n"
      "Capture on interface ingress/input\n"
      "Capture on interface egress/output\n"
      "Capture on interface ingress and egress\n"
      "Capture packet max length\n"
      "Value\n")
{
	struct gtp_interface *iface = NULL;
	char capname[64];

	iface = gtp_interface_get(argv[0], false);
	if (!iface) {
		vty_out(vty, "%% Unknown interface:'%s'\n", argv[0]);
		return CMD_WARNING;
	}

	if (iface->bpf_prog == NULL) {
		vty_out(vty, "%% No bpf-program attached to interface %s\n", argv[0]);
		return CMD_WARNING;
	}

	if (argc > 1)
		snprintf(capname, sizeof (capname), "%s", argv[1]);
	else
		snprintf(capname, sizeof (capname), "%s", iface->ifname);

	iface->capture_entry.flags = 0;
	if (argc > 3) {
		if (!strcmp(argv[3], "output") || !strcmp(argv[3], "both"))
			iface->capture_entry.flags |= GTP_CAPTURE_FL_OUTPUT;
		if (!strcmp(argv[3], "input") || !strcmp(argv[3], "both"))
			iface->capture_entry.flags |= GTP_CAPTURE_FL_INPUT;
	} else {
		iface->capture_entry.flags |= GTP_CAPTURE_FL_INPUT;
	}

	if (gtp_capture_start_iface(&iface->capture_entry, iface->bpf_prog,
				    capname, iface->ifindex)) {
		vty_out(vty, "%% Error starting interface trace\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(capture_stop_interface,
      capture_stop_interface_cmd,
      "capture interface IFNAME stop",
      "Capture menu\n"
      "Capture interface submenu\n"
      "Interface name\n"
      "Stop capture\n")
{
	struct gtp_interface *iface = NULL;

	iface = gtp_interface_get(argv[0], false);
	if (!iface) {
		vty_out(vty, "%% Unknown interface:'%s'\n", argv[0]);
		return CMD_WARNING;
	}

	gtp_capture_stop(&iface->capture_entry);

	return CMD_SUCCESS;
}


/* Show */
DEFUN(show_interface_rxq_topology,
      show_interface_rxq_topology_cmd,
      "show interface rx-queue topology",
      SHOW_STR
      "Interface\n"
      "Display RX queue IRQ affinity and NUMA diagnostic\n")
{
	gtp_interface_rxq_show(vty);
	return CMD_SUCCESS;
}

DEFUN(show_interface_topology,
      show_interface_topology_cmd,
      "show interface topology",
      SHOW_STR
      "Interface\n"
      "Display PCI ethernet devices and NUMA topology\n")
{
	struct pci_eth_dev *devs;
	int ndevs;

	devs = calloc(PCI_MAX_ETH_DEVS, sizeof(*devs));
	if (!devs)
		return CMD_WARNING;

	ndevs = pci_eth_dev_fetch(devs, PCI_MAX_ETH_DEVS);
	if (ndevs < 0) {
		vty_out(vty, "%% cannot enumerate PCI devices%s", VTY_NEWLINE);
		free(devs);
		return CMD_WARNING;
	}

	if (!ndevs) {
		vty_out(vty, "No PCI ethernet devices found%s", VTY_NEWLINE);
		free(devs);
		return CMD_SUCCESS;
	}

	pci_eth_dev_vty(vty, devs, ndevs);
	free(devs);
	return CMD_SUCCESS;
}

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
		return CMD_SUCCESS;
	}

	gtp_interface_foreach(gtp_interface_show, vty);
	return CMD_SUCCESS;
}

DEFUN(show_interface_stats_all,
      show_interface_stats_all_cmd,
      "show interface statistics",
      SHOW_STR
      "Interface\n"
      "Display cumulative interface statistics\n")
{
	vty_out(vty, "%-16s  %14s  %14s  %14s  %14s  %14s  %14s%s",
		"Interface", "rx-packets", "tx-packets",
		"rx-bytes", "tx-bytes", "rx-bw", "tx-bw", VTY_NEWLINE);
	vty_out(vty, "%-16s  %14s  %14s  %14s  %14s  %14s  %14s%s",
		"----------------", "--------------", "--------------",
		"--------------", "--------------",
		"--------------", "--------------", VTY_NEWLINE);
	gtp_interface_foreach(gtp_interface_stats_show_summary, vty);
	return CMD_SUCCESS;
}

DEFUN(show_interface_stats,
      show_interface_stats_cmd,
      "show interface statistics WORD",
      SHOW_STR
      "Interface\n"
      "Display cumulative interface statistics\n"
      "Interface name\n")
{
	struct gtp_interface *iface;

	iface = gtp_interface_get(argv[0], false);
	if (!iface) {
		vty_out(vty, "%% Unknown interface:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	gtp_interface_stats_show_detail(vty, iface);
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
		if (__test_bit(GTP_INTERFACE_FL_BPF_NO_DEFAULT_ROUTE_BIT, &iface->flags))
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

	/* Install capture commands */
	install_element(ENABLE_NODE, &capture_start_interface_cmd);
	install_element(ENABLE_NODE, &capture_stop_interface_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_interface_cmd);
	install_element(ENABLE_NODE, &show_interface_cmd);
	install_element(VIEW_NODE, &show_interface_rxq_topology_cmd);
	install_element(ENABLE_NODE, &show_interface_rxq_topology_cmd);
	install_element(VIEW_NODE, &show_interface_topology_cmd);
	install_element(ENABLE_NODE, &show_interface_topology_cmd);
	install_element(VIEW_NODE, &show_interface_stats_all_cmd);
	install_element(ENABLE_NODE, &show_interface_stats_all_cmd);
	install_element(VIEW_NODE, &show_interface_stats_cmd);
	install_element(ENABLE_NODE, &show_interface_stats_cmd);

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
