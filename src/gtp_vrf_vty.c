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

/* Local data */
static uint32_t gtp_vrf_id;

cmd_node_t ip_vrf_node = {
        IP_VRF_NODE,
        "%s(ip-vrf)# ",
        1,
};


/*
 *	Command
 */
DEFUN(ip_vrf,
      ip_vrf_cmd,
      "ip vrf WORD",
      "Configure IP VRF\n"
      "VRF Name")
{
	ip_vrf_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = gtp_ip_vrf_get(argv[0]);
	if (!new)
		new = gtp_ip_vrf_alloc(argv[0]);

	__sync_add_and_fetch(&gtp_vrf_id, 1);
	new->id = gtp_vrf_id;

	vty->node = IP_VRF_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_ip_vrf,
      no_ip_vrf_cmd,
      "no ip vrf WORD",
      "Destroy IP VRF\n"
      "VRF Name")
{
	ip_vrf_t *vrf;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	vrf = gtp_ip_vrf_get(argv[0]);
	if (!vrf) {
		vty_out(vty, "%% unknown ip vrf %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_ip_vrf_destroy(vrf);
	FREE(vrf);

	return CMD_SUCCESS;
}

DEFUN(ip_vrf_description,
      ip_vrf_description_cmd,
      "description WORD",
      "IP VRF Description\n"
      "Description String")
{
	ip_vrf_t *vrf = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strncat(vrf->description, argv[0], GTP_STR_MAX_LEN - 1);

	return CMD_SUCCESS;
}

DEFUN(ip_vrf_encapsulation_dot1q,
      ip_vrf_encapsulation_dot1q_cmd,
      "encapsulation dot1q <1-65535>",
      "Encapsulation\n"
      "802.1q type\n"
      "Vlan ID between 1 and 65535\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_iptnl_t *t = &vrf->iptnl;
	int vlan_id;

	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-Route program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Vlan ID", vlan_id, argv[0], 1, 65535);
	vrf->encap_vlan_id = vlan_id;
	t->encap_vlan_id = vlan_id;
	t->flags |= IPTNL_FL_TAG_VLAN;

	__set_bit(IP_VRF_FL_ENCAP_DOT1Q_BIT, &vrf->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_decapsulation_dot1q,
      ip_vrf_decapsulation_dot1q_cmd,
      "decapsulation dot1q <1-65535>",
      "Decapsulation\n"
      "802.1q type\n"
      "Vlan ID between 1 and 65535\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_iptnl_t *t = &vrf->iptnl;
	int vlan_id;

	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-Route program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Vlan ID", vlan_id, argv[0], 1, 65535);
	vrf->decap_vlan_id = vlan_id;
	t->decap_vlan_id = vlan_id;
	t->flags |= IPTNL_FL_UNTAG_VLAN;

	__set_bit(IP_VRF_FL_DECAP_DOT1Q_BIT, &vrf->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_encapsulation_ipip,
      ip_vrf_encapsulation_ipip_cmd,
      "encapsulation ipip local (A.B.C.D|X:X:X:X) remote (A.B.C.D|X:X:X:X)",
      "Encapsulation\n"
      "IP-IP tunneling type\n"
      "local Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Remote Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_iptnl_t *t = &vrf->iptnl;
	uint32_t laddr, raddr;
	int ret;

	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% eBPF GTP-Route program not loaded!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_ston(argv[0], &laddr);
	if (!ret) {
		vty_out(vty, "%% malformed Local IP address %s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_ston(argv[1], &raddr);
	if (!ret) {
		vty_out(vty, "%% malformed Remote IP address %s%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	t->selector_addr = vrf->id;
	t->local_addr = laddr;
	t->remote_addr = raddr;
	ret = gtp_xdp_rt_iptnl_action(RULE_ADD, t);
	if (ret < 0) {
		vty_out(vty, "%% Unable to create XDP IPIP-Tunnel%s", VTY_NEWLINE);
		memset(t, 0, sizeof(gtp_iptnl_t));
		return CMD_WARNING;
	}

	__set_bit(IP_VRF_FL_IPIP_BIT, &vrf->flags);
	return CMD_SUCCESS;
}

/* Configuration writer */
static int
gtp_config_write(vty_t *vty)
{
        list_head_t *l = &daemon_data->ip_vrf;
        ip_vrf_t *vrf;

        list_for_each_entry(vrf, l, next) {
        	vty_out(vty, "ip vrf %s%s", vrf->name, VTY_NEWLINE);
		if (vrf->description[0])
			vty_out(vty, " description %s%s", vrf->description, VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_ENCAP_DOT1Q_BIT, &vrf->flags))
			vty_out(vty, " encapsulation dot1q %d%s", vrf->encap_vlan_id, VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_DECAP_DOT1Q_BIT, &vrf->flags))
			vty_out(vty, " decapsulation dot1q %d%s", vrf->decap_vlan_id, VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_IPIP_BIT, &vrf->flags))
			vty_out(vty, " encapsulation ipip local %u.%u.%u.%u remoite %u.%u.%u.%u%s"
				   , NIPQUAD(vrf->iptnl.local_addr)
				   , NIPQUAD(vrf->iptnl.remote_addr)
				   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_vrf_vty_init(void)
{
	/* Install PDN commands. */
	install_node(&ip_vrf_node, gtp_config_write);
	install_element(CONFIG_NODE, &ip_vrf_cmd);
	install_element(CONFIG_NODE, &no_ip_vrf_cmd);

	install_default(IP_VRF_NODE);
	install_element(IP_VRF_NODE, &ip_vrf_description_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_encapsulation_dot1q_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_decapsulation_dot1q_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_encapsulation_ipip_cmd);

	return 0;
}
