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

static int gtp_config_write(vty_t *vty);
cmd_node_t ip_vrf_node = {
        .node = IP_VRF_NODE,
        .parent_node = CONFIG_NODE,
        .prompt ="%s(ip-vrf)# ",
        .config_write = gtp_config_write,
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

DEFUN(ip_vrf_gtp_udp_port_learning,
      ip_vrf_gtp_udp_port_learning_cmd,
      "gtp-udp-port-learning",
      "GTP-U UDP src-port learning\n")
{
	ip_vrf_t *vrf = vty->index;

	__set_bit(IP_VRF_FL_GTP_UDP_PORT_LEARNING_BIT, &vrf->flags);
	return CMD_SUCCESS;
}

DEFUN(no_ip_vrf_gtp_udp_port_learning,
      no_ip_vrf_gtp_udp_port_learning_cmd,
      "no gtp-udp-port-learning",
      "GTP-U UDP src-port learning\n")
{
	ip_vrf_t *vrf = vty->index;

	__clear_bit(IP_VRF_FL_GTP_UDP_PORT_LEARNING_BIT, &vrf->flags);
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

DEFUN(ip_vrf_pppoe,
      ip_vrf_pppoe_cmd,
      "pppoe interface STRING [rps-bits [INTEGER]]",
      "PPP Over Ethernet support\n"
      "Interface\n"
      "IFNAME\n"
      "RPS bits for pthread workers\n"
      "max bits of pthread workers (default = "STR(GTP_PPPOE_RPS_BITS)" bits)\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe;
	int ret;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(IP_VRF_FL_PPPOE_BIT, &vrf->flags)) {
		vty_out(vty, "%% PPPoE already configured!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pppoe = gtp_pppoe_init(argv[0]);
	if (!pppoe) {
		vty_out(vty, "%% unknown interface %s!%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* argv[3] is listnener-count */
	pppoe->thread_cnt = (argc == 3) ? (1 << strtoul(argv[2], NULL, 10)) : GTP_PPPOE_RPS_SIZE;
	pppoe->thread_cnt = (pppoe->thread_cnt < 1) ? 1 : pppoe->thread_cnt; /* XXX useless */
	__set_bit(IP_VRF_FL_PPPOE_BIT, &vrf->flags);
	vrf->pppoe = pppoe;
	ret = gtp_pppoe_start(pppoe);
	if (ret < 0) {
		vty_out(vty, "%% Error starting PPPoE on interface %s!%s", argv[0], VTY_NEWLINE);
		gtp_pppoe_release(pppoe);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_ac_name,
      ip_vrf_pppoe_ac_name_cmd,
      "pppoe access-concentrator-name STRING",
      "PPP Over Ethernet\n"
      "Access Concentrator Name\n"
      "String\n")
{
	ip_vrf_t *vrf = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!vrf->pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strlcpy(vrf->pppoe->ac_name, argv[0], PPPOE_NAMELEN);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_service_name,
      ip_vrf_pppoe_service_name_cmd,
      "pppoe service-name STRING",
      "PPP Over Ethernet\n"
      "Service Name\n"
      "String\n")
{
	ip_vrf_t *vrf = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!vrf->pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strlcpy(vrf->pppoe->service_name, argv[0], PPPOE_NAMELEN);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_mru,
      ip_vrf_pppoe_mru_cmd,
      "pppoe maximum-receive-unit INTEGER",
      "PPP Over Ethernet\n"
      "Maximum Receive Unit\n"
      "Integer\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pppoe->mru = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_vmac_hbits,
      ip_vrf_pppoe_vmac_hbits_cmd,
      "pppoe vmac-hbits INTEGER",
      "PPP Over Ethernet\n"
      "Virtual MAC Address first 4bits\n"
      "hbits\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;
	uint8_t hbits;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("hbits", hbits, argv[0], 0, 15);
	pppoe->vmac_hbits = hbits << 4;
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_auth_pap_gtp_username,
      ip_vrf_pppoe_auth_pap_gtp_username_cmd,
      "pppoe authentication pap gtp-username",
      "PPP Over Ethernet\n"
      "Authentication method\n"
      "Password Authentication Protocol\n"
      "Username built from GTP imsi+mei@apn\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (__test_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags)) {
		vty_out(vty, "%% Static username already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_GTP_USERNAME_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_auth_pap_username,
      ip_vrf_pppoe_auth_pap_username_cmd,
      "pppoe authentication pap username STRING",
      "PPP Over Ethernet\n"
      "Authentication method\n"
      "Password Authentication Protocol\n"
      "Username\n"
      "String\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(PPPOE_FL_GTP_USERNAME_BIT, &pppoe->flags)) {
		vty_out(vty, "%% GTP username already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strlcpy(pppoe->pap_username, argv[0], PPPOE_NAMELEN);
	__set_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_auth_pap_passwd,
      ip_vrf_pppoe_auth_pap_passwd_cmd,
      "pppoe authentication pap password STRING",
      "PPP Over Ethernet\n"
      "Authentication method\n"
      "Password Authentication Protocol\n"
      "Password\n"
      "String\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strlcpy(pppoe->pap_passwd, argv[0], PPPOE_NAMELEN);
	__set_bit(PPPOE_FL_STATIC_PASSWD_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_ipv6cp_disable,
      ip_vrf_pppoe_ipv6cp_disable_cmd,
      "pppoe ipv6cp disable",
      "PPP Over Ethernet\n"
      "IPv6 Control Protocol\n"
      "Disable\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_IPV6CP_DISABLE_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_keepalive,
      ip_vrf_pppoe_keepalive_cmd,
      "pppoe keepalive INTEGER",
      "PPP Over Ethernet\n"
      "PPP Keepalive interval\n"
      "Number of seconds\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_KEEPALIVE_BIT, &pppoe->flags);
	pppoe->keepalive = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_padi_fast_retry,
      ip_vrf_pppoe_padi_fast_retry_cmd,
      "pppoe padi-fast-retry",
      "PPP Over Ethernet\n"
      "PADI Fast Retry (1s)\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_lcp_timeout,
      ip_vrf_pppoe_lcp_timeout_cmd,
      "pppoe lcp-timeout INTEGER",
      "PPP Over Ethernet\n"
      "PPP lcp-timeout\n"
      "Number of seconds\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_TIMEOUT_BIT, &pppoe->flags);
	pppoe->lcp_timeout = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_lcp_max_terminate,
      ip_vrf_pppoe_lcp_max_terminate_cmd,
      "pppoe lcp-max-terminate INTEGER",
      "PPP Over Ethernet\n"
      "PPP lcp-max-terminate request\n"
      "Number\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_MAX_TERMINATE_BIT, &pppoe->flags);
	pppoe->lcp_max_terminate = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_lcp_max_configure,
      ip_vrf_pppoe_lcp_max_configure_cmd,
      "pppoe lcp-max-configure INTEGER",
      "PPP Over Ethernet\n"
      "PPP lcp-max-configure request\n"
      "Number\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_MAX_CONFIGURE_BIT, &pppoe->flags);
	pppoe->lcp_max_configure = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(ip_vrf_pppoe_lcp_max_failure,
      ip_vrf_pppoe_lcp_max_failure_cmd,
      "pppoe lcp-max-failure INTEGER",
      "PPP Over Ethernet\n"
      "PPP lcp-max-failure\n"
      "Number\n")
{
	ip_vrf_t *vrf = vty->index;
	gtp_pppoe_t *pppoe = vrf->pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pppoe) {
		vty_out(vty, "%% You MUST configure pppoe interface first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_MAX_FAILURE_BIT, &pppoe->flags);
	pppoe->lcp_max_failure = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}


/* Configuration writer */
static int
gtp_config_write(vty_t *vty)
{
        list_head_t *l = &daemon_data->ip_vrf;
	gtp_pppoe_t *pppoe;
        ip_vrf_t *vrf;

        list_for_each_entry(vrf, l, next) {
        	vty_out(vty, "ip vrf %s%s", vrf->name, VTY_NEWLINE);
		if (vrf->description[0])
			vty_out(vty, " description %s%s", vrf->description, VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_GTP_UDP_PORT_LEARNING_BIT, &vrf->flags))
			vty_out(vty, " gtp-udp-port-learning%s", VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_ENCAP_DOT1Q_BIT, &vrf->flags))
			vty_out(vty, " encapsulation dot1q %d%s", vrf->encap_vlan_id, VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_DECAP_DOT1Q_BIT, &vrf->flags))
			vty_out(vty, " decapsulation dot1q %d%s", vrf->decap_vlan_id, VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_IPIP_BIT, &vrf->flags))
			vty_out(vty, " encapsulation ipip local %u.%u.%u.%u remoite %u.%u.%u.%u%s"
				   , NIPQUAD(vrf->iptnl.local_addr)
				   , NIPQUAD(vrf->iptnl.remote_addr)
				   , VTY_NEWLINE);
		if (__test_bit(IP_VRF_FL_PPPOE_BIT, &vrf->flags)) {
			pppoe = vrf->pppoe;
			vty_out(vty, " pppoe interface %s", pppoe->ifname);
			if (pppoe->thread_cnt != GTP_PPPOE_RPS_SIZE)
				vty_out(vty, " rps-bits %d", __builtin_ctz(pppoe->thread_cnt));
			vty_out(vty, "%s", VTY_NEWLINE);
			if (pppoe->ac_name[0])
				vty_out(vty, " pppoe access-concentrator-name %s%s"
					   , pppoe->ac_name
					   , VTY_NEWLINE);
			if (pppoe->service_name[0])
				vty_out(vty, " pppoe service-name %s%s"
					   , pppoe->service_name
					   , VTY_NEWLINE);
			if (pppoe->mru)
				vty_out(vty, " pppoe maximum-receive-unit %d%s"
					   , pppoe->mru
					   , VTY_NEWLINE);
			if (pppoe->vmac_hbits)
				vty_out(vty, " pppoe vmac-hbits %d%s"
					   , pppoe->vmac_hbits
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_GTP_USERNAME_BIT, &pppoe->flags))
				vty_out(vty, " pppoe authentication pap gtp-username%s"
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags))
				vty_out(vty, " pppoe authentication pap username %s%s"
					   , pppoe->pap_username
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_STATIC_PASSWD_BIT, &pppoe->flags))
				vty_out(vty, " pppoe authentication pap password %s%s"
					   , pppoe->pap_passwd
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_IPV6CP_DISABLE_BIT, &pppoe->flags))
				vty_out(vty, " pppoe ipv6cp disable%s"
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_KEEPALIVE_BIT, &pppoe->flags))
				vty_out(vty, " pppoe keepalive %d%s"
					   , pppoe->keepalive
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags))
				vty_out(vty, " pppoe padi-fast-retry%s"
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_LCP_TIMEOUT_BIT, &pppoe->flags))
				vty_out(vty, " pppoe lcp-timeout %d%s"
					   , pppoe->lcp_timeout
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_LCP_MAX_TERMINATE_BIT, &pppoe->flags))
				vty_out(vty, " pppoe lcp-max-terminate %d%s"
					   , pppoe->lcp_max_terminate
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_LCP_MAX_CONFIGURE_BIT, &pppoe->flags))
				vty_out(vty, " pppoe lcp-max-configure %d%s"
					   , pppoe->lcp_max_configure
					   , VTY_NEWLINE);
			if (__test_bit(PPPOE_FL_LCP_MAX_FAILURE_BIT, &pppoe->flags))
				vty_out(vty, " pppoe lcp-max-failture %d%s"
					   , pppoe->lcp_max_failure
					   , VTY_NEWLINE);
		}
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
	install_node(&ip_vrf_node);
	install_element(CONFIG_NODE, &ip_vrf_cmd);
	install_element(CONFIG_NODE, &no_ip_vrf_cmd);

	install_default(IP_VRF_NODE);
	install_element(IP_VRF_NODE, &ip_vrf_description_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_gtp_udp_port_learning_cmd);
	install_element(IP_VRF_NODE, &no_ip_vrf_gtp_udp_port_learning_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_encapsulation_dot1q_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_decapsulation_dot1q_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_encapsulation_ipip_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_ac_name_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_service_name_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_mru_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_vmac_hbits_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_auth_pap_gtp_username_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_auth_pap_username_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_auth_pap_passwd_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_ipv6cp_disable_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_keepalive_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_padi_fast_retry_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_lcp_timeout_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_lcp_max_terminate_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_lcp_max_configure_cmd);
	install_element(IP_VRF_NODE, &ip_vrf_pppoe_lcp_max_failure_cmd);

	return 0;
}
