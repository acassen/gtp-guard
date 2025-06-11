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
#include <net/ethernet.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


static int gtp_config_pppoe_write(vty_t *vty);
static int gtp_config_pppoe_bundle_write(vty_t *vty);
cmd_node_t pppoe_node = {
	.node = PPPOE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(pppoe)# ",
	.config_write = gtp_config_pppoe_write,
};
cmd_node_t pppoe_bundle_node = {
	.node = PPPOE_BUNDLE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(pppoe-bundle)# ",
	.config_write = gtp_config_pppoe_bundle_write,
};

/*
 *	PPPoE Commands
 */
DEFUN(pppoe,
      pppoe_cmd,
      "pppoe STRING",
      "Configure PPPoE Instance\n"
      "PPPoE Instance Name")
{
	gtp_pppoe_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_pppoe_init(argv[0]);
	if (!new) {
		if (errno == EEXIST)
			vty_out(vty, "%% PPPoE instance %s already exist !!!%s"
				   , argv[0], VTY_NEWLINE);
		else
			vty_out(vty, "%% PPPoE Error allocating instance %s !!!%s"
				   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}


	vty->node = PPPOE_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_pppoe,
      no_pppoe_cmd,
      "no pppoe STRING",
      "Destroy PPPoe\n"
      "PPPoE Instance Name")
{
	gtp_pppoe_t *pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	pppoe = gtp_pppoe_get_by_name(argv[0]);
	if (!pppoe) {
		vty_out(vty, "%% unknown PPPoE instance %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_pppoe_release(pppoe);
	return CMD_SUCCESS;
}

DEFUN(pppoe_interface,
      pppoe_interface_cmd,
      "interface STRING [rps-bits [INTEGER]]",
      "Interface\n"
      "IFNAME\n"
      "RPS bits for pthread workers\n"
      "max bits of pthread workers (default = "STR(GTP_PPPOE_RPS_BITS)" bits)\n")
{
	gtp_pppoe_t *pppoe = vty->index;
	int err, rps_bits, rps_size = 1;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = gtp_pppoe_interface_init(pppoe, argv[0]);
	if (err) {
		vty_out(vty, "%% Error intializing interface %s (%s)%s"
			   , argv[0]
			   , (errno == EINVAL) ? "Invalid ifname" : "PPPoE already running"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* PPPoE ingress thread count built from rps-bits */
	if (__test_bit(GTP_FL_PPP_RPS_LOADED_BIT, &daemon_data->flags)) {
		rps_size = GTP_PPPOE_RPS_SIZE;
		if (argc == 3) {
			VTY_GET_INTEGER_RANGE("rps-bits", rps_bits, argv[2], 1, 7);
			rps_size = 1 << rps_bits;
		}
	}

	pppoe->thread_cnt = rps_size;
	err = gtp_pppoe_start(pppoe);
	if (err) {
		vty_out(vty, "%% Error starting PPPoE on interface %s!%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(pppoe_monitor_vrrp,
      pppoe_monitor_vrrp_cmd,
      "monitor-vrrp <3-15>",
      "VRRP Traffic monitoring\n"
      "Timeout to transit into FAULT state\n")
{
	gtp_pppoe_t *pppoe = vty->index;
	int credit, err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Credit handling */
	pppoe->credit = 3 * TIMER_HZ;
	VTY_GET_INTEGER_RANGE("Timeout", credit, argv[0], 3, 15);
	pppoe->credit = credit * TIMER_HZ;
	pppoe->expire = timer_long(time_now) + pppoe->credit;

	err = gtp_pppoe_monitor_vrrp_init(pppoe);
	if (err) {
		vty_out(vty, "%% Error VRRP Monitoring on interface:%s (%s)%s"
			   , pppoe->ifname
			   , strerror(errno)
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_VRRP_MONITOR_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_ac_name,
      pppoe_ac_name_cmd,
      "access-concentrator-name STRING",
      "Access Concentrator Name\n"
      "String\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pppoe->ac_name_len = bsd_strlcpy(pppoe->ac_name, argv[0], PPPOE_NAMELEN);
	return CMD_SUCCESS;
}


DEFUN(pppoe_strict_ac_name,
      pppoe_strict_ac_name_cmd,
      "strict-ac-name",
      "Discard incoming PPPoE packet if ac_name miss-match our\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (!pppoe->ac_name[0]) {
		vty_out(vty, "%% access-concentrator-name not configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_STRICT_AC_NAME_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_service_name,
      pppoe_service_name_cmd,
      "service-name STRING",
      "Service Name\n"
      "String\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(pppoe->service_name, argv[0], PPPOE_NAMELEN);
	return CMD_SUCCESS;
}

DEFUN(pppoe_vendor_specific_bbf,
      pppoe_vendor_specific_bbf_cmd,
      "vendor-specific-bbf",
      "Vendor Specific BroadBandForum\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	__set_bit(PPPOE_FL_VENDOR_SPECIFIC_BBF_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_mru,
      pppoe_mru_cmd,
      "maximum-receive-unit INTEGER",
      "Maximum Receive Unit\n"
      "Integer\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pppoe->mru = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(pppoe_vmac_hbits,
      pppoe_vmac_hbits_cmd,
      "vmac-hbits INTEGER",
      "Virtual MAC Address first 4bits\n"
      "hbits\n")
{
	gtp_pppoe_t *pppoe = vty->index;
	uint8_t hbits;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("hbits", hbits, argv[0], 0, 15);
	pppoe->vmac_hbits = hbits << 4;
	return CMD_SUCCESS;
}

DEFUN(pppoe_auth_pap_gtp_username_tpl0,
      pppoe_auth_pap_gtp_username_tpl0_cmd,
      "authentication pap gtp-username imsi+mei@apn",
      "Authentication method\n"
      "Password Authentication Protocol\n"
      "Username built from GTP imsi+mei@apn\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (__test_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags)) {
		vty_out(vty, "%% Static username already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_0_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_auth_pap_gtp_username_tpl1,
      pppoe_auth_pap_gtp_username_tpl1_cmd,
      "authentication pap gtp-username imsi@apn",
      "Authentication method\n"
      "Password Authentication Protocol\n"
      "Username built from GTP imsi@apn\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (__test_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags)) {
		vty_out(vty, "%% Static username already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_1_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_auth_pap_username,
      pppoe_auth_pap_username_cmd,
      "authentication pap username STRING",
      "Authentication method\n"
      "Password Authentication Protocol\n"
      "Username\n"
      "String\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_0_BIT, &pppoe->flags)) {
		vty_out(vty, "%% GTP username already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(pppoe->pap_username, argv[0], PPPOE_NAMELEN);
	__set_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_auth_pap_passwd,
      pppoe_auth_pap_passwd_cmd,
      "authentication pap password STRING",
      "Authentication method\n"
      "Password Authentication Protocol\n"
      "Password\n"
      "String\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(pppoe->pap_passwd, argv[0], PPPOE_NAMELEN);
	__set_bit(PPPOE_FL_STATIC_PASSWD_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_ipv6cp_disable,
      pppoe_ipv6cp_disable_cmd,
      "ipv6cp disable",
      "IPv6 Control Protocol\n"
      "Disable\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	__set_bit(PPPOE_FL_IPV6CP_DISABLE_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_keepalive,
      pppoe_keepalive_cmd,
      "keepalive INTEGER",
      "PPP Keepalive interval\n"
      "Number of seconds\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_KEEPALIVE_BIT, &pppoe->flags);
	pppoe->keepalive = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(pppoe_padi_fast_retry,
      pppoe_padi_fast_retry_cmd,
      "padi-fast-retry",
      "PADI Fast Retry (1s)\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	__set_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags);
	return CMD_SUCCESS;
}

DEFUN(pppoe_lcp_timeout,
      pppoe_lcp_timeout_cmd,
      "lcp-timeout INTEGER",
      "PPP lcp-timeout\n"
      "Number of seconds\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_TIMEOUT_BIT, &pppoe->flags);
	pppoe->lcp_timeout = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(pppoe_lcp_max_terminate,
      pppoe_lcp_max_terminate_cmd,
      "lcp-max-terminate INTEGER",
      "PPP lcp-max-terminate request\n"
      "Number\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_MAX_TERMINATE_BIT, &pppoe->flags);
	pppoe->lcp_max_terminate = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(pppoe_lcp_max_configure,
      pppoe_lcp_max_configure_cmd,
      "lcp-max-configure INTEGER",
      "PPP lcp-max-configure request\n"
      "Number\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_MAX_CONFIGURE_BIT, &pppoe->flags);
	pppoe->lcp_max_configure = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

DEFUN(pppoe_lcp_max_failure,
      pppoe_lcp_max_failure_cmd,
      "lcp-max-failure INTEGER",
      "PPP lcp-max-failure\n"
      "Number\n")
{
	gtp_pppoe_t *pppoe = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PPPOE_FL_LCP_MAX_FAILURE_BIT, &pppoe->flags);
	pppoe->lcp_max_failure = strtoul(argv[0], NULL, 10);
	return CMD_SUCCESS;
}

/*
 *	PPPoE Bundle Commands
 */
DEFUN(pppoe_bundle,
      pppoe_bundle_cmd,
      "pppoe-bundle STRING",
      "Configure PPPoE Bundle\n"
      "PPPoE Bundle Name")
{
	gtp_pppoe_bundle_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_pppoe_bundle_init(argv[0]);
	if (!new) {
		if (errno == EEXIST)
			vty_out(vty, "%% PPPoE bundle %s already exist !!!%s"
				   , argv[0], VTY_NEWLINE);
		else
			vty_out(vty, "%% PPPoE Error allocating bundle %s !!!%s"
				   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}


	vty->node = PPPOE_BUNDLE_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_pppoe_bundle,
      no_pppoe_bundle_cmd,
      "no pppoe-bundle STRING",
      "Destroy PPPoe Bundle\n"
      "PPPoE Bundle Name")
{
	gtp_pppoe_bundle_t *bundle;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	bundle = gtp_pppoe_bundle_get_by_name(argv[0]);
	if (!bundle) {
		vty_out(vty, "%% unknown PPPoE bundle %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_pppoe_bundle_release(bundle);
	return CMD_SUCCESS;
}

static gtp_pppoe_t *
gtp_pppoe_bundle_instance_prepare(vty_t *vty, gtp_pppoe_bundle_t *bundle, int argc, const char **argv)
{
	gtp_pppoe_t *pppoe;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return NULL;
	}

	pppoe = gtp_pppoe_get_by_name(argv[0]);
	if (!pppoe) {
		vty_out(vty, "%% Unknown PPPoe Instance %s%s"
			   , argv[0]
			   , VTY_NEWLINE);
		return NULL;
	}

	if (bundle->instance_idx >= PPPOE_BUNDLE_MAXSIZE) {
		vty_out(vty, "%% PPPoe Bundle no more Instance available%s"
			   , VTY_NEWLINE);
		return NULL;
	}

	if (pppoe->bundle) {
		vty_out(vty, "%% PPPoe Instance:%s already part of pppoe-bundle:%s%s"
			   , pppoe->name, pppoe->bundle->name
			   , VTY_NEWLINE);
		return NULL;
	}

	/* First PPPoE instance in bundle is primary, followings are secondary */
	if (!bundle->instance_idx)
		__set_bit(PPPOE_FL_PRIMARY_BIT, &pppoe->flags);
	else
		__set_bit(PPPOE_FL_SECONDARY_BIT, &pppoe->flags);

	bundle->pppoe[bundle->instance_idx++] = pppoe;
	pppoe->bundle = bundle;
	return pppoe;
}

DEFUN(pppoe_bundle_instance,
      pppoe_bundle_instance_cmd,
      "instance STRING",
      "PPPoE Instance\n"
      "Name\n")
{
	gtp_pppoe_bundle_t *bundle = vty->index;
	gtp_pppoe_t *pppoe;

	pppoe = gtp_pppoe_bundle_instance_prepare(vty, bundle, argc, argv);
	if (!pppoe)
		return CMD_WARNING;

	log_message(LOG_INFO, "PPPoE:%s is %s"
			    , pppoe->name
			    , __test_bit(PPPOE_FL_PRIMARY_BIT, &pppoe->flags) ? "primary" : "secondary");
	return CMD_SUCCESS;
}

DEFUN(pppoe_bundle_ignore_ingress_ppp_brd,
      pppoe_bundle_ignore_ingress_ppp_brd_cmd,
      "ignore-ingress-ppp-brd",
      "Ignore Ingress PPP broadcast messages\n")
{
	gtp_pppoe_bundle_t *bundle = vty->index;
	__set_bit(PPPOE_FL_IGNORE_INGRESS_PPP_BRD_BIT, &bundle->flags);
	return CMD_SUCCESS;
}

DEFUN(no_pppoe_bundle_ignore_ingress_ppp_brd,
      no_pppoe_bundle_ignore_ingress_ppp_brd_cmd,
      "no ignore-ingress-ppp-brd",
      "Allow Ingress PPP broadcast messages\n")
{
	gtp_pppoe_bundle_t *bundle = vty->index;
	__clear_bit(PPPOE_FL_IGNORE_INGRESS_PPP_BRD_BIT, &bundle->flags);
	return CMD_SUCCESS;
}

/*
 *	Show commands
 */
static int
gtp_pppoe_worker_vty(vty_t *vty, gtp_pppoe_worker_t *w)
{
	gtp_stats_pkt_t *rx = &w->rx_stats;
	gtp_stats_pkt_t *tx = &w->rx_stats;

	vty_out(vty, "   #%.2d: rx_packets:%ld rx_bytes:%ld tx_packets:%ld tx_bytes:%ld%s"
		   , w->id, rx->pkts, rx->bytes, tx->pkts, tx->bytes
		   , VTY_NEWLINE);
	return 0;
}

static int
gtp_pppoe_workers_vty(vty_t *vty, const char *desc, gtp_pppoe_worker_t *w, int count)
{
	int i;

	vty_out(vty, "  %s:%s", desc, VTY_NEWLINE);
	for (i = 0; i < count; i++)
		gtp_pppoe_worker_vty(vty, &w[i]);

	return 0;
}

static int
gtp_pppoe_vty(vty_t *vty, gtp_pppoe_t *pppoe)
{
	if (!pppoe)
		return -1;

	vty_out(vty, " PPPoE(%s): ifname %s (ifindex:%d) sessions:%d%s"
		   , pppoe->name, pppoe->ifname, pppoe->ifindex, pppoe->session_count
		   , VTY_NEWLINE);
	gtp_pppoe_workers_vty(vty, "Discovery channel"
				 , pppoe->worker_disc, pppoe->thread_cnt);
	gtp_pppoe_workers_vty(vty, "Session channel"
				 , pppoe->worker_ses, pppoe->thread_cnt);
	return 0;
}

DEFUN(show_pppoe,
      show_pppoe_cmd,
      "show pppoe [STRING]",
      SHOW_STR
      "PPP Over Ethernet\n"
      "Instance name")
{
	gtp_pppoe_t *pppoe;
	const char *name = NULL;

	if (list_empty(&daemon_data->pppoe)) {
		vty_out(vty, "%% No PPPoE instance configured...");
		return CMD_SUCCESS;
	}

	if (argc == 1)
		name = argv[0];

	list_for_each_entry(pppoe, &daemon_data->pppoe, next) {
		if (name && strncmp(pppoe->name, name, GTP_NAME_MAX_LEN))
			continue;

		gtp_pppoe_vty(vty, pppoe);
	}

	return CMD_SUCCESS;
}

/* Configuration writer */
static int
gtp_config_pppoe_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->pppoe;
	gtp_pppoe_t *pppoe;

	list_for_each_entry(pppoe, l, next) {
		vty_out(vty, "pppoe %s%s", pppoe->name, VTY_NEWLINE);
		vty_out(vty, " interface %s", pppoe->name);
		if (pppoe->thread_cnt != GTP_PPPOE_RPS_SIZE)
			vty_out(vty, " rps-bits %d", __builtin_ctz(pppoe->thread_cnt));
		vty_out(vty, "%s", VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_VRRP_MONITOR_BIT, &pppoe->flags))
			vty_out(vty, " monitor-vrrp %ld%s", pppoe->credit / TIMER_HZ, VTY_NEWLINE);
		if (pppoe->ac_name[0])
			vty_out(vty, " access-concentrator-name %s%s", pppoe->ac_name, VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_STRICT_AC_NAME_BIT, &pppoe->flags))
			vty_out(vty, " strict-ac-name%s", VTY_NEWLINE);
		if (pppoe->service_name[0])
			vty_out(vty, " service-name %s%s", pppoe->service_name, VTY_NEWLINE);
		if (pppoe->mru)
			vty_out(vty, " maximum-receive-unit %d%s", pppoe->mru, VTY_NEWLINE);
		if (pppoe->vmac_hbits)
			vty_out(vty, " vmac-hbits %d%s", pppoe->vmac_hbits >> 4, VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_0_BIT, &pppoe->flags))
			vty_out(vty, " authentication pap gtp-username imsi+mei@apn%s"
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_1_BIT, &pppoe->flags))
			vty_out(vty, " authentication pap gtp-username imsi@apn%s"
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_VENDOR_SPECIFIC_BBF_BIT, &pppoe->flags))
			vty_out(vty, " vendor-specific-bbf%s", VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags))
			vty_out(vty, " authentication pap username %s%s"
				   , pppoe->pap_username
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_STATIC_PASSWD_BIT, &pppoe->flags))
			vty_out(vty, " authentication pap password %s%s"
				   , pppoe->pap_passwd
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_IPV6CP_DISABLE_BIT, &pppoe->flags))
			vty_out(vty, " ipv6cp disable%s", VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_KEEPALIVE_BIT, &pppoe->flags))
			vty_out(vty, " keepalive %d%s"
				   , pppoe->keepalive
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags))
			vty_out(vty, " padi-fast-retry%s", VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_LCP_TIMEOUT_BIT, &pppoe->flags))
			vty_out(vty, " lcp-timeout %d%s"
				   , pppoe->lcp_timeout
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_LCP_MAX_TERMINATE_BIT, &pppoe->flags))
			vty_out(vty, " lcp-max-terminate %d%s"
				   , pppoe->lcp_max_terminate
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_LCP_MAX_CONFIGURE_BIT, &pppoe->flags))
			vty_out(vty, " lcp-max-configure %d%s"
				   , pppoe->lcp_max_configure
				   , VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_LCP_MAX_FAILURE_BIT, &pppoe->flags))
			vty_out(vty, " lcp-max-failture %d%s"
				   , pppoe->lcp_max_failure
				   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

static int
gtp_config_pppoe_bundle_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->pppoe_bundle;
	gtp_pppoe_bundle_t *bundle;
	gtp_pppoe_t *pppoe;
	int i;

	list_for_each_entry(bundle, l, next) {
		vty_out(vty, "pppoe-bundle %s%s", bundle->name, VTY_NEWLINE);
		if (__test_bit(PPPOE_FL_IGNORE_INGRESS_PPP_BRD_BIT, &bundle->flags))
			vty_out(vty, " ignore-ingress-ppp-brd%s", VTY_NEWLINE);
		for (i = 0; i < PPPOE_BUNDLE_MAXSIZE && bundle->pppoe[i]; i++) {
			pppoe = bundle->pppoe[i];
			vty_out(vty, " instance %s%s", pppoe->name, VTY_NEWLINE);
		}
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_pppoe_vty_init(void)
{

	/* Install PPPoE commands. */
	install_node(&pppoe_node);
	install_element(CONFIG_NODE, &pppoe_cmd);
	install_element(CONFIG_NODE, &no_pppoe_cmd);

	install_element(PPPOE_NODE, &pppoe_interface_cmd);
	install_element(PPPOE_NODE, &pppoe_monitor_vrrp_cmd);
	install_element(PPPOE_NODE, &pppoe_ac_name_cmd);
	install_element(PPPOE_NODE, &pppoe_service_name_cmd);
	install_element(PPPOE_NODE, &pppoe_vendor_specific_bbf_cmd);
	install_element(PPPOE_NODE, &pppoe_strict_ac_name_cmd);
	install_element(PPPOE_NODE, &pppoe_mru_cmd);
	install_element(PPPOE_NODE, &pppoe_vmac_hbits_cmd);
	install_element(PPPOE_NODE, &pppoe_auth_pap_gtp_username_tpl0_cmd);
	install_element(PPPOE_NODE, &pppoe_auth_pap_gtp_username_tpl1_cmd);
	install_element(PPPOE_NODE, &pppoe_auth_pap_username_cmd);
	install_element(PPPOE_NODE, &pppoe_auth_pap_passwd_cmd);
	install_element(PPPOE_NODE, &pppoe_ipv6cp_disable_cmd);
	install_element(PPPOE_NODE, &pppoe_keepalive_cmd);
	install_element(PPPOE_NODE, &pppoe_padi_fast_retry_cmd);
	install_element(PPPOE_NODE, &pppoe_lcp_timeout_cmd);
	install_element(PPPOE_NODE, &pppoe_lcp_max_terminate_cmd);
	install_element(PPPOE_NODE, &pppoe_lcp_max_configure_cmd);
	install_element(PPPOE_NODE, &pppoe_lcp_max_failure_cmd);

	/* Install PPPoE Bundle commands. */
	install_node(&pppoe_bundle_node);
	install_element(CONFIG_NODE, &pppoe_bundle_cmd);
	install_element(CONFIG_NODE, &no_pppoe_bundle_cmd);

	install_element(PPPOE_BUNDLE_NODE, &pppoe_bundle_instance_cmd);
	install_element(PPPOE_BUNDLE_NODE, &pppoe_bundle_ignore_ingress_ppp_brd_cmd);
	install_element(PPPOE_BUNDLE_NODE, &no_pppoe_bundle_ignore_ingress_ppp_brd_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_pppoe_cmd);
	install_element(ENABLE_NODE, &show_pppoe_cmd);

	return 0;
}
