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

static int apn_config_write(vty_t *vty);
cmd_node_t apn_node = {
	.node = APN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(gtp-apn)# ",
	.config_write = apn_config_write,
};


/*
 *	VTY utilities
 */
static void
gtp_apn_hplmn_vty(vty_t *vty, gtp_apn_t *apn)
{
	gtp_plmn_t *p;

	if (!apn)
		return;

	list_for_each_entry(p, &apn->hplmn, next) {
		vty_out(vty, " hplmn %ld%s"
			   , bcd_plmn_to_int64(p->plmn, GTP_PLMN_MAX_LEN)
			   , VTY_NEWLINE);
	}
}

static int
gtp_apn_vty(gtp_apn_t *apn, void *arg)
{
	vty_t *vty = arg;
	gtp_naptr_show(vty, apn);
	gtp_apn_hplmn_vty(vty, apn);
	return 0;
}

static int
gtp_apn_show(vty_t *vty, gtp_apn_t *apn)
{
	if (apn) {
		gtp_naptr_show(vty, apn);
		gtp_apn_hplmn_vty(vty, apn);
		return 0;
	}

	gtp_apn_foreach(gtp_apn_vty, vty);
	return 0;
}


/*
 *	VTY Command
 */
DEFUN(apn,
      apn_cmd,
      "access-point-name STRING",
      "Configure Access Point Name data\n")
{
	gtp_apn_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_apn_get(argv[0]);
	if (new) {
		vty->node = APN_NODE;
		vty->index = new;
		return CMD_SUCCESS;
	}

	new = gtp_apn_alloc(argv[0]);
	vty->node = APN_NODE;
	vty->index = new;

	return CMD_SUCCESS;
}

DEFUN(apn_realm,
      apn_realm_cmd,
      "realm STRING",
      "Set Global PDN Realm\n"
      "name\n")
{
        gtp_apn_t *apn = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(apn->realm, argv[0], GTP_REALM_LEN - 1);
	apn_resolv_cache_realloc(apn);

	return CMD_SUCCESS;
}

DEFUN(apn_realm_dynamic,
      apn_realm_dynamic_cmd,
      "realm-dynamic",
      "Enable dynamic resolution\n")
{
        gtp_apn_t *apn = vty->index;

	__set_bit(GTP_APN_FL_REALM_DYNAMIC, &apn->flags);
	return CMD_SUCCESS;
}

DEFUN(apn_nameserver,
      apn_nameserver_cmd,
      "nameserver (A.B.C.D|X:X:X:X)",
      "Set Global PDN nameserver\n"
      "IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	gtp_apn_t *apn = vty->index;
	struct sockaddr_storage *addr = &apn->nameserver;
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

DEFUN(apn_nameserver_bind,
      apn_nameserver_bind_cmd,
      "nameserver-bind (A.B.C.D|X:X:X:X) port <1024-65535> [persistent]",
      "Set Global PDN nameserver binding Address\n"
      "IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "UDP Port\n"
      "Number\n"
      "Persistent connection\n")
{
	gtp_apn_t *apn = vty->index;
	struct sockaddr_storage *addr = &apn->nameserver_bind;
	int ret, port;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);

	ret = inet_stosockaddr(argv[0], port, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	if (argc == 3) {
		if (strstr(argv[2], "persistent"))
			__set_bit(GTP_RESOLV_FL_CNX_PERSISTENT, &apn->flags);
	}

	return CMD_SUCCESS;
}

DEFUN(apn_nameserver_timeout,
      apn_nameserver_timeout_cmd,
      "nameserver-timeout INTEGER",
      "Define nameserver operation timeout in seconds\n"
      "seconds\n")
{
	gtp_apn_t *apn = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn->nameserver_timeout = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(apn_resolv_max_retry,
      apn_resolv_max_retry_cmd,
      "resolv-max-retry INTEGER",
      "Define maximum number of retry per nameserver query\n"
      "retry count\n")
{
	gtp_apn_t *apn = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn->resolv_max_retry = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(apn_resolv_cache_update,
      apn_resolv_cache_update_cmd,
      "resolv-cache-update <5-86400>",
      "Define periodic cache updates\n"
      "seconds\n")
{
	gtp_apn_t *apn = vty->index;
	int sec = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Seconds", sec, argv[0], 5, 86400);
	apn->resolv_cache_update = sec;
	__set_bit(GTP_RESOLV_FL_CACHE_UPDATE, &apn->flags);

	/* Launch dedicated task since resolver use its own internal network
	 * stuff and must be registered ouside our I/O MUX */
	pthread_mutex_init(&apn->cache_mutex, NULL);
	pthread_cond_init(&apn->cache_cond, NULL);
	pthread_create(&apn->cache_task, NULL, apn_resolv_cache_task, apn);

	return CMD_SUCCESS;
}

DEFUN(apn_resolv_cache_reload,
      apn_resolv_cache_reload_cmd,
      "resolv-cache-reload STRING",
      "Force resolv cache update\n"
      "access-point-name string")
{
	gtp_apn_t *apn;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn = gtp_apn_get(argv[0]);
	if (!apn) {
		vty_out(vty, "%% unknown access-point-name %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_RESOLV_FL_CACHE_UPDATE, &apn->flags)) {
		apn_resolv_cache_signal(apn);
	} else {
		apn_resolv_cache_realloc(apn);
	}

	return CMD_SUCCESS;
}

DEFUN(apn_tag_uli_with_serving_node_ip4,
      apn_tag_uli_with_serving_node_ip4_cmd,
      "tag-uli-with-serving-node-ip4 [INTEGER]",
      "Override ULI eCGI/CGI to include serving node IPv4 address\n"
      "PLMN string")
{
	gtp_apn_t *apn = vty->index;
	uint8_t plmn[GTP_PLMN_MAX_LEN];
	gtp_plmn_t *egci_plmn = &apn->egci_plmn;
	int err;

	memset(egci_plmn->plmn, 0xff, GTP_PLMN_MAX_LEN);
	if (argc == 1) {
		err = str_plmn_to_bcd(argv[0], plmn, GTP_PLMN_MAX_LEN);
		if (err) {
			vty_out(vty, "%% invalid plmn:%s%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}

		memcpy(egci_plmn->plmn, plmn, GTP_PLMN_MAX_LEN);
		__set_bit(GTP_APN_FL_TAG_ULI_WITH_EGCI_PLMN, &apn->flags);
	}

	__set_bit(GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4, &apn->flags);
	return CMD_SUCCESS;
}

DEFUN(apn_no_tag_uli_with_serving_node_ip4,
      apn_no_tag_uli_with_serving_node_ip4_cmd,
      "no tag-uli-with-serving-node-ip4",
      "Override ULI eCGI/CGI to include serving node IPv4 address\n")
{
	gtp_apn_t *apn = vty->index;

	__clear_bit(GTP_APN_FL_TAG_ULI_WITH_EGCI_PLMN, &apn->flags);
	__clear_bit(GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4, &apn->flags);
	return CMD_SUCCESS;
}

static int
apn_service_selection_config_write(vty_t *vty, gtp_apn_t *apn)
{
	gtp_service_t *service;

	list_for_each_entry(service, &apn->service_selection, next) {
		if (service->prio)
			vty_out(vty, " service-selection %s prio %d%s"
				   , service->str
				   , service->prio
				   , VTY_NEWLINE);
		else
			vty_out(vty, " service-selection %s%s"
				   , service->str
				   , VTY_NEWLINE);
	}

	return 0;
}

DEFUN(apn_service_selection,
      apn_service_selection_cmd,
      "service-selection STRING prio INTEGER",
      "Force service selection\n"
      "service\n"
      "priority\n")
{
	gtp_apn_t *apn = vty->index;
	int prio = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc >= 1)
		prio = atoi(argv[1]);

	gtp_service_alloc(apn, argv[0], prio);
	__set_bit(GTP_RESOLV_FL_SERVICE_SELECTION, &apn->flags);

	return CMD_SUCCESS;
}

DEFUN(apn_imsi_match,
      apn_imsi_match_cmd,
      "imsi-prefix-match STRING rewrite STRING",
      "IMSI rewriting based on prefix matching\n"
      "imsi prefix match\n"
      "imsi prefix rewrite\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_rewrite_rule_t *rule;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rule = gtp_rewrite_rule_alloc(apn, &apn->imsi_match);
	stringtohex(argv[0], 15, rule->match, GTP_MATCH_MAX_LEN);
	swapbuffer((uint8_t *)rule->match, 8, (uint8_t *)rule->match);
	rule->match_len = strlen(argv[0]);
	stringtohex(argv[1], 15, rule->rewrite, GTP_MATCH_MAX_LEN);
	swapbuffer((uint8_t *)rule->rewrite, 8, (uint8_t *)rule->rewrite);
	rule->rewrite_len = strlen(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(apn_oi_match,
      apn_oi_match_cmd,
      "apn-oi-match STRING rewrite STRING",
      "APN OI rewriting based on prefix matching\n"
      "OI match\n"
      "OI rewrite\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_rewrite_rule_t *rule;
	int match_label_cnt, rewrite_label_cnt;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strlen(argv[0]) != strlen(argv[1])) {
		vty_out(vty, "%% prefix match and rewrite MUST have the same length%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	match_label_cnt = gtp_ie_apn_labels_cnt(argv[0], strlen(argv[0]));
	rewrite_label_cnt = gtp_ie_apn_labels_cnt(argv[1], strlen(argv[1]));
	if (match_label_cnt != rewrite_label_cnt) {
		vty_out(vty, "%% match and rewrite MUST have the same label count%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rule = gtp_rewrite_rule_alloc(apn, &apn->oi_match);
	strncpy(rule->match, argv[0], GTP_MATCH_MAX_LEN-1);
	strncpy(rule->rewrite, argv[1], GTP_MATCH_MAX_LEN-1);

	return CMD_SUCCESS;
}

DEFUN(apn_session_lifetime,
      apn_session_lifetime_cmd,
      "session-lifetime <5-864000>",
      "Define GTP session lifetime\n"
      "seconds\n")
{
	gtp_apn_t *apn = vty->index;
	int sec = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Seconds", sec, argv[0], 5, 864000);
	apn->session_lifetime = sec;

	return CMD_SUCCESS;
}

DEFUN(apn_eps_bearer_id,
      apn_eps_bearer_id_cmd,
      "eps-bearer-id <0-255>",
      "Define Bearer Context EPS Bearer ID\n"
      "INTEGER\n")
{
	gtp_apn_t *apn = vty->index;
	uint8_t id = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("eps-bearer-id", id, argv[0], 0, 255);
	apn->eps_bearer_id = id;

	return CMD_SUCCESS;
}

DEFUN(apn_restriction,
      apn_restriction_cmd,
      "restriction <0-255>",
      "Define Restriction\n"
      "INTEGER\n")
{
	gtp_apn_t *apn = vty->index;
	uint8_t value = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("restriction", value, argv[0], 0, 255);
	apn->restriction = value;

	return CMD_SUCCESS;
}


static const struct {
	char *vty_str;
	char *description;
} apn_indication_fl[32] = {
	{ "CPSR" ,	"CS to PS SRVCC Indication"				},
	{ "CLII" ,	"Change of Location Information Indication"		},
	{ "CSFBI" ,	"CSFB Indication"					},
	{ "PPSI" ,	"PDN Pause Support Indication"				},
	{ "PPON" ,	"PDN Pause On Indication"				},
	{ "PPOFF" ,	"PDN Pause Off Indication"				},
	{ "ARRL" ,	"Abnormal Release of Radio Link"			},
	{ "CPRAI" ,	"Change of Presence Reporting Area Information"		},
	{ "CCRSI" ,	"CSG Change Reporting support Indication"		},
	{ "ISRAU" ,	"ISR is activated for the UE"				},
	{ "MBMDT" ,	"Management Based MDT allowed Flag"			},
	{ "S4AF" ,	"Static IPv4 Address Flag"				},
	{ "S6AF" ,	"Static IPv6 Address Flag"				},
	{ "SRNI" ,	"SGW Restoration Needed Indication"			},
	{ "PBIC" ,	"Propagate BBAI Information Change"			},
	{ "RetLoc" ,	"Retrieve Location Indication Flag"			},
	{ "MSV" ,	"MS Validated"						},
	{ "SI" ,	"Scope Indication"					},
	{ "PT" ,	"Protocol Type"						},
	{ "PS" ,	"Piggybacking Supported"				},
	{ "CRSI" ,	"Change Reporting Support Indication"			},
	{ "CFSI" ,	"Change F-TEID Support Indication"			},
	{ "UIMSI" ,	"Unauthenticated IMSI"					},
	{ "SQCI" ,	"Subscribed QoS Change Indication"			},
	{ "SGWCI" ,	"sGW Change Indication"					},
	{ "ISRAI" ,	"Idle mode Signalling Reduction Activation Indication"	},
	{ "ISRSI" ,	"Idle mode Signalling Reduction Supported Indication"	},
	{ "OI" ,	"Operation Identication"				},
	{ "DFI" ,	"Direct Forwarding Indication"				},
	{ "HI" ,	"Handover Indication"					},
	{ "DTF" ,	"Direct Tunnel Flag"					},
	{ "DAF" ,	"Dual Address Bearer Flag"				}
};

static int
apn_indication_bit_get(const char *str, size_t str_len)
{
	int i;

	for (i = 0; i < 32; i++) {
		if (strlen(apn_indication_fl[i].vty_str) != str_len)
			continue;
		if (strncmp(str, apn_indication_fl[i].vty_str, str_len) == 0)
			return i;
	}

	return -1;
}

static int
apn_indication_dump_vty(vty_t *vty)
{
	int i;

	for (i = 0; i < 32; i++)
		vty_out(vty, " %s\t: %s%s"
			   , apn_indication_fl[i].vty_str
			   , apn_indication_fl[i].description
			   , VTY_NEWLINE);

	return 0;
}

static int
apn_indication_config_write(vty_t *vty, gtp_apn_t *apn)
{
	int i;

	for (i = 0; i < 32; i++) {
		if (__test_bit(i, &apn->indication_flags)) {
			vty_out(vty, " indication-flags %s%s"
				   , apn_indication_fl[i].vty_str
				   , VTY_NEWLINE);
		}
	}

	return 0;
}

DEFUN(apn_indication_flags,
      apn_indication_flags_cmd,
      "indication-flags STRING",
      "Define Indication Flags\n")
{
	gtp_apn_t *apn = vty->index;
	int fl;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	fl = apn_indication_bit_get(argv[0], strlen(argv[0]));
	if (fl < 0) {
		vty_out(vty, "%% Unknwon flag:%s%s", argv[0], VTY_NEWLINE);
		vty_out(vty, "%% flags supported are :%s", VTY_NEWLINE);
		apn_indication_dump_vty(vty);
		return CMD_WARNING;
	}

	__set_bit(fl, &apn->indication_flags);
	return CMD_SUCCESS;
}

DEFUN(apn_pco_ipcp_primary_ns,
      apn_pco_ipcp_primary_ns_cmd,
      "protocol-configuration-option ipcp primary-nameserver (A.B.C.D|X:X:X:X)",
      "Procol Configuration Option IPCP Primary Nameserver\n"
      "Internet Protocol Control Protocol\n"
      "Primary Nameserver\n"
      "IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_pco_t *pco = gtp_apn_pco(apn);
	struct sockaddr_storage *addr = &pco->ipcp_primary_ns;
	int ret;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pco) {
		vty_out(vty, "%% Cant allocate PCO for APN:%s%s"
			   , apn->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_stosockaddr(argv[0], 53, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	__set_bit(GTP_PCO_IPCP_PRIMARY_NS, &pco->flags);
	return CMD_SUCCESS;
}

DEFUN(apn_pco_ipcp_secondary_ns,
      apn_pco_ipcp_secondary_ns_cmd,
      "protocol-configuration-option ipcp secondary-nameserver (A.B.C.D|X:X:X:X)",
      "Procol Configuration Option IPCP Secondary Nameserver\n"
      "Internet Protocol Control Protocol\n"
      "Secondary Nameserver\n"
      "IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_pco_t *pco = gtp_apn_pco(apn);
	struct sockaddr_storage *addr = &pco->ipcp_secondary_ns;
	int ret;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pco) {
		vty_out(vty, "%% Cant allocate PCO for APN:%s%s"
			   , apn->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_stosockaddr(argv[0], 53, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	__set_bit(GTP_PCO_IPCP_SECONDARY_NS, &pco->flags);
	return CMD_SUCCESS;
}


static int
apn_pco_ip_ns_config_write(vty_t *vty, list_head_t *l)
{
	gtp_ns_t *ns;

	list_for_each_entry(ns, l, next) {
		vty_out(vty, " protocol-configuration-option ip nameserver %s%s"
			   , inet_sockaddrtos(&ns->addr)
			   , VTY_NEWLINE);
	}

	return 0;
}

static int
apn_pco_config_write(vty_t *vty, gtp_pco_t *pco)
{
	if (!pco)
		return -1;

	if (__test_bit(GTP_PCO_IPCP_PRIMARY_NS, &pco->flags))
		vty_out(vty, " protocol-configuration-option ipcp primary-nameserver %s%s"
			   , inet_sockaddrtos(&pco->ipcp_primary_ns)
			   , VTY_NEWLINE);
	if (__test_bit(GTP_PCO_IPCP_SECONDARY_NS, &pco->flags))
		vty_out(vty, " protocol-configuration-option ipcp secondary-nameserver %s%s"
			   , inet_sockaddrtos(&pco->ipcp_secondary_ns)
			   , VTY_NEWLINE);
	if (__test_bit(GTP_PCO_IP_NS, &pco->flags))
		apn_pco_ip_ns_config_write(vty, &pco->ns);
	if (pco->link_mtu)
		vty_out(vty, " protocol-configuration-option ip link-mtu %d%s"
			   , pco->link_mtu
			   , VTY_NEWLINE);
	if (pco->selected_bearer_control_mode)
		vty_out(vty, " protocol-configuration-option selected-bearer-control-mode %d%s"
			   , pco->selected_bearer_control_mode
			   , VTY_NEWLINE);
	return 0;
}


DEFUN(apn_pco_ip_ns,
      apn_pco_ip_ns_cmd,
      "protocol-configuration-option ip nameserver (A.B.C.D|X:X:X:X)",
      "Procol Configuration Option IP Nameserver\n"
      "Internet Protocol\n"
      "Nameserver\n"
      "IP Address\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_pco_t *pco = gtp_apn_pco(apn);
	gtp_ns_t *new;
	int ret;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pco) {
		vty_out(vty, "%% Cant allocate PCO for APN:%s%s"
			   , apn->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	ret = inet_stosockaddr(argv[0], 53, &new->addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		FREE(new);
		return CMD_WARNING;
	}

	list_add_tail(&new->next, &pco->ns);

	__set_bit(GTP_PCO_IP_NS, &pco->flags);
	return CMD_SUCCESS;
}

DEFUN(apn_pco_ip_link_mtu,
      apn_pco_ip_link_mtu_cmd,
      "protocol-configuration-option ip link-mtu INTEGER",
      "Procol Configuration Option IP Link MTU\n"
      "Internet Protocol\n"
      "MTU\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_pco_t *pco = gtp_apn_pco(apn);

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pco) {
		vty_out(vty, "%% Cant allocate PCO for APN:%s%s"
			   , apn->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	pco->link_mtu = strtoul(argv[0], NULL, 10);

	return CMD_SUCCESS;
}

DEFUN(apn_pco_selected_bearer_control_mode,
      apn_pco_selected_bearer_control_mode_cmd,
      "protocol-configuration-option selected-bearer-control-mode INTEGER",
      "Procol Configuration Option Selected Bearer Control Mode\n"
      "Bearer Control Mode\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_pco_t *pco = gtp_apn_pco(apn);

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!pco) {
		vty_out(vty, "%% Cant allocate PCO for APN:%s%s"
			   , apn->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	pco->selected_bearer_control_mode = strtoul(argv[0], NULL, 10);

	return CMD_SUCCESS;
}

DEFUN(apn_pdn_address_allocation_pool,
      apn_pdn_address_allocation_pool_cmd,
      "pdn-address-allocation-pool local network A.B.C.D netmask A.B.C.D",
      "PDN IP Address Allocation Pool\n"
      "locally configured\n"
      "Network\n"
      "IPv4 Address\n"
      "Netmask\n"
      "IPv4 Address\n")
{
	gtp_apn_t *apn = vty->index;
	uint32_t network, netmask;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (apn->ip_pool) {
		vty_out(vty, "%% IP Pool already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	inet_ston(argv[0], &network);
	inet_ston(argv[1], &netmask);
	apn->ip_pool = gtp_ip_pool_alloc(network, netmask);

	return CMD_SUCCESS;
}

DEFUN(apn_ip_vrf_forwarding,
      apn_ip_vrf_forwarding_cmd,
      "ip vrf forwarding STRING",
      "Define IP VRF forwarding\n")
{
	gtp_apn_t *apn = vty->index;
	ip_vrf_t *vrf;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vrf = gtp_ip_vrf_get(argv[0]);
	if (!vrf) {
		vty_out(vty, "%% Unknwon VRF:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	apn->vrf = vrf;
	return CMD_SUCCESS;
}

DEFUN(apn_gtp_session_uniq_ptype,
      apn_gtp_session_uniq_ptype_cmd,
      "gtp-session-uniq-pdn-type-per-imsi",
      "GTP Session unicity per pdn type and per imsi\n")
{
	gtp_apn_t *apn = vty->index;

	__set_bit(GTP_APN_FL_SESSION_UNIQ_PTYPE, &apn->flags);
	return CMD_SUCCESS;
}

DEFUN(apn_hplmn,
      apn_hplmn_cmd,
      "hplmn INTEGER",
      "Define a HPLMN\n"
      "PLMN\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_plmn_t *hplmn;
	uint8_t plmn[GTP_PLMN_MAX_LEN];
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = str_plmn_to_bcd(argv[0], plmn, GTP_PLMN_MAX_LEN);
	if (err) {
		vty_out(vty, "%% invalid plmn:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	hplmn = gtp_apn_hplmn_get(apn, plmn);
	if (hplmn) {
		vty_out(vty, "%% hplmn:%s already exists%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_apn_hplmn_alloc(apn, plmn);
	return CMD_SUCCESS;
}

DEFUN(no_apn_hplmn,
      no_apn_hplmn_cmd,
      "no hplmn INTEGER",
      "Undefine a HPLMN\n"
      "PLMN\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_plmn_t *hplmn;
	uint8_t plmn[GTP_PLMN_MAX_LEN];
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = str_plmn_to_bcd(argv[0], plmn, GTP_PLMN_MAX_LEN);
	if (err) {
		vty_out(vty, "%% invalid plmn:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	hplmn = gtp_apn_hplmn_get(apn, plmn);
	if (!hplmn) {
		vty_out(vty, "%% unknown hplmn:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_apn_hplmn_del(apn, hplmn);
	return CMD_SUCCESS;
}

DEFUN(apn_cdr_spool,
      apn_cdr_spool_cmd,
      "cdr-spool STRING",
      "Use a CDR Spool\n"
      "Name\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_cdr_spool_t *s;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (apn->cdr_spool) {
		vty_out(vty, "%% cdr-spool already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	s = gtp_cdr_spool_get(argv[0]);
	if (!s) {
		vty_out(vty, "%% unknown cdr-spool %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn->cdr_spool = s;
	return CMD_SUCCESS;
}

DEFUN(no_apn_cdr_spool,
      no_apn_cdr_spool_cmd,
      "no cdr-spool",
      "Use a CDR Spool\n"
      "Name\n")
{
	gtp_apn_t *apn = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!apn->cdr_spool) {
		vty_out(vty, "%% no cdr-spool configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_cdr_spool_put(apn->cdr_spool);
	apn->cdr_spool = NULL;
	return CMD_SUCCESS;
}


/* Show */
DEFUN(show_apn,
      show_apn_cmd,
      "show access-point-name [STRING]",
      SHOW_STR
      "Access-Point-Name ruleset\n")
{
	gtp_apn_t *apn = NULL;

	if (argc >= 1) {
		apn = gtp_apn_get(argv[0]);
		if (!apn) {
			vty_out(vty, "%% Unknown access-point-name:%s%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	gtp_apn_show(vty, apn);

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
apn_config_imsi_match(vty_t *vty, gtp_apn_t *apn)
{
        list_head_t *l = &apn->imsi_match;
	gtp_rewrite_rule_t *rule;
	char match_str[32], rewrite_str[32];
	char match[8], rewrite[8];

        list_for_each_entry(rule, l, next) {
		memset(match_str, 0, 32);
		memset(match, 0, 8);
		memset(rewrite_str, 0, 32);
		memset(rewrite, 0, 8);
		swapbuffer((uint8_t *)rule->match, 8, (uint8_t *)match);
		hextostring(match, rule->match_len / 2, match_str);
		if (!!(rule->match_len % 2))
			match_str[rule->match_len - 1] = hextochar((match[rule->match_len / 2] & 0xf0) >> 4);
		swapbuffer((uint8_t *)rule->rewrite, 8, (uint8_t *)rewrite);
		hextostring(rewrite, rule->rewrite_len / 2, rewrite_str);
		if (!!(rule->rewrite_len % 2))
			rewrite_str[rule->rewrite_len - 1] = hextochar((rewrite[rule->rewrite_len / 2] & 0xf0) >> 4);
		vty_out(vty, " imsi-prefix-match %s rewrite %s%s"
			   , match_str, rewrite_str , VTY_NEWLINE);
	}

	return 0;
}

static int
apn_config_apn_oi_match(vty_t *vty, gtp_apn_t *apn)
{
	list_head_t *l = &apn->oi_match;
	gtp_rewrite_rule_t *rule;

	list_for_each_entry(rule, l, next) {
		vty_out(vty, " apn-oi-match %s rewrite %s%s"
			   , rule->match, rule->rewrite, VTY_NEWLINE);
	}

	return 0;
}

static int
apn_config_write(vty_t *vty)
{
        list_head_t *l = &daemon_data->gtp_apn;
        gtp_apn_t *apn;

        list_for_each_entry(apn, l, next) {
        	vty_out(vty, "access-point-name %s%s", apn->name, VTY_NEWLINE);
		if (apn->nameserver.ss_family)
			vty_out(vty, " nameserver %s%s"
				   , inet_sockaddrtos(&apn->nameserver)
				   , VTY_NEWLINE);
		if (apn->nameserver_bind.ss_family)
			vty_out(vty, " nameserver-bind %s port %d %s%s"
				   , inet_sockaddrtos(&apn->nameserver_bind)
				   , ntohs(inet_sockaddrport(&apn->nameserver_bind))
				   , __test_bit(GTP_RESOLV_FL_CNX_PERSISTENT, &apn->flags) ?
				     "persistent" : ""
				   , VTY_NEWLINE);
		if (apn->nameserver_timeout)
			vty_out(vty, " nameserver-timeout %d%s"
				   , apn->nameserver_timeout
				   , VTY_NEWLINE);
		if (apn->resolv_max_retry)
			vty_out(vty, " resolv-max-retry %d%s"
				   , apn->resolv_max_retry
				   , VTY_NEWLINE);
		if (apn->resolv_cache_update)
			vty_out(vty, " resolv-cache-update %d%s"
				   , apn->resolv_cache_update
				   , VTY_NEWLINE);
		if (__test_bit(GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4, &apn->flags)) {
			vty_out(vty, " tag-uli-with-serving-node-ip4");
			if (__test_bit(GTP_APN_FL_TAG_ULI_WITH_EGCI_PLMN, &apn->flags))
				vty_out(vty, " %ld"
					   , bcd_plmn_to_int64(apn->egci_plmn.plmn, GTP_PLMN_MAX_LEN));
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		if (apn->realm[0])
			vty_out(vty, " realm %s%s", apn->realm, VTY_NEWLINE);
		if (__test_bit(GTP_RESOLV_FL_SERVICE_SELECTION, &apn->flags))
			apn_service_selection_config_write(vty, apn);
		apn_config_imsi_match(vty, apn);
		apn_config_apn_oi_match(vty, apn);
		if (apn->session_lifetime)
			vty_out(vty, " session-lifetime %d%s"
				   , apn->session_lifetime, VTY_NEWLINE);
		if (apn->eps_bearer_id)
			vty_out(vty, " eps-bearer-id %d%s"
				   , apn->eps_bearer_id, VTY_NEWLINE);
		vty_out(vty, " restriction %d%s", apn->restriction, VTY_NEWLINE);
		if (apn->indication_flags)
			apn_indication_config_write(vty, apn);
		apn_pco_config_write(vty, apn->pco);
		if (apn->ip_pool)
			vty_out(vty, " pdn-address-allocation-pool local network %u.%u.%u.%u netmask %u.%u.%u.%u%s"
				   , NIPQUAD(apn->ip_pool->network)
				   , NIPQUAD(apn->ip_pool->netmask)
				   , VTY_NEWLINE);
		if (apn->vrf)
			vty_out(vty, " ip vrf forwarding %s%s"
				   , apn->vrf->name
				   , VTY_NEWLINE);
		if (__test_bit(GTP_APN_FL_SESSION_UNIQ_PTYPE, &apn->flags))
			vty_out(vty, " gtp-session-uniq-pdn-type-per-imsi%s"
				   , VTY_NEWLINE);
		gtp_apn_hplmn_vty(vty, apn);

        	vty_out(vty, "!%s", VTY_NEWLINE);
        }

	return CMD_SUCCESS;
}

/*
 *	VTY init
 */
int
gtp_apn_vty_init(void)
{

	/* Install PDN commands. */
	install_node(&apn_node);
	install_element(CONFIG_NODE, &apn_cmd);

	install_default(APN_NODE);
	install_element(APN_NODE, &apn_nameserver_cmd);
	install_element(APN_NODE, &apn_nameserver_bind_cmd);
	install_element(APN_NODE, &apn_nameserver_timeout_cmd);
	install_element(APN_NODE, &apn_resolv_max_retry_cmd);
	install_element(APN_NODE, &apn_resolv_cache_update_cmd);
	install_element(APN_NODE, &apn_realm_cmd);
	install_element(APN_NODE, &apn_realm_dynamic_cmd);
	install_element(APN_NODE, &apn_tag_uli_with_serving_node_ip4_cmd);
	install_element(APN_NODE, &apn_no_tag_uli_with_serving_node_ip4_cmd);
	install_element(APN_NODE, &apn_service_selection_cmd);
	install_element(APN_NODE, &apn_imsi_match_cmd);
	install_element(APN_NODE, &apn_oi_match_cmd);
	install_element(APN_NODE, &apn_session_lifetime_cmd);
	install_element(APN_NODE, &apn_eps_bearer_id_cmd);
	install_element(APN_NODE, &apn_restriction_cmd);
	install_element(APN_NODE, &apn_indication_flags_cmd);
	install_element(APN_NODE, &apn_pco_ipcp_primary_ns_cmd);
	install_element(APN_NODE, &apn_pco_ipcp_secondary_ns_cmd);
	install_element(APN_NODE, &apn_pco_ip_ns_cmd);
	install_element(APN_NODE, &apn_pco_ip_link_mtu_cmd);
	install_element(APN_NODE, &apn_pco_selected_bearer_control_mode_cmd);
	install_element(APN_NODE, &apn_pdn_address_allocation_pool_cmd);
	install_element(APN_NODE, &apn_ip_vrf_forwarding_cmd);
	install_element(APN_NODE, &apn_gtp_session_uniq_ptype_cmd);
	install_element(APN_NODE, &apn_hplmn_cmd);
	install_element(APN_NODE, &no_apn_hplmn_cmd);
	install_element(APN_NODE, &apn_cdr_spool_cmd);
	install_element(APN_NODE, &no_apn_cdr_spool_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_apn_cmd);
	install_element(ENABLE_NODE, &show_apn_cmd);
	install_element(ENABLE_NODE, &apn_resolv_cache_reload_cmd);

	return 0;
}
