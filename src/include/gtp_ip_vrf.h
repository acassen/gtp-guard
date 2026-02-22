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
#pragma once

#include "gtp_iptnl.h"
#include "pppoe.h"

enum ip_vrf_flags {
	IP_VRF_FL_ENCAP_DOT1Q_BIT,
	IP_VRF_FL_DECAP_DOT1Q_BIT,
	IP_VRF_FL_IPIP_BIT,
	IP_VRF_FL_PPPOE_BIT,
	IP_VRF_FL_PPPOE_BUNDLE_BIT,
	IP_VRF_FL_DIRECT_TX_BIT,
	IP_VRF_FL_GTP_UDP_PORT_LEARNING_BIT,
};

struct ip_vrf {
	uint32_t		id;
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	uint16_t		encap_vlan_id;
	uint16_t		decap_vlan_id;
	struct gtp_iptnl	iptnl;
	struct pppoe		*pppoe;
	struct pppoe_bundle	*pppoe_bundle;

	struct list_head	next;

	unsigned long		flags;
};


/* Prototypes */
struct ip_vrf *gtp_ip_vrf_get(const char *);
struct ip_vrf *gtp_ip_vrf_alloc(const char *);
int gtp_ip_vrf_destroy(struct ip_vrf *);
int gtp_vrf_init(void);
int gtp_vrf_destroy(void);
