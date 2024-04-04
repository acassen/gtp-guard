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

#ifndef _GTP_VRF_H
#define _GTP_VRF_H

enum ip_vrf_flags {
	IP_VRF_FL_ENCAP_DOT1Q_BIT,
	IP_VRF_FL_DECAP_DOT1Q_BIT,
	IP_VRF_FL_IPIP_BIT,
	IP_VRF_FL_PPPOE_BIT,
	IP_VRF_FL_PPPOE_BUNDLE_BIT,
	IP_VRF_FL_DIRECT_TX_BIT,
	IP_VRF_FL_GTP_UDP_PORT_LEARNING_BIT,
};

typedef struct _ip_vrf {
	uint32_t		id;
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	uint16_t		encap_vlan_id;
	uint16_t		decap_vlan_id;
	gtp_iptnl_t		iptnl;
	gtp_pppoe_t		*pppoe;
	gtp_pppoe_bundle_t	*pppoe_bundle;

	list_head_t		next;

	unsigned long		flags;
} ip_vrf_t;


/* Prototypes */
extern ip_vrf_t *gtp_ip_vrf_get(const char *);
extern ip_vrf_t *gtp_ip_vrf_alloc(const char *);
extern int gtp_ip_vrf_destroy(ip_vrf_t *);
extern int gtp_vrf_init(void);
extern int gtp_vrf_destroy(void);
extern int gtp_vrf_vty_init(void);

#endif
