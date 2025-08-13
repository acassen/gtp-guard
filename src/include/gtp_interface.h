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
#pragma once

#include <stdint.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include "inet_utils.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface_rule.h"


typedef struct _gtp_bpf_interface_rule gtp_bpf_interface_rule_t;

/* Flags */
enum gtp_interface_flags {
	GTP_INTERFACE_FL_METRICS_GTP_BIT,
	GTP_INTERFACE_FL_METRICS_PPPOE_BIT,
	GTP_INTERFACE_FL_METRICS_IPIP_BIT,
	GTP_INTERFACE_FL_METRICS_LINK_BIT,
	GTP_INTERFACE_FL_DIRECT_TX_GW_BIT,
	GTP_INTERFACE_FL_CGNAT_NET_IN_BIT,
	GTP_INTERFACE_FL_CGNAT_NET_OUT_BIT,
	GTP_INTERFACE_FL_SHUTDOWN_BIT,
};

/* Interface structure */
struct gtp_interface {
	char			ifname[IF_NAMESIZE];
	uint8_t			hw_addr[ETH_ALEN];
	uint8_t			hw_addr_len;
	uint16_t		vlan_id;
	uint16_t		ip_table;
	struct ip_address	direct_tx_gw;
	uint8_t			direct_tx_hw_addr[ETH_ALEN];
	char			cgn_name[GTP_STR_MAX_LEN];
	int			ifindex;
	char			description[GTP_STR_MAX_LEN];
	struct gtp_bpf_prog	*bpf_prog;
	struct bpf_link		*bpf_xdp_lnk;
	struct bpf_link		*bpf_tc_lnk;

	/* metrics */
	struct rtnl_link_stats64 *link_metrics;

	/* bpf rules */
	struct gtp_bpf_interface_rule *bpf_itf;

	struct list_head	next;

	struct _gtp_interface	*parent;

	int			refcnt;
	unsigned long		flags;
};

/* BPF interface attributes */
struct ll_attr {
	__u16		vlan_id;
	__u16		flags;
} __attribute__ ((__aligned__(8)));


/* Prototypes */
int gtp_interface_metrics_dump(FILE *);
void gtp_interface_metrics_foreach(int (*hdl) (struct gtp_interface *, void *, const char *, int, __u8, __u8),
 				   void *, const char *, int, __u8, __u8);
void gtp_interface_foreach(int (*hdl) (struct gtp_interface *, void *), void *);
void gtp_interface_update_direct_tx_lladdr(struct ip_address *, const uint8_t *);
struct gtp_interface *gtp_interface_get(const char *);
struct gtp_interface *gtp_interface_get_by_ifindex(int);
int gtp_interface_put(struct gtp_interface *);
struct gtp_interface *gtp_interface_alloc(const char *, int);
void gtp_interface_destroy(struct gtp_interface *);
int gtp_interfaces_destroy(void);
