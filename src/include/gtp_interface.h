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

#ifndef IF_NAMESIZE
# define IF_NAMESIZE 16
#endif

#include <stdint.h>
#include <netinet/if_ether.h>
#include "addr.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface_rule.h"

/* Interface events */
enum gtp_interface_event {
	GTP_INTERFACE_EV_PRG_BIND,
	GTP_INTERFACE_EV_PRG_UNBIND,
	GTP_INTERFACE_EV_VTY_SHOW,
	GTP_INTERFACE_EV_VTY_WRITE,
	GTP_INTERFACE_EV_DESTROYING,
};

typedef void (*gtp_interface_event_cb_t)(struct gtp_interface *,
					 enum gtp_interface_event,
					 void *user_data,
					 void *arg);
struct gtp_interface_event_storage;


/* Flags */
enum gtp_interface_flags {
	GTP_INTERFACE_FL_METRICS_GTP_BIT,
	GTP_INTERFACE_FL_METRICS_PPPOE_BIT,
	GTP_INTERFACE_FL_METRICS_IPIP_BIT,
	GTP_INTERFACE_FL_METRICS_LINK_BIT,
	GTP_INTERFACE_FL_DIRECT_TX_GW_BIT,
	GTP_INTERFACE_FL_SHUTDOWN_BIT,
	GTP_INTERFACE_FL_RUNNING_BIT,
};

/* Interface structure */
struct gtp_interface {
	char			ifname[IF_NAMESIZE];
	uint8_t			hw_addr[ETH_ALEN];
	uint8_t			hw_addr_len;
	uint16_t		vlan_id;
	uint16_t		table_id;
	union addr		direct_tx_gw;
	uint8_t			direct_tx_hw_addr[ETH_ALEN];
	int			ifindex;
	char			description[GTP_STR_MAX_LEN];

	/* bpf-prog */
	struct gtp_bpf_prog	*bpf_prog;
	struct list_head	bpf_prog_list;
	struct bpf_link		*bpf_xdp_lnk;
	struct bpf_link		*bpf_tc_lnk;
	struct gtp_bpf_interface_rule *rules;

	/* interface events */
	struct gtp_interface_event_storage *ev;
	int			ev_n;
	int			ev_msize;

	/* metrics */
	struct rtnl_link_stats64 *link_metrics;

	/* point to real device if it's a virtual device */
	struct gtp_interface	*link_iface;

	/* tunnel info */
	int			tunnel_mode; /* 0:none, 1:gre, 2:ipip */
	union addr		tunnel_local;
	union addr		tunnel_remote;

	struct list_head	next;

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
void gtp_interface_update_direct_tx_lladdr(const union addr *, const uint8_t *);
struct gtp_interface *gtp_interface_get(const char *, bool);
struct gtp_interface *gtp_interface_get_by_ifindex(int, bool);
int gtp_interface_put(struct gtp_interface *);
int gtp_interface_start(struct gtp_interface *);
void gtp_interface_stop(struct gtp_interface *);
void gtp_interface_link(struct gtp_interface *, struct gtp_interface *);
void gtp_interface_register_event(struct gtp_interface *, gtp_interface_event_cb_t,
				  void *);
void gtp_interface_unregister_event(struct gtp_interface *, gtp_interface_event_cb_t);
void gtp_interface_trigger_event(struct gtp_interface *iface,
				 enum gtp_interface_event type, void *arg);
void gtp_interface_trigger_event_wide(struct gtp_interface *iface,
				      enum gtp_interface_event type, void *arg);
struct gtp_interface *gtp_interface_alloc(const char *, int);
void gtp_interface_destroy(struct gtp_interface *);
int gtp_interfaces_destroy(void);
