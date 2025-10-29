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
#pragma once

#include <linux/types.h>
#include "vty.h"
#include "gtp_teid.h"
#include "gtp_bpf_prog.h"
#include "gtp_iptnl.h"


enum {
	XDP_RT_MAP_TEID_INGRESS = 0,
	XDP_RT_MAP_TEID_EGRESS,
	XDP_RT_MAP_PPP_INGRESS,
	XDP_RT_MAP_IPTNL,
	XDP_RT_MAP_IF_LLADDR,
	XDP_RT_MAP_IF_STATS,
	XDP_RT_MAP_CNT
};

#define GTP_RT_FL_IPIP		(1 << 0)
#define GTP_RT_FL_PPPOE		(1 << 1)
#define GTP_RT_FL_DIRECT_TX	(1 << 2)
#define GTP_RT_FL_UDP_LEARNING	(1 << 3)

struct ip_rt_key {
	__u32	id;
	__u32	addr;
};

struct gtp_rt_rule {
	__u8	h_src[6];
	__u8	h_dst[6];
	__u16	session_id;
	__be32	teid;
	__be32	saddr;
	__be32	daddr;
	__be32	dst_key;
	__u8	ifindex;
	__u16	vlan_id;
	__be16	gtp_udp_port;

	/* Some stats */
	__u64	packets;
	__u64	bytes;

	__u8	flags;
} __attribute__ ((__aligned__(8)));

struct ll_addr {
	__u8 local[6];
	__u8 remote[6];
	__u8 state;
} __attribute__ ((__aligned__(8)));

/* Statistics */
enum {
	IF_METRICS_GTP = 0,
	IF_METRICS_PPPOE,
	IF_METRICS_IPIP,
	IF_METRICS_CNT
};

#define IF_DIRECTION_RX		0
#define IF_DIRECTION_TX		1
struct metrics_key {
	__u32		ifindex;
	__u8		type;
	__u8		direction;
} __attribute__ ((packed));

struct metrics {
	__u64		packets;
	__u64		bytes;
	__u64		dropped_packets;
	__u64		dropped_bytes;
} __attribute__ ((__aligned__(8)));


/* Prototypes */
const char *gtp_rt_stats_metrics_str(int);
int gtp_bpf_rt_metrics_init(struct gtp_bpf_prog *, int, int);
int gtp_bpf_rt_metrics_dump(struct gtp_bpf_prog *,
			    int (*dump) (void *, __u8, __u8, struct metrics *),
 			    void *, __u32, __u8, __u8);
void gtp_bpf_rt_stats_vty(struct gtp_bpf_prog *p, struct gtp_interface *iface,
			  struct vty *vty);
int gtp_bpf_rt_key_set(struct gtp_teid *, struct ip_rt_key *);
int gtp_bpf_rt_teid_action(int, struct gtp_teid *);
int gtp_bpf_rt_teid_vty(struct vty *, struct gtp_teid *);
int gtp_bpf_rt_vty(struct gtp_bpf_prog *p, void *arg);
int gtp_bpf_rt_teid_bytes(struct gtp_teid *, uint64_t *);
int gtp_bpf_rt_iptnl_action(int, struct gtp_iptnl *);
int gtp_bpf_rt_iptnl_vty(struct gtp_bpf_prog *p, void *arg);
int gtp_bpf_rt_lladdr_update(void *);
int gtp_bpf_rt_lladdr_vty(struct gtp_bpf_prog *p, void *arg);
