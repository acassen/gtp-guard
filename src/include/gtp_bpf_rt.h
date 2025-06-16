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

#ifndef _GTP_BPF_RT_H
#define _GTP_BPF_RT_H

enum {
	XDP_RT_MAP_TEID_INGRESS = 0,
	XDP_RT_MAP_TEID_EGRESS,
	XDP_RT_MAP_PPP_INGRESS,
	XDP_RT_MAP_IPTNL,
	XDP_RT_MAP_MAC_LEARNING,
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
} __attribute__ ((__aligned__(8)));

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

struct port_mac_address {
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
} __attribute__ ((__aligned__(8)));

struct metrics {
	__u64		packets;
	__u64		bytes;
	__u64		dropped_packets;
	__u64		dropped_bytes;
} __attribute__ ((__aligned__(8)));


/* Prototypes */
extern int gtp_bpf_rt_load(gtp_bpf_opts_t *);
extern void gtp_bpf_rt_unload(gtp_bpf_opts_t *);
extern int gtp_bpf_rt_stats_init(gtp_bpf_opts_t *);
extern int gtp_bpf_rt_stats_dump(gtp_bpf_opts_t *,
				 int (*dump) (void *, __u32, __u8, __u8, struct metrics *),
				 void *);
extern int gtp_bpf_rt_key_set(gtp_teid_t *, struct ip_rt_key *);
extern int gtp_bpf_rt_teid_action(int, gtp_teid_t *);
extern int gtp_bpf_rt_teid_vty(vty_t *, gtp_teid_t *);
extern int gtp_bpf_rt_vty(vty_t *);
extern int gtp_bpf_rt_teid_bytes(gtp_teid_t *, uint64_t *);
extern int gtp_bpf_rt_iptnl_action(int, gtp_iptnl_t *);
extern int gtp_bpf_rt_iptnl_vty(vty_t *);
extern int gtp_bpf_rt_mac_learning_vty(vty_t *);

#endif
