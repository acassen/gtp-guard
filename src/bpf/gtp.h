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

#ifndef _GTP_H
#define _GTP_H

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* linux/if_vlan.h have not exposed this as UAPI, thus mirror some here
 *
 *      struct vlan_hdr - vlan header
 *      @h_vlan_TCI: priority and VLAN ID
 *      @h_vlan_encapsulated_proto: packet type ID or len
 */
struct _vlan_hdr {
        __be16  hvlan_TCI;
        __be16  h_vlan_encapsulated_proto;
};

struct pppoehdr {
	__u8	vertype;
	__u8	code;
	__u16	session;
	__u16	plen;
} __attribute__ ((__packed__));
#define PPPOE_VERTYPE		0x11		/* VER=1, TYPE = 1 */
#define PPPOE_CODE_SESSION	0x00		/* Session */
#define PPP_IP			0x0021		/* Internet Protocol */
#define PPP_IPV6		0x0057		/* Internet Protocol v6 */

struct gtphdr {
        __u8    flags;
        __u8    type;
        __be16  length;
        __be32  teid;
} __attribute__ ((__packed__));
#define GTPU_TPDU		0xff
#define GTPU_FLAGS		0x30
#define GTPU_PORT		2152
#define GTPC_PORT		2123
#define GTPU_ECHO_REQ_TYPE	1

struct parse_pkt {
	struct xdp_md	*ctx;
	__u16	vlan_id;
	__u16   l3_proto;
	__u16   l3_offset;
};

struct gtp_teid_rule {
	__be32  vteid;
	__be32  teid;
	__be32  dst_addr;

	/* Some stats */
	__u64   packets;
	__u64   bytes;

	__u8	direction;
} __attribute__ ((__aligned__(8)));
#define GTP_TEID_DIRECTION_INGRESS	0
#define GTP_TEID_DIRECTION_EGRESS	1

/* IP Fragmentation handling */
#define IP_CE           0x8000          /* Flag: "Congestion"           */
#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

struct ip_frag_key {
	__u32		saddr;
	__u32		daddr;
	__u16		id;
	__u8		protocol;
};

struct gtp_teid_frag {
	__be32		dst_addr;
	struct bpf_timer timer;
};

/* IPIP Tunnel related */
struct gtp_iptnl_rule {
	__be32	selector_addr;
	__be32	local_addr;
	__be32	remote_addr;
	__be16	encap_vlan_id;
	__be16	decap_vlan_id;
	__u8	flags;
} __attribute__ ((__aligned__(8)));
#define MAX_IPTNL_ENTRIES 256U
#define IPTNL_FL_TRANSPARENT_INGRESS_ENCAP	(1 << 0)
#define IPTNL_FL_TRANSPARENT_EGRESS_ENCAP	(1 << 1)
#define IPTNL_FL_TRANSPARENT_BYPASS		(1 << 2)
#define IPTNL_FL_DPD				(1 << 3)
#define IPTNL_FL_DEAD				(1 << 4)
#define IPTNL_FL_UNTAG_VLAN			(1 << 5)
#define IPTNL_FL_TAG_VLAN			(1 << 6)

struct gtp_mirror_rule {
	__be32	addr;
	__be16	port;
	__u8	protocol;
	int	ifindex;
} __attribute__ ((__aligned__(8)));
#define MAX_MIRROR_ENTRIES 100U

/* IP Routing related */
struct ip_rt_key {
	__u32		id;
	__u32		addr;
} __attribute__ ((__aligned__(8)));

struct ppp_key {
	__u8	hw[6];
	__u16	session_id;
} __attribute__ ((__aligned__(8)));

struct gtp_rt_rule {
	__u8	h_src[6];
	__u8	h_dst[6];
	__u16	session_id;
	__be32  teid;
	__be32  saddr;
	__be32  daddr;
	__be32  dst_key;
	__u8	ifindex;
	__u16	vlan_id;
	__be16	gtp_udp_port;

	/* Some stats */
	__u64   packets;
	__u64   bytes;

	__u8	flags;
} __attribute__ ((__aligned__(8)));

#define GTP_RT_FL_IPIP		(1 << 0)
#define GTP_RT_FL_PPPOE		(1 << 1)
#define GTP_RT_FL_UDP_LEARNING	(1 << 2)

/* FIXME: How can we fetch cpu_num in BPF context ? */
const volatile int nr_cpus = 12;

struct rt_percpu_ctx {
	/* ingress */
	__u8 hw[6];
	__u16 session_id;
	/* egress */
	__be32 addr;
	__be32 id;

	__u16 dst_port;
};

/* Receive Packet Steering related */
struct rps_opts {
	__u16 id;
	__u16 max_id;
	__u32 alg;
} __attribute__ ((__aligned__(8)));

#endif
