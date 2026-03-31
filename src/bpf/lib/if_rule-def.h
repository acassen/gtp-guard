/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

/* extends XDP_PASS, XDP_DROP, ... */
#define XDP_IFR_DEFAULT_ROUTE	8
#define XDP_IFR_FORWARD		9

//#define IF_RULE_DEBUG

#ifdef IF_RULE_DEBUG
# define IFR_DBG(Fmt, ...) bpf_printk(Fmt, ## __VA_ARGS__)
#else
# define IFR_DBG(...)
#endif

#define IF_RULE_MAX_RULE	2048

#define IF_RULE_FL_TUNNEL_GRE	0x0001
#define IF_RULE_FL_TUNNEL_IPIP	0x0002
#define IF_RULE_FL_TUNNEL_MASK	0x0003

/* for dynamic routing */
struct if_rule_attr {
	__u32	ifindex;	/* output ifindex */
	__u32	tun_local;
	__u32	tun_remote;
	__u16	vlan_id;
	__u16	flags;
} __attribute__((packed));

/* match on input */
struct if_rule_key_base {
	__u32	ifindex;	/* input ifindex */
	__u16	vlan_id;
	__u16	flags;
	__u32	tun_local;
	__u32	tun_remote;
} __attribute__((packed));

struct if_rule {
	int	action;
	__u32	table_id;
	__u32	force_ifindex;	/* bypass first fib_loookup */
	__u32	xsk_base_idx;	/* base idx for xsks lookup */

	/* metrics */
	__u64	pkt_in;
	__u64	bytes_in;
	__u64	pkt_fwd;
} __attribute__((packed));
