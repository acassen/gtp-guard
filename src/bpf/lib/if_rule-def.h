/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#define IF_RULE_MAX_RULE	2048


#define IF_RULE_FL_TUNNEL_IPIP	0x0001
#define IF_RULE_FL_TUNNEL_GRE	0x0002

struct if_rule_key_base
{
	int ifindex;
	__u32 tun_local;
	__u32 tun_remote;
	__u16 vlan_id;
} __attribute__((packed));

struct if_rule
{
	int action;
	int ifindex;	/* 0 to use fib_lookup output */
	__u32 table;
	__u32 tun_remote;
	__u16 vlan_id;
	__u16 flags;
	__u32 _pad;

	/* metrics */
	__u64 pkt_in;
	__u64 bytes_in;
	__u64 pkt_fwd;
} __attribute__((packed));
