/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"
#include "if_rule-def.h"

/* #define CGN_DEBUG */


/*
 * ipv4 flow
 *
 * 'proto_state' field contains tcp state, and it kept sync
 * between cgn_v4_flow_pub and cgn_v4_flow_priv
 */
struct cgn_v4_flow_pub_key {
	__u32			cgn_addr;
	__u32			pub_addr;
	__u16			cgn_port;
	__u16			pub_port;
	__u8			proto;
} __attribute__((packed));

struct cgn_v4_flow_pub {
	__u32			priv_addr;
	__u16			priv_port;
	__u8			proto_state;
	__u8			_pad;
} __attribute__((packed));


struct cgn_v4_flow_priv_key {
	__u32			priv_addr;
	__u32			pub_addr;
	__u16			priv_port;
	__u16			pub_port;
	__u8			proto;
	__u8			_pad[3];
} __attribute__((packed));

struct cgn_v4_flow_priv {
	__u32			cgn_addr;
	__u16			cgn_port;
	__u8			proto_state;
	__u8			_pad;
	__u64			last_use;
} __attribute__((packed));


/* parsed data / internal state */
struct cgn_packet
{
	__be32		src_addr;
	__be32		dst_addr;
	__be16		src_port;
	__be16		dst_port;
	__u8		proto;
	__u8		from_priv;
	__u16		icmp_err_off;
	__u32		tcp_flags;
};
