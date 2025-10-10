/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"


/*
 * ipv4 block allocation.
 * filled by userspace on startup, then exclusively managed by bpf program
 */
struct cgn_v4_block {
	__u64			refcnt;		/* used flow */
	__u64			cgn_port_next;
	__u32			ipbl_idx;	/* idx in map 'blocks' */
	__u32			bl_idx;		/* ipbl->b[@idx] */
	__u32			cgn_port_start;	/* fixed */
	__u32			_pad;
};

struct cgn_v4_ipblock {
	__u32			cgn_addr;	/* cpu order */
	__u32			ipbl_idx;
	__u32			fr_idx;		/* idx in map 'v4_free_blocks'  */
	__u32			used;		/* [ 0 - bl_n ] */
	__u32			next;
	__u32			_pad;
	struct cgn_v4_block	b[];		/* 'total' blocks follow */
};

#define CGN_BLOG_FL_ALLOC	0x01

/* log entry sent to userspace  */
struct cgn_v4_block_log
{
	char		prefix[32];	/* log prefix */
	__u32		cgn_addr;	/* allocated ip (v4) */
	__u32		priv_addr;	/* private ip */
	__u32		duration;	/* in seconds */
	__u16		port_start;
	__u16		port_size;
	__u8		flag;
} __attribute__((packed));


/* global lock for ipv4 block allocation */
struct cgn_v4_block_lock
{
	struct bpf_spin_lock l;
};


/*
 * ipv4 flow
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
	__u32			cgn_addr;
	__u16			priv_port;
	__u16			cgn_port;
	__u8			proto_state;	/* tcp state */
} __attribute__((packed));


struct cgn_v4_flow_priv_key {
	__u32			priv_addr;
	__u32			pub_addr;
	__u16			priv_port;
	__u16			pub_port;
	__u8			proto;
} __attribute__((packed));

struct cgn_v4_flow_priv {
	struct bpf_timer	timer;		/* flow expiration */
	__u64			updated;
	__u32			cgn_addr;
	__u16			cgn_port;
	__u16			bl_idx;
	__u16			ipbl_idx;
	__u8			proto_state;	/* tcp state */
};

/* todo */
struct cgn_v4_flow_priv_hairpin_key {
	__u32			priv_addr;
	__u16			priv_port;
	__u8			proto;
} __attribute__((packed));

struct cgn_v4_flow_priv_hairpin {
	__u16			cgn_port;
} __attribute__((packed));



/*
 * cgn user, keep allocated blocks
 */

#define CGN_USER_BLOCKS_MAX	8

struct cgn_user_key {
	__u32			addr;
} __attribute__((packed));

struct cgn_user {
	__u64			created;
	__u64			allocating;
	__u32			addr;
	__u32			ipblock_idx;
	__u32			block_idx[CGN_USER_BLOCKS_MAX];
	__u8			block_n;
	__u8			_pad[3];
};



/* all address/port in cpu order */
struct cgn_packet
{
	__u32		src_addr;
	__u32		dst_addr;
	__u32		cgn_addr;
	__u16		src_port;
	__u16		dst_port;
	__u8		proto;
	__u8		from_priv;
	__u8		racy;
	__u8		_pad;
	__u32		tcp_flags;
	__u16		icmp_err_off;
};
