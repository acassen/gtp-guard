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
 *              Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#pragma once

#include "gtp_stddef.h"
#include "list_head.h"

struct gtp_xsk_desc;


#define CGN_BLOCK_SIZE_DEF		500
#define CGN_USER_MAX_DEF		100000
#define CGN_BLOCK_PER_USER_DEF		4
#define CGN_FLOW_PER_USER_DEF		2000

#define CGN_FLOW_DEFAULT_TIMEOUT	120
#define CGN_FLOW_DEFAULT_TIMEOUT_NS	(FLOW_DEFAULT_TIMEOUT * NSEC_PER_SEC)

/* default protocol timeout values */
#define CGN_PROTO_TIMEOUT_TCP_EST	600
#define CGN_PROTO_TIMEOUT_TCP_SYNFIN	120
#define CGN_PROTO_TIMEOUT_UDP		120
#define CGN_PROTO_TIMEOUT_ICMP		120

/* timeout are in seconds */
struct port_timeout_config
{
	uint16_t udp;
	uint16_t tcp_synfin;
	uint16_t tcp_est;
};


/*
 * cgn flow
 */

#define CGN_FLOW_FL_IN_MAP	0x01
#define CGN_FLOW_FL_SHARED_PORT	0x02

struct cgn_v4_flow
{
	uint8_t			proto;
	uint8_t			flags : 2;
	uint8_t			bl_idx : 6;
	uint16_t		priv_port;	/* net order */
	uint16_t		cgn_port;	/* net order */
	uint16_t		pub_port;	/* net order */
	uint32_t		pub_addr;	/* net order */
} __attribute__((packed));

struct cgn_v4_block
{
	struct cgn_v4_ipblock	*ipbl;		/* parent */
	uint64_t		alloc_time;
	uint32_t		refcnt;		/* # of allocated flow */

	/* cgn port allocation */
	uint16_t		port_start;	/* fixed */
	uint16_t		port_end;	/* fixed */
	uint16_t		port_next[4];
	uint16_t		port_uniq[4];	/* per proto. estimation */
};

struct cgn_v4_ipblock
{
	uint32_t		cgn_addr;	/* cpu order */
	uint32_t		used;		/* [ 0 - bl_n ] */
	uint32_t		next;
	uint32_t		_pad;
	struct list_head	addr_list;	/* c->addr_slots */
	struct cgn_v4_block	bl[];		/* 'total' blocks follow */
};

struct cgn_user
{
	uint32_t		addr;		/* cpu order */
	uint32_t		cgn_addr;
	struct list_head	list;
	struct hlist_node	hlist;

	/* allocated blocks */
	struct cgn_v4_block	**bl;
	uint32_t		bl_n;
	uint32_t		bl_next;

	/* flow data */
	struct cgn_v4_flow	*flow;		/* flows info */
	uint16_t		flow_size;
	uint16_t		flow_n;		/* used slots [0, size] */
	uint16_t		flow_next;	/* [0, size-1] */
	time_t			flow_gc_next;

	/* flow index by private port */
	uint16_t		hpriv_size;	/* fixed, power of 2 */
	uint16_t		hpriv_n;
	uint32_t		*hpriv;		/* priv_port << 16 | flow_idx */
};


/* between xsk thread and main context */
struct cgn_v4_block_log
{
	char			prefix[32];	/* log prefix */
	uint32_t		cgn_addr;	/* allocated ip (v4) */
	uint32_t		priv_addr;	/* private ip */
	uint32_t		duration;	/* in seconds */
	uint16_t		port_start;
	uint16_t		port_size;
	bool			alloc;
};


/*
 * cgn bpf
 */

struct cgn_bpf_ctx
{
	struct gtp_bpf_prog	*p;
	struct gtp_xsk_ctx	*xc;
	struct list_head	cgn_list;

	struct bpf_map		*v4_priv_flows;
	struct bpf_map		*v4_pub_flows;
	struct bpf_map		*v4_pool_addr;
};


/*
 * main context
 */

struct cgn_ctx
{
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	struct list_head	next;

	struct cgn_bpf_ctx	*bpf_data;
	struct gtp_bpf_ifrules	*bpf_ifrules;
	struct list_head	bpf_list;

	/* cgn configuration, read-only after initialization */
	bool			initialized;
	uint32_t		*cgn_addr;	/* array of size 'cgn_addr_n' */
	uint32_t		cgn_addr_n;
	uint16_t		port_start;
	uint16_t		port_end;
	uint32_t		block_size;	/* # of port per block */
	uint32_t		block_count;	/* # of block per ip */
	uint32_t		flow_per_user;	/* max # of flow per user */
	uint8_t			block_per_user;	/* max # of blocks per user */
	uint32_t		max_user;	/* max # of users */
	uint32_t		max_flow;	/* max # of flow, global */
	struct port_timeout_config timeout;
	struct port_timeout_config timeout_by_port[0x10000];
	uint16_t		timeout_icmp;

	/* cgn user/block allocation, owned by xsk thread */
	uint64_t		now_ns;
	struct list_head	*addr_slots;
	uint32_t		*addr_stats;
	struct cgn_v4_ipblock	*ipbl;
	struct list_head	user_list;
	struct cgn_user		*user_gc_cur;
	struct thread		*user_gc_th;
	struct hlist_head	*huser;
	uint32_t		huser_size;
	uint32_t		user_n;
	uint32_t		flow_n;

	/* cgn block log */
	struct cdr_fwd_entry	*blog_cdr_fwd;

	/* metrics */
};


/* cgn.c */
void cgn_ctx_log_send(struct cgn_ctx *c, const struct cgn_v4_block_log *e, size_t size);
int cgn_ctx_compact_cgn_addr(struct cgn_ctx *c, uint64_t *out);
int cgn_ctx_dump(struct cgn_ctx *c, char *b, size_t s);
struct cgn_ctx *cgn_ctx_get_by_name(const char *name);
int cgn_ctx_start(struct cgn_ctx *c);
void cgn_ctx_release(struct cgn_ctx *c);
struct cgn_ctx *cgn_ctx_alloc(const char *name);

/* cgn_flow.c */
int cgn_flow_gc(struct cgn_ctx *c);
int cgn_flow_read_pkt(void *priv, struct gtp_xsk_desc *pkt);
void cgn_flow_dump_user_full(struct cgn_ctx *c, uint32_t addr, char *buf, size_t s);
void cgn_flow_dump_block_alloc(struct cgn_ctx *c, char *b, size_t s);
int cgn_flow_init(void *);
void cgn_flow_release(void *);
