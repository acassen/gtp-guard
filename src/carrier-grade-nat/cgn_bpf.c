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


/* system includes */
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <libbpf.h>
#include <btf.h>

/* local includes */
#include "tools.h"
#include "utils.h"
#include "inet_server.h"
#include "inet_utils.h"
#include "list_head.h"
#include "bitops.h"
#include "vty.h"
#include "command.h"
#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "gtp_interface_rule.h"
#include "cgn.h"
#include "bpf/lib/cgn-def.h"
#include "bpf/lib/flow-def.h"


/*
 *	BPF stuff
 */

static const char *
proto_to_str(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_ICMPV6:
		return "icmp6";
	default:
		return "???";
	}
}


/* compute flow timeout, from bpf/lib/flow.h */
static inline uint64_t
_flow_timeout_ns(struct cgn_ctx *c, uint8_t proto, uint16_t port, uint8_t state)
{
	switch (proto) {
	case IPPROTO_UDP:
		return (uint64_t)(c->timeout_by_port[port].udp ?: c->timeout.udp)
			* NSEC_PER_SEC;
	case IPPROTO_TCP:
		if (state == 1)
			return (uint64_t)(c->timeout_by_port[port].tcp_est ?:
					  c->timeout.tcp_est) * NSEC_PER_SEC;
		return (uint64_t)(c->timeout_by_port[port].tcp_synfin ?:
				  c->timeout.tcp_synfin) * NSEC_PER_SEC;
	case IPPROTO_ICMP:
		return (uint64_t)c->timeout_icmp * NSEC_PER_SEC;
	default:
		return FLOW_DEFAULT_TIMEOUT;
	}
}

struct cgn_stats
{
	uint32_t bl_total;
	uint32_t bl_used;
	uint32_t *bl;		/* details per ipaddr */
	uint32_t bl_n;

	uint32_t p_total;
	uint32_t f_total;
	uint32_t f_used;
	uint32_t *f;		/* details per block */
	uint32_t f_n;
};

static void
make_block_stats(struct cgn_ctx *c, struct cgn_stats *st)
{
	struct cgn_v4_ipblock *ipbl;
	void *data;
	uint32_t i, j;
	int ret;

	if (c->v4_blocks == NULL || !c->v4_block_size)
		return;

	st->bl_n = c->block_count + 1;
	st->bl = calloc(st->bl_n, sizeof (uint32_t));
	ipbl = data = malloc(c->v4_block_size);

	st->f_n = (c->flow_per_user / c->block_per_user) + 1;
	st->f = calloc(st->f_n, sizeof (uint32_t));

	for (i = 0; i < c->cgn_addr_n; i++) {
		ret = bpf_map__lookup_elem(c->v4_blocks,
					   &i, sizeof (i),
					   data, c->v4_block_size,
					   0);
		if (ret < 0) {
			log_message(LOG_INFO, "map_lookup{v4_block[%d]}: %m",
				    i);
			goto exit;
		}
		assert(ipbl->used <= st->bl_n);
		++st->bl[ipbl->used];
		st->bl_used += ipbl->used;
		st->bl_total += c->block_count;

		for (j = 0; j < c->block_count; j++) {
			struct cgn_v4_block *b = &ipbl->b[j];
			st->p_total += c->block_size;
			st->f_total += st->f_n - 1;
			st->f_used += b->refcnt;
			++st->f[b->refcnt];
		}
	}

 exit:
	free(data);
}


void
cgn_bpf_block_alloc_dump(struct cgn_ctx *c, char *b, size_t s)
{
	struct cgn_stats st = {};
	uint32_t k = 0, i;

	make_block_stats(c, &st);

	k += scnprintf(b + k, s - k, "ipaddr total       : "
		       "%d\n", c->cgn_addr_n);
	k += scnprintf(b + k, s - k, "block used         : "
		       "%d / %d (%.2f%%)\n", st.bl_used, st.bl_total,
		       (double)st.bl_used / (st.bl_total ?: 1));
	k += scnprintf(b + k, s - k, "block distribution : \n");
	for (i = 0; i < st.bl_n; i++) {
		if (st.bl[i])
			k += scnprintf(b + k, s - k, "  %d / %d blocks for %d ipaddr\n",
				       i, c->block_count, st.bl[i]);
	}
	k += scnprintf(b + k, s - k, "flow used          : "
		       "%d / %d (%.2f%%)\n", st.f_used, st.f_total,
		       (double)st.f_used / (st.f_total ?: 1));
	k += scnprintf(b + k, s - k, "ports total        : "
		       "%d\n", st.p_total);

	free(st.bl);
	free(st.f);
}

static int
_flow_print(struct cgn_ctx *c, char *buf, size_t s,
	    const struct cgn_v4_flow_priv_key *fk)
{
	struct cgn_v4_flow_priv f;
	char spriv[100], scgn[100], spub[100];
	uint64_t now_ns, timeout, upd_ns;
	struct timespec ts;
	int ret, k = 0;
	uint32_t a;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now_ns = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

	ret = bpf_map__lookup_elem(c->v4_priv_flows,
				   fk, sizeof (*fk),
				   &f, sizeof (f),
				   0);
	if (ret < 0) {
		log_message(LOG_INFO, "cannot lookup flow");
		return 0;
	}

	upd_ns = f.updated;
	timeout = _flow_timeout_ns(c, fk->proto, fk->pub_port, f.proto_state);
	k += scnprintf(buf + k, s - k, "   %4s  %4ld  ",
		       proto_to_str(fk->proto),
		       (int64_t)(upd_ns + timeout - now_ns) / NSEC_PER_SEC);

	a = ntohl(fk->priv_addr);
	inet_ntop(AF_INET, &a, spriv, sizeof (spriv));
	a = ntohl(f.cgn_addr);
	inet_ntop(AF_INET, &a, scgn, sizeof (scgn));
	a = ntohl(fk->pub_addr);
	inet_ntop(AF_INET, &a, spub, sizeof (spub));
	k += scnprintf(buf + k, s - k, "%s:%-5d  %s:%-5d  %s:%d\n",
		       spriv, fk->priv_port, scgn, f.cgn_port, spub, fk->pub_port);

	return k;
}

void
cgn_bpf_user_full_dump(struct cgn_ctx *c, uint32_t addr, char *buf, size_t s)
{
	const uint32_t bl_flow_max = c->flow_per_user / c->block_per_user;
	struct cgn_user u;
	char spriv[100], scgn[100];
	uint32_t a;
	int ret, i;
	int k = 0;

	buf[0] = 0;

	ret = bpf_map__lookup_elem(c->users,
				   &addr, sizeof (addr),
				   &u, sizeof (u),
				   0);
	if (ret < 0)
		return;

	a = htonl(addr);
	inet_ntop(AF_INET, &a, spriv, sizeof (spriv));
	k += scnprintf(buf + k, s - k, "user:\n private addr        : "
		       "%s\n", spriv);

	uint32_t ipbl_idx = u.ipblock_idx;
	struct cgn_v4_ipblock *ipbl = malloc(c->v4_block_size);
	ret = bpf_map__lookup_elem(c->v4_blocks,
				   &ipbl_idx, sizeof (ipbl_idx),
				   ipbl, c->v4_block_size,
				   0);
	if (ret < 0) {
		log_message(LOG_INFO, "cannot lookup ipblock_idx %d",
			    ipbl_idx);
		goto exit;
	}

	a = htonl(ipbl->cgn_addr);
	inet_ntop(AF_INET, &a, scgn, sizeof (scgn));
	k += scnprintf(buf + k, s - k, " pub address        : %s\n",
		       scgn);

	k += scnprintf(buf + k, s - k, " allocated blocks   : %d / %d\n",
		       u.block_n, c->block_per_user);

	for (i = 0; i < u.block_n; i++) {
		uint32_t bl_idx = u.block_idx[i];
		struct cgn_v4_block *bl = &ipbl->b[bl_idx];
		assert(bl->bl_idx == bl_idx);
		assert(bl->ipbl_idx == ipbl_idx);

		k += scnprintf(buf + k, s - k,
			       " bl[%d] used flows  : %lld / %d [%d-%d]\n",
			       i, bl->refcnt, bl_flow_max, bl->cgn_port_start,
			       bl->cgn_port_start + c->block_size);
	}

	k += scnprintf(buf + k, s - k, "user flows:\n");
	k += scnprintf(buf + k, s - k, "   prot  tim     "
		       "priv                    cgn      "
		       "        ext_pub\n");

	/* we do not have flow index by user, so walk on all flows */
	struct cgn_v4_flow_priv_key sk = {}, *pk = &sk;
	while (!bpf_map__get_next_key(c->v4_priv_flows, pk, pk, sizeof (sk))) {
		if (pk->priv_addr == addr)
			k += _flow_print(c, buf + k, s - k, pk);
	}

 exit:
	free(ipbl);
}

/*
 * Modify map 'value' size. This allow something like, in bpf:
 *
 * struct {
 * 	__uint(type, BPF_MAP_TYPE_ARRAY);
 * 	__type(key, __u32);
 *	__type(value, __u32[]);
 * } map_name SEC(".maps");
 *
 * OR
 *
 * struct mydata {
 *   __u32  somefields;
 *   __u32  last_member_array[];
 * }
 *
 * struct {
 * 	__uint(type, BPF_MAP_TYPE_HASH);
 * 	__type(key, __u32);
 *	__type(value, struct mydata);
 * } map_name SEC(".maps");
 *
 * Compile program as this, and then set array size dynamically (from config)
 * when loading program, using this function.
 *
 * It modifies map attribute _and_ BTF associated to this map, to keep
 * libbpf/verifier happy.
 */
static size_t
_dyn_map_resize(struct bpf_object *obj, struct bpf_map *m,
		uint32_t new_array_size)
{
	const struct btf_type *t, *st_t, *ptr_t;
	struct btf_member *mb;
	struct btf_array *a;
	struct btf *btf;
	int vlen, svlen, id, i;
	size_t new_size;

	/* dig into btf */
	btf = bpf_object__btf(obj);
	if (btf == NULL)
		return -1;

	/* btf info for map (VAR -> STRUCT <map_name>) */
	id = btf__find_by_name(btf, bpf_map__name(m));
	if (id < 0)
		return -1;
	t = btf__type_by_id(btf, id);
	if (t == NULL || !btf_is_var(t))
		return -1;
	st_t = btf__type_by_id(btf, t->type);
	if (st_t == NULL || !btf_is_struct(st_t))
		return -1;

	/* find 'value' struct member in map. fields are listed in
	 * libbpf.c:parse_btf_map_def() */
	vlen = btf_vlen(st_t);
	mb = btf_members(st_t);
	for (i = 0; i < vlen; i++, mb++) {
		const char *name = btf__name_by_offset(btf, mb->name_off);
		if (!name || strcmp(name, "value"))
			continue;

		/* 'value' is PTR -> {STRUCT|ARRAY} */
		ptr_t = btf__type_by_id(btf, mb->type);
		if (!btf_is_ptr(ptr_t) ||
		    !(t = btf__type_by_id(btf, ptr_t->type)))
			continue;

		switch (btf_kind(t)) {
		case BTF_KIND_STRUCT:
			st_t = t;

			/* last member should contains the array to resize */
			svlen = btf_vlen(st_t);
			mb = btf_members(st_t);
			if (!svlen ||
			    !(t = btf__type_by_id(btf, mb[svlen - 1].type)) ||
			    !btf_is_array(t))
				return -1;

			a = btf_array(t);
			if (a->nelems == new_array_size)
				return st_t->size;
			new_size = st_t->size
				- a->nelems * btf__resolve_size(btf, a->type)
				+ new_array_size * btf__resolve_size(btf, a->type);

			/* update array and struct size */
			a->nelems = new_array_size;
			((struct btf_type *)st_t)->size = new_size;
			break;

		case BTF_KIND_ARRAY:
			a = btf_array(t);
			new_size = new_array_size * btf__resolve_size(btf, a->type);
			if (a->nelems == new_array_size)
				return new_size;
			a->nelems = new_array_size;
			break;

		default:
			log_message(LOG_DEBUG, "%s: kind %d not handled as map value",
				    bpf_map__name(m), btf_kind(t));
			return -1;
		}
		break;
	}
	if (i == vlen)
		return -1;

	/* the easiest part: modify map value size */
	if (bpf_map__set_value_size(m, new_size) != 0) {
		log_message(LOG_DEBUG, "set %s.value_size failed: %m",
			    bpf_map__name(m));
		return -1;
	}
	return new_size;
}


static int
cgn_bpf_prepare(struct gtp_bpf_prog *p, void *udata)
{
	struct bpf_object *obj = p->load.obj;
	struct cgn_ctx **pc = udata, *c = *pc;
	struct bpf_map *m;
	uint64_t icmp_to;

	/* bpf program is not yet attached to cgn block configuration.
	 * this is not an error, but stop loading. */
	if (c == NULL)
		return 1;

	/* set consts */
	icmp_to = (uint64_t)c->timeout_icmp * NSEC_PER_SEC;
	uint32_t bl_flow_max = c->flow_per_user / c->block_per_user;
	struct gtp_bpf_prog_var consts_var[] = {
		{ .name = "ipbl_n", .value = &c->cgn_addr_n,
		  .size = sizeof (c->cgn_addr_n) },
		{ .name = "bl_n", .value = &c->block_count,
		  .size = sizeof (c->block_count) },
		{ .name = "bl_user_max", .value = &c->block_per_user,
		  .size = sizeof (c->block_per_user) },
		{ .name = "bl_flow_max", .value = &bl_flow_max,
		  .size = sizeof (bl_flow_max) },
		{ .name = "port_count", .value = &c->block_size,
		  .size = sizeof (c->block_size) },
		{ .name = "icmp_timeout", .value = &icmp_to,
		  .size = sizeof (icmp_to) },
		{ NULL },
	};
	gtp_bpf_prog_obj_update_var(obj, consts_var);

	/* resize bpf maps */
	m = bpf_object__find_map_by_name(obj, "v4_blocks");
	if (m == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, c->cgn_addr_n) != 0) {
		log_message(LOG_INFO, "set v4_blocks.max_entries failed");
		return -1;
	}
	if ((c->v4_block_size_tmp = _dyn_map_resize(obj, m, c->block_count)) < 0)
		return -1;

	m = bpf_object__find_map_by_name(obj, "v4_free_blocks");
	if (m == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, c->block_count + 1) != 0) {
		log_message(LOG_INFO, "set v4_free_blocks.max_entries failed");
		return -1;
	}
	if (_dyn_map_resize(obj, m, c->cgn_addr_n + 3) < 0)
		return -1;

	m = bpf_object__find_map_by_name(obj, "v4_pool_addr");
	if (m == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, c->cgn_addr_n * 2) != 0) {
		log_message(LOG_INFO, "set v4_pool_addr.max_entries failed");
		return -1;
	}

	return 0;
}


static int
cgn_bpf_loaded(struct gtp_bpf_prog *p, void *udata, bool reloading)
{
	struct bpf_object *obj = p->load.obj;
	struct cgn_ctx **pc = udata, *c = *pc;
	struct cgn_v4_ipblock *ipbl;
	struct bpf_map *m;
	void *free_area;
	int *free_cnt;

	/* prepare() ensures a cgn block is attached */
	assert(c != NULL);

	/* index bpf maps */
	c->v4_blocks = bpf_object__find_map_by_name(obj, "v4_blocks");
	c->v4_free_blocks = bpf_object__find_map_by_name(obj, "v4_free_blocks");
	c->users = bpf_object__find_map_by_name(obj, "users");
	c->flow_port_timeouts = bpf_object__find_map_by_name(obj, "flow_port_timeouts");
	c->blog_queue = bpf_object__find_map_by_name(obj, "v4_block_log_queue");
	c->v4_priv_flows = bpf_object__find_map_by_name(obj, "v4_priv_flows");
	c->v4_pool_addr = bpf_object__find_map_by_name(obj, "v4_pool_addr");

	if (!c->v4_blocks || !c->v4_free_blocks || !c->users ||
	    !c->flow_port_timeouts || !c->blog_queue || !c->v4_pool_addr) {
		log_message(LOG_ERR, "%s: a mandatory bpf map is missing",
			    p->name);
		return -1;
	}

	c->v4_block_size = c->v4_block_size_tmp;

	if (reloading)
		return 0;

	const size_t fmsize = (c->cgn_addr_n + 3) * sizeof (int);
	const int block_msize = sizeof (struct cgn_v4_ipblock) +
		sizeof (struct cgn_v4_block) * c->block_count;
	uint32_t i, l, k;
	uint8_t d[block_msize], uu = 1;

	/* prepare memory to be copied to maps */
	free_cnt = free_area = malloc(fmsize);
	m = c->v4_blocks;

	/* fill blocks */
	for (i = 0; i < c->cgn_addr_n; i++) {
		memset(d, 0, block_msize);
		ipbl = (struct cgn_v4_ipblock *)d;
		ipbl->ipbl_idx = i;
		ipbl->fr_idx = i;
		ipbl->cgn_addr = c->cgn_addr[i];
		for (l = 0; l < c->block_count; l++) {
			ipbl->b[l].ipbl_idx = i;
			ipbl->b[l].bl_idx = l;
			ipbl->b[l].cgn_port_start =
				c->port_start + l * c->block_size;
			ipbl->b[l].cgn_port_next = ipbl->b[l].cgn_port_start;
		}
		free_cnt[2 + i] = i;

		bpf_map__update_elem(m, &i, sizeof (i),
				     d, block_msize, 0);

		k = htonl(c->cgn_addr[i]);
		bpf_map__update_elem(c->v4_pool_addr, &k, sizeof (k),
				     &uu, sizeof (uu), 0);

	}
	free_cnt[0] = 0;
	free_cnt[1] = c->cgn_addr_n;
	free_cnt[i + 2] = 0;

	/* on startup, all blocks are unused, so only the first line contains
	 * indexes. */
	m = c->v4_free_blocks;
	i = 0;
	bpf_map__update_elem(m, &i, sizeof (i), free_area, fmsize, 0);
	free(free_area);

	/* set flow port timeout */
	m = c->flow_port_timeouts;
	for (i = 0; i < 1 << 16; i++) {
		union flow_timeout_config val = {};

		k = i;
		val.udp = c->timeout_by_port[i].udp ?: c->timeout.udp;
		bpf_map__update_elem(m, &k, sizeof (k), &val, sizeof (val), 0);

		k = (1 << 16) | i;
		val.tcp_synfin = c->timeout_by_port[i].tcp_synfin ?:
			c->timeout.tcp_synfin;
		val.tcp_est = c->timeout_by_port[i].tcp_est ?: c->timeout.tcp_est;
		bpf_map__update_elem(m, &k, sizeof (k), &val, sizeof (val), 0);
	}

	return cgn_blog_init(c);
}

static void
cgn_bpf_closed(struct gtp_bpf_prog *p, void *udata)
{
	struct cgn_ctx **c = udata;

	if (*c != NULL)
		cgn_blog_release(*c);
}

static void *
cgn_bpf_alloc(struct gtp_bpf_prog *p)
{
	struct cgn_ctx **pc, *c;

	pc = calloc(1, sizeof (struct cgn_ctx *));
	if (pc == NULL)
		return NULL;

	/* attach to already declared cgn-block */
	c = cgn_ctx_get_by_name(p->name);
	if (c != NULL) {
		c->bpf_data = pc;
		*pc = c;
	}

	return pc;
}

static void
cgn_bpf_release(struct gtp_bpf_prog *p, void *udata)
{
	struct cgn_ctx **c = udata;

	if (*c != NULL)
		(*c)->bpf_data = NULL;
	free(c);
}

static struct gtp_bpf_prog_tpl gtp_bpf_tpl_cgn = {
	.name = "cgn",
	.description = "carrier-grade-nat",
	.alloc = cgn_bpf_alloc,
	.release = cgn_bpf_release,
	.prepare = cgn_bpf_prepare,
	.loaded = cgn_bpf_loaded,
	.closed = cgn_bpf_closed,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_cgn);
}
