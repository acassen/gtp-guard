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
static int
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
			if (a->nelems == new_array_size) {
				printf("ARRAY IN STRUCT IS ALREADY SIZE %d, do nothing\n",
				       a->nelems);
				return 0;
			}
			new_size = st_t->size
				- a->nelems * btf__resolve_size(btf, a->type)
				+ new_array_size * btf__resolve_size(btf, a->type);

			/* update array and struct size */
			a->nelems = new_array_size;
			((struct btf_type *)st_t)->size = new_size;
			break;

		case BTF_KIND_ARRAY:
			a = btf_array(t);
			if (a->nelems == new_array_size) {
				printf("ARRAY IS ALREADY SIZE %d, do nothing\n",
				       a->nelems);
				return 0;
			}
			new_size = new_array_size * btf__resolve_size(btf, a->type);
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
	return 0;
}


static int
cgn_bpf_prepare(struct gtp_bpf_prog *p, void *udata)
{
	struct bpf_object *obj = p->load.obj;
	const struct cgn_ctx *c = udata;
	struct bpf_map *m;
	uint64_t icmp_to;

	if (c == NULL)
		return 1;

	/* set consts */
	icmp_to = c->timeout_icmp * NSEC_PER_SEC;
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
	if (_dyn_map_resize(obj, m, c->block_count) < 0)
		return -1;

	m = bpf_object__find_map_by_name(obj, "v4_free_blocks");
	if (m == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, c->block_count + 1) != 0) {
		log_message(LOG_INFO, "set free_blocks_cnt.max_entries failed");
		return -1;
	}
	if (_dyn_map_resize(obj, m, c->cgn_addr_n + 3) < 0)
		return -1;

	return 0;
}


static int
cgn_bpf_loaded(struct gtp_bpf_prog *p, void *udata)
{
	struct bpf_object *obj = p->load.obj;
	struct cgn_ctx *c = udata;
	struct cgn_v4_ipblock *ipbl;
	struct bpf_map *m;
	const size_t fmsize = (c->cgn_addr_n + 3) * sizeof (int);
	const int block_msize = sizeof (struct cgn_v4_ipblock) +
		sizeof (struct cgn_v4_block) * c->block_count;
	uint32_t i, l, k;
	uint8_t d[block_msize];
	void *free_area;
	int *free_cnt;

	/* index bpf maps */
	c->v4_blocks = bpf_object__find_map_by_name(obj, "v4_blocks");
	c->v4_free_blocks = bpf_object__find_map_by_name(obj, "v4_free_blocks");
	c->users = bpf_object__find_map_by_name(obj, "users");
	c->flow_port_timeouts = bpf_object__find_map_by_name(obj, "flow_port_timeouts");
	c->blog_event = bpf_object__find_map_by_name(obj, "block_log_event");

	if (!c->v4_blocks || !c->v4_free_blocks || !c->users ||
	    !c->flow_port_timeouts || !c->blog_event)
		return 1;

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

static struct gtp_bpf_prog_tpl gtp_bpf_tpl_cgn = {
	.name = "cgn",
	.description = "carrier-grade-nat",
	.prepare = cgn_bpf_prepare,
	.loaded = cgn_bpf_loaded,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_cgn);
}
