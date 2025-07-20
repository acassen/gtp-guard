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

/* local includes */
#include "tools.h"
#include "inet_server.h"
#include "list_head.h"
#include "vty.h"
#include "command.h"
#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "cgn.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	CGN utilities
 */


/*
 *	BPF stuff
 */

static int
cgn_bpf_opened(gtp_bpf_prog_t *p, struct bpf_object *obj)
{
	return 0;
}

static int
cgn_bpf_loaded(gtp_bpf_prog_t *p, struct bpf_object *obj)
{
	return 0;
}

static gtp_bpf_prog_tpl_t gtp_bpf_tpl_cgn = {
	.mode = CGN,
	.description = "cgn",
	.def_path = "/etc/gtp-guard/cgn.bpf",
	.opened = cgn_bpf_opened,
	.loaded = cgn_bpf_loaded,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_cgn);
}



/* compact addr/netmask from cgn_addr array.
 * returned u64 contains cgn_addr on lower 32 bits,
 * netmask (24 => addr/24, 256 ips) on upper 64 bits.
 * 'out' must be of c->cgn_addr_n size.
 * return number of written addr/mask */
int
cgn_ctx_compact_cgn_addr(struct cgn_ctx *c, uint64_t *out)
{
	uint32_t a_n, a_mask, a_mask_bits, a_start, a_inc_next;
	int j, k = 0;

	a_start = c->cgn_addr[0];
	a_n = a_inc_next = 1;
	a_mask = a_mask_bits = 0;

	for (j = 1; j < c->cgn_addr_n; j++) {
		if (a_start + a_n == c->cgn_addr[j]) {
			a_n++;
			bool inc = a_inc_next;
			if (inc)
				a_mask = (a_mask << 1) | 1;
			a_inc_next = next_power_of_2(a_n) == a_n;

			if ((a_start & ~a_mask) == (c->cgn_addr[j] & ~a_mask)) {
				if (inc)
					a_mask_bits++;
				continue;
			}
		}

		out[k++] = a_start | ((32ULL - a_mask_bits) << 32);

		a_start = c->cgn_addr[j];
		a_n = a_inc_next = 1;
		a_mask = a_mask_bits = 0;
	}

	out[k++] = a_start | ((32ULL - a_mask_bits) << 32);

	return k;
}


int
cgn_ctx_dump(struct cgn_ctx *c, char *b, size_t s)
{
	int i, j, k = 0, p;
	uint32_t pub;
	uint64_t cgn_addr[c->cgn_addr_n];

	k += scnprintf(b + k, s - k, "  %d address%s; "
		       "%d blocks of %d ports [%d-%d]\n",
		       c->cgn_addr_n, c->cgn_addr_n > 1 ? "es" : "",
		       c->block_count, c->block_size,
		       c->port_start, c->port_end);
	j = cgn_ctx_compact_cgn_addr(c, cgn_addr);
	for (i = 0; i < j; i++) {
		pub = ntohl(cgn_addr[i]);
		k += scnprintf(b + k, s - k, "    - %s/%d\n",
			       inet_ntoa(*(struct in_addr *)&pub),
			       (int)(cgn_addr[i] >> 32));
	}

	k += scnprintf(b + k, s - k,"  flow timeouts:\n");
	k += scnprintf(b + k, s - k,"    icmp : %d\n", c->timeout_icmp);
	k += scnprintf(b + k, s - k,"    udp  : %d\n", c->timeout.udp);
	for (p = 0; p < UINT16_MAX; p++) {
		if (c->timeout_by_port[p].udp) {
			k += scnprintf(b + k, s - k,"     port % 5d: %d\n",
				       p, c->timeout_by_port[p].udp);
		}
	}
	k += scnprintf(b + k, s - k,"    tcp  : estab:%d  synfin:%d\n",
		       c->timeout.tcp_est, c->timeout.tcp_synfin);
	for (p = 0; p < UINT16_MAX; p++) {
		if (c->timeout_by_port[p].tcp_est) {
			k += scnprintf(b + k, s - k,"     port % 5d: "
				       "estab:%d  synfin:%d\n", p,
				       c->timeout_by_port[p].tcp_est,
				       c->timeout_by_port[p].tcp_synfin);
		}
	}

	return k;
}

struct cgn_ctx *
cgn_ctx_get_by_name(const char *name)
{
	list_head_t *l = &daemon_data->cgn;
	struct cgn_ctx *c;

	list_for_each_entry(c, l, next) {
		if (!strcmp(c->name, name))
			return c;
	}

	return NULL;
}

struct cgn_ctx *
cgn_ctx_alloc(const char *name)
{
	struct cgn_ctx *c = NULL;

	c = calloc(1, sizeof (*c));
	assert(c != NULL);
	c->port_start = 1025;
	c->port_end = 65535;
	c->block_size = 1000;
	c->block_count = (c->port_end - c->port_start) / c->block_size;
	c->port_end = c->port_start + c->block_size * c->block_count;
	c->timeout.udp = CGN_PROTO_TIMEOUT_UDP;
	c->timeout.tcp_synfin = CGN_PROTO_TIMEOUT_TCP_SYNFIN;
	c->timeout.tcp_est = CGN_PROTO_TIMEOUT_TCP_EST;
	c->timeout_icmp = CGN_PROTO_TIMEOUT_ICMP;
	snprintf(c->name, GTP_NAME_MAX_LEN, "%s", name);
	list_add_tail(&c->next, &daemon_data->cgn);

	return c;
}

/* release a cgn context instance */
void
cgn_ctx_release(struct cgn_ctx *cgn)
{
	list_del(&cgn->next);
	free(cgn);
}


/* initialize cgn module */
int
cgn_init(void)
{
	return 0;
}

/* destroy cgn module */
int
cgn_destroy(void)
{
	list_head_t *l = &daemon_data->cgn;
	struct cgn_ctx *cgn, *cgn_tmp;

	list_for_each_entry_safe(cgn, cgn_tmp, l, next) {
		cgn_ctx_release(cgn);
	}
	return 0;
}
