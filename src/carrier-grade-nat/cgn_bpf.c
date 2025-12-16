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
#include "gtp_bpf_xsk.h"
#include "cgn-priv.h"
#include "bpf/lib/cgn-def.h"


/*
 *	BPF stuff
 */

static void *
cgn_bpf_alloc(struct gtp_bpf_prog *p)
{
	struct cgn_bpf_ctx *x;

	x = calloc(1, sizeof (struct cgn_bpf_ctx));
	if (x == NULL)
		return NULL;
	x->p = p;
	INIT_LIST_HEAD(&x->cgn_list);

	return x;
}

static void
cgn_bpf_release(struct gtp_bpf_prog *p, void *udata)
{
	struct cgn_bpf_ctx *x = udata;
	struct cgn_ctx *c, *c_tmp;

	list_for_each_entry_safe(c, c_tmp, &x->cgn_list, bpf_list) {
		c->bpf_data = NULL;
		c->bpf_ifrules = NULL;
		list_del_init(&c->bpf_list);
	}
	if (x->xc != NULL)
		gtp_xsk_release(x->xc);
	free(x);
}


static int
cgn_bpf_prepare(struct gtp_bpf_prog *p, void *udata)
{
	struct cgn_bpf_ctx *x = udata;
	struct cgn_ctx *c;
	struct bpf_map *m;
	uint32_t max_flow = 0;
	int cpt = 1;

	if (list_empty(&x->cgn_list))
		return 1;

	list_for_each_entry(c, &x->cgn_list, bpf_list) {
		cpt += c->cgn_addr_n;
		max_flow += c->max_flow;
	}

	m = gtp_bpf_prog_load_map(p->obj_load, "v4_pool_addr");
	if (m == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, cpt) != 0) {
		log_message(LOG_INFO, "set v4_pool_addr.max_entries=%d failed",
			    cpt);
		return -1;
	}

	m = gtp_bpf_prog_load_map(p->obj_load, "v4_priv_flows");
	if (m == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, max_flow) != 0) {
		log_message(LOG_INFO, "set v4_priv_flows.max_entries=%d failed",
			    max_flow);
		return -1;
	}
	m = gtp_bpf_prog_load_map(p->obj_load, "v4_pub_flows");
	if (m == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, max_flow) != 0) {
		log_message(LOG_INFO, "set v4_pub_flows.max_entries=%d failed",
			    max_flow);
		return -1;
	}

	return 0;
}

static int
cgn_bpf_loaded(struct gtp_bpf_prog *p, void *udata, bool reloading)
{
	struct cgn_bpf_ctx *x = udata;

	/* index bpf maps */
	x->v4_priv_flows = gtp_bpf_prog_load_map(p->obj_load, "v4_priv_flows");
	x->v4_pub_flows = gtp_bpf_prog_load_map(p->obj_load, "v4_pub_flows");
	x->v4_pool_addr = gtp_bpf_prog_load_map(p->obj_load, "v4_pool_addr");
	if (!x->v4_priv_flows || !x->v4_pub_flows || !x->v4_pool_addr)
		return -1;

	return 0;
}

static int
cgn_bpf_bind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct cgn_bpf_ctx *x = udata;
	struct cgn_ctx *c;

	/* lazy start: initialize whole cgn contexts on first use */
	list_for_each_entry(c, &x->cgn_list, bpf_list) {
		if (cgn_ctx_start(c) < 0)
			return -1;
	}

	return 0;
}

static void
cgn_bpf_unbind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
}


static struct gtp_bpf_prog_tpl gtp_bpf_tpl_cgn = {
	.name = "cgn",
	.description = "carrier-grade-nat",
	.alloc = cgn_bpf_alloc,
	.release = cgn_bpf_release,
	.prepare = cgn_bpf_prepare,
	.loaded = cgn_bpf_loaded,
	.iface_bind = cgn_bpf_bind_itf,
	.iface_unbind = cgn_bpf_unbind_itf,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_cgn);
}
