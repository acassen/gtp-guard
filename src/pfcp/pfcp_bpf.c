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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdlib.h>

#include "inet_utils.h"
#include "gtp_interface.h"
#include "pfcp_router.h"
#include "pfcp_bpf.h"
#include "logger.h"
#include "bpf/lib/upf-def.h"


/* Extern data */
extern struct data *daemon_data;


static void *
pfcp_bpf_alloc(struct gtp_bpf_prog *p)
{
	struct pfcp_bpf_data *bd;

	bd = calloc(1, sizeof (*bd));
	if (bd == NULL)
		return NULL;

	INIT_LIST_HEAD(&bd->pfcp_router_list);
	return bd;
}

static void
pfcp_bpf_release(struct gtp_bpf_prog *p, void *udata)
{
	struct pfcp_bpf_data *bd = udata;
	struct pfcp_router *c, *tmp;

	list_for_each_entry_safe(c, tmp, &bd->pfcp_router_list, bpf_list) {
		c->bpf_prog = NULL;
		c->bpf_data = NULL;
		list_del_init(&c->bpf_list);
	}
	free(bd);
}

static int
pfcp_bpf_load_maps(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct pfcp_bpf_data *bd = udata;

	bd->teid_rule = gtp_bpf_prog_load_map(p->load.obj, "teid_rule");
	if (!bd->teid_rule)
		return -1;

	return 0;
}


static struct gtp_bpf_prog_tpl pfcp_bpf_tpl = {
	.name = "upf",
	.description = "3GPP User Plane Function",
	.alloc = pfcp_bpf_alloc,
	.loaded = pfcp_bpf_load_maps,
	.release = pfcp_bpf_release,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&pfcp_bpf_tpl);
}
