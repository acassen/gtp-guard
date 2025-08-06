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

/* local includes */
#include "gtp_interface.h"
#include "bpf/lib/if_rule-def.h"


struct gtp_bpf_interface_rule
{
	struct bpf_map		*acl;
};


void
gtp_interface_rule_add(struct gtp_interface *from, struct gtp_interface *to, int action)
{
	struct gtp_bpf_interface_rule *r = from->bpf_itf;
	struct if_rule_key k = {};
	struct if_rule ar = {};
	int ret;

	k.ifindex = from->ifindex;
	k.vlan_id = from->vlan_id;

	ar.action = action;
	//ar.table = to->force_ip_table;
	ar.vlan_id = to->vlan_id;

	printf("add acl if:%d vlan:%d gre:%d sizeof:%ld\n", k.ifindex, k.vlan_id,
	       k.gre_remote, sizeof (k));

	ret = bpf_map__update_elem(r->acl, &k, sizeof (k),
				   &ar, sizeof (ar), BPF_NOEXIST);
	if (ret) {
		printf("cannot add / update rule! (%d)\n", ret);
	}
}

void
gtp_interface_rule_del(struct gtp_interface *from)
{
	struct gtp_bpf_interface_rule *r = from->bpf_itf;
	struct if_rule_key k = {};

	k.ifindex = from->ifindex;
	k.vlan_id = from->vlan_id;

	bpf_map__delete_elem(r->acl, &k, sizeof (k), 0);
}


/*
 *	eBPF template for interface
 */

static int
gtp_ifrule_opened(struct gtp_bpf_prog *p, void *udata)
{
	struct gtp_bpf_interface_rule *r = udata;

	r->acl = bpf_object__find_map_by_name(p->bpf_obj, "if_rule");
	if (r->acl == NULL)
		return -1;

	return 0;
}

static int
gtp_ifrule_bind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct gtp_bpf_interface_rule *r = udata;

	iface->bpf_itf = r;

	return 0;
}


static struct gtp_bpf_prog_tpl gtp_interface_rule_module = {
	.name = "if_rules",
	.description = "iface-rule-dispatcher",
	.udata_alloc_size = sizeof (struct gtp_bpf_interface_rule),
	.opened = gtp_ifrule_opened,
	.iface_bind = gtp_ifrule_bind_itf,
};

static void __attribute__((constructor))
gtp_interface_rule_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_interface_rule_module);
}
