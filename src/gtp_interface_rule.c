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
#include "addr.h"


/*
 * TODO:
 *
 * save rules in userspace,
 * and if there are multiple rules on one interface,
 * then apply (write on bpf map) the one with highest prio.
 *
 * if rules gets added/modified, update bpf map accordingly.
 */


struct gtp_bpf_interface_rule
{
	struct bpf_map		*acl;
};


void
gtp_interface_rule_add(struct gtp_interface *from, struct gtp_interface *to,
		       int action, int prio)
{
	struct gtp_bpf_interface_rule *r;
	struct gtp_interface *iface = from;
	struct if_rule_key k = {};
	struct if_rule ar = {};
	int ret;

	/* if program is not loaded on this interface, and this interface is virtual
	 * (and has pointer to real device), then use real device ifindex/bpf map */
	if (from->bpf_prog == NULL && from->link_iface)
		iface = from->link_iface;

	r = iface->rules;
	printf("%s action %d rules:%p ifindex:%d\n", __func__, action,
	       r, iface->ifindex);
	if (!r)
		return;

	k.ifindex = iface->ifindex;
	k.vlan_id = from->vlan_id;
	switch (from->tunnel_mode) {
	case 1:
		k.gre_remote = addr_toip4(&from->tunnel_remote);
		break;
	default:
		break;
	}

	ar.action = action;
	ar.table = from->table_id;
	ar.vlan_id = to->vlan_id;

	switch (to->tunnel_mode) {
	case 1:
		ar.gre_remote = addr_toip4(&to->tunnel_remote);
		break;
	default:
		break;
	}

	/* when output interface is a sub-interface, we force output
	 * ifindex to it (otherwise bpf_fib_lookup will send from it) */
	if (to->link_iface)
		ar.ifindex = to->link_iface->ifindex;

	printf("add acl if:%d vlan:%d ip-table:%d gre:%x sizeof:%ld\n",
	       k.ifindex, k.vlan_id, ar.table,
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
	struct gtp_bpf_interface_rule *r;
	struct gtp_interface *iface = from;
	struct if_rule_key k = {};

	if (from->bpf_prog == NULL && from->link_iface != NULL)
		iface = from->link_iface;

	r = iface->rules;
	if (!r)
		return;

	k.ifindex = iface->ifindex;
	k.vlan_id = from->vlan_id;

	bpf_map__delete_elem(r->acl, &k, sizeof (k), 0);
}


/*
 *	eBPF template for interface
 */

static int
gtp_ifrule_loaded(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct gtp_bpf_interface_rule *r = udata;

	r->acl = bpf_object__find_map_by_name(p->load.obj, "if_rule");
	if (r->acl == NULL)
		return -1;

	return 0;
}

static int
gtp_ifrule_bind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct gtp_bpf_interface_rule *r = udata;

	iface->rules = r;

	return 0;
}

static void
gtp_ifrule_unbind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	iface->rules = NULL;
}


static struct gtp_bpf_prog_tpl gtp_interface_rule_module = {
	.name = "if_rules",
	.description = "iface-rule-dispatcher",
	.udata_alloc_size = sizeof (struct gtp_bpf_interface_rule),
	.loaded = gtp_ifrule_loaded,
	.iface_bind = gtp_ifrule_bind_itf,
	.iface_unbind = gtp_ifrule_unbind_itf,
};

static void __attribute__((constructor))
gtp_interface_rule_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_interface_rule_module);
}
