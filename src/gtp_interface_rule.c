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
#include "gtp_guard.h"
#include "bpf/lib/if_rule-def.h"


typedef struct _gtp_bpf_interface_rule
{
	struct bpf_map		*acl;
} gtp_bpf_interface_rule_t;


void
gtp_interface_rule_add(gtp_interface_t *from, gtp_interface_t *to, int action)
{
	gtp_bpf_interface_rule_t *r = from->bpf_itf;
	struct if_rule_key k = {};
	struct if_rule ar = {};
	int ret;

	k.ifindex = from->ifindex;
	k.vlan_id = from->vlan_id;

	ar.action = action;
	ar.ifindex = to->ifindex;
	ar.vlan_id = to->vlan_id;
	memcpy(ar.h_local, to->hw_addr, ETH_ALEN);
	memcpy(ar.h_remote, to->direct_tx_hw_addr, ETH_ALEN);

	printf("add acl if:%d vlan:%d gre:%d sizeof:%ld\n", k.ifindex, k.vlan_id,
	       k.gre_remote, sizeof (k));

	ret = bpf_map__update_elem(r->acl, &k, sizeof (k),
				   &ar, sizeof (ar), BPF_NOEXIST);
	if (ret) {
		printf("cannot add / update rule! (%d)\n", ret);
	}
}

void
gtp_interface_rule_del(gtp_interface_t *from)
{
	gtp_bpf_interface_rule_t *r = from->bpf_itf;
	struct if_rule_key k = {};

	k.ifindex = from->ifindex;
	k.vlan_id = from->vlan_id;

	bpf_map__delete_elem(r->acl, &k, sizeof (k), 0);
}

/* called by netlink when an ethernet address change */
void
gtp_interface_rule_lladdr_updated(gtp_interface_t *iface)
{
	gtp_bpf_interface_rule_t *r = iface->bpf_itf;
	struct if_rule_key key = {}, next_key;
	struct if_rule ifr = {};
	int err;

	if (r == NULL)
		return;

	/* walk if_rule and replace all occurences HW of iface->ifindex  */
	while (bpf_map__get_next_key(r->acl, &key, &next_key, sizeof(key)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(r->acl, &key, sizeof(key),
					   &ifr, sizeof (ifr), 0);
		if (err) {
			printf("cannot get/update rule! (%d)\n", err);
			break;
		}

		if (ifr.ifindex != iface->ifindex)
			continue;

		/* update iface's eth_dst address */
		memcpy(ifr.h_remote, iface->direct_tx_hw_addr, ETH_ALEN);
		err = bpf_map__update_elem(r->acl, &key, sizeof(key),
					   &ifr, sizeof(ifr), BPF_EXIST);
		if (err) {
			printf("cannot update rule! (%d)\n", err);
		}
	}
}



/*
 *	eBPF template for interface
 */

static int
gtp_ifrule_opened(gtp_bpf_prog_t *p, void *udata)
{
	gtp_bpf_interface_rule_t *r = udata;

	r->acl = bpf_object__find_map_by_name(p->bpf_obj, "if_rule");
	if (r->acl == NULL)
		return -1;

	return 0;
}

static int
gtp_ifrule_bind_itf(gtp_bpf_prog_t *p, void *udata, gtp_interface_t *iface)
{
	gtp_bpf_interface_rule_t *r = udata;

	iface->bpf_itf = r;

	return 0;
}


static gtp_bpf_prog_tpl_t gtp_interface_rule_module = {
	.name = "if_rules",
	.description = "iface-rule-dispatcher",
	.udata_alloc_size = sizeof (gtp_bpf_interface_rule_t),
	.opened = gtp_ifrule_opened,
	.iface_bind = gtp_ifrule_bind_itf,
};

static void __attribute__((constructor))
gtp_interface_rule_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_interface_rule_module);
}
