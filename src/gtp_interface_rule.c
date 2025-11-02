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

#include <arpa/inet.h>

/* local includes */
#include "gtp_interface.h"
#include "vty.h"
#include "addr.h"
#include "logger.h"
#include "bpf/lib/if_rule-def.h"


struct gtp_bpf_interface_rule
{
	struct bpf_map		*acl;
	int			key_size;
	key_stringify_cb_t	key_stringify_cb;
	bool			rule_list_sorted;
	struct list_head	rule_list;
};


struct stored_rule
{
	struct gtp_if_rule	r;
	bool			installed;
	struct list_head	list;
};

static inline struct gtp_bpf_interface_rule *
_get_ir(struct gtp_interface *iface, int *ifindex)
{
	/* retrieve 'physical' interface, where bpf map are located */
	if (iface->bpf_prog == NULL && iface->link_iface)
		iface = iface->link_iface;
	if (ifindex)
		*ifindex = iface->ifindex;
	return iface->rules && iface->rules->acl ? iface->rules : NULL;
}

static int
_rule_sort_cb(struct list_head *al, struct list_head *bl)
{
	struct stored_rule *a = container_of(al, struct stored_rule, list);
	struct stored_rule *b = container_of(bl, struct stored_rule, list);
	struct if_rule_key_base *ka = a->r.key;
	struct if_rule_key_base *kb = b->r.key;

	if (ka->ifindex < kb->ifindex)
		return -1;
	if (ka->ifindex > kb->ifindex)
		return 1;
	return strcmp(a->r.from->ifname, b->r.from->ifname);
}

struct stored_rule *
_rule_find(struct gtp_bpf_interface_rule *ir, const struct gtp_if_rule *r,
	   bool exact)
{
	struct stored_rule *sr;

	list_for_each_entry(sr, &ir->rule_list, list) {
		if (sr->r.from == r->from &&
		    !memcmp(sr->r.key, r->key, r->key_size) &&
		    (!exact || (sr->r.to == r->to &&
				sr->r.prio == r->prio))) {
			return sr;
		}
	}
	return NULL;
}

static struct stored_rule *
_rule_store(struct gtp_bpf_interface_rule *ir, struct gtp_if_rule *r)
{
	struct stored_rule *sr;

	sr = calloc(1, sizeof (*sr) + r->key_size);
	sr->r = *r;
	sr->r.key = sr + 1;
	memcpy(sr + 1, r->key, r->key_size);
	list_add(&sr->list, &ir->rule_list);
	ir->rule_list_sorted = false;
	return sr;
}

static void
_rule_del(struct stored_rule *sr)
{
	list_del(&sr->list);
	free(sr);
}

static int
_rule_set_key_base(struct gtp_bpf_interface_rule *ir, int ifindex, struct gtp_if_rule *r)
{
	struct if_rule_key_base *k = r->key;

	if (ir->key_size != r->key_size) {
		log_message(LOG_INFO, "interface_rule: key size mismatch (%d != %d)",
			    ir->key_size, r->key_size);
		return -1;
	}

	/* set up key */
	k->ifindex = ifindex;
	k->vlan_id = r->from->vlan_id;
	k->tun_local = 0;
	k->tun_remote = 0;
	if (r->from->tunnel_mode > 0) {
		k->tun_local = addr_toip4(&r->from->tunnel_local);
		k->tun_remote = addr_toip4(&r->from->tunnel_remote);
	}

	return 0;
}

static int
_rule_install(struct gtp_bpf_interface_rule *ir, struct gtp_if_rule *r,
	      bool overwrite)
{
	struct if_rule_key_base *k = r->key;
	struct if_rule ar = {};
	int ret;

	/* set up rule */
	ar.action = r->action;
	ar.table = r->from->table_id;
	if (r->to != NULL) {
		ar.vlan_id = r->to->vlan_id;
		if (r->to->tunnel_mode == 1) {
			ar.tun_remote = addr_toip4(&r->to->tunnel_remote);
			ar.flags |= IF_RULE_FL_TUNNEL_GRE;
		} else if (r->to->tunnel_mode == 2) {
			ar.tun_remote = addr_toip4(&r->to->tunnel_remote);
			ar.flags |= IF_RULE_FL_TUNNEL_IPIP;
		}

		/* when output interface is a sub-interface, we force output
		 * ifindex to it (otherwise bpf_fib_lookup will send from it) */
		if (r->to->link_iface)
			ar.ifindex = r->to->link_iface->ifindex;
	}

	printf("add acl if:%d vlan:%d ip-table:%d tun:%d/%x/%x sizeof:%d\n",
	       k->ifindex, k->vlan_id, ar.table,
	       r->from->tunnel_mode, k->tun_local, k->tun_remote, r->key_size);

	ret = bpf_map__update_elem(ir->acl, k, r->key_size,
				   &ar, sizeof (ar),
				   overwrite ? 0 : BPF_NOEXIST);
	if (ret) {
		printf("cannot %s rule! (%d / %m)\n",
		       overwrite ? "update" : "add", ret);
		return -1;
	}

	return 0;
}

static void
_rule_uninstall(struct gtp_bpf_interface_rule *ir, struct gtp_if_rule *r)
{
	int ret;

	ret = bpf_map__delete_elem(ir->acl, r->key, r->key_size, 0);
	if (ret)
		printf("cannot delete rule! (%d / %m)\n", ret);
}

int
gtp_interface_rule_add(struct gtp_if_rule *r)
{
	struct gtp_bpf_interface_rule *ir;
	struct stored_rule *sr;
	int ifindex, ret = -1;

	/* retrieve 'physical' interface. we will install rules on it */
	ir = _get_ir(r->from, &ifindex);
	if (ir == NULL)
		return -1;

	if (_rule_set_key_base(ir, ifindex, r) < 0)
		return -1;
	sr = _rule_find(ir, r, false);
	if (sr == NULL || r->prio > sr->r.prio) {
		/* install new rule or with higher priority */
		ret = _rule_install(ir, r, sr != NULL);
		if (ret < 0)
			return -1;
		if (sr != NULL)
			sr->installed = false;
	}
	sr = _rule_store(ir, r);
	sr->installed = ret == 0;

	return 0;
}


void
gtp_interface_rule_del(struct gtp_if_rule *r)
{
	struct gtp_bpf_interface_rule *ir;
	struct stored_rule *sr;
	int ifindex;

	ir = _get_ir(r->from, &ifindex);
	if (ir == NULL)
		return;

	if (_rule_set_key_base(ir, ifindex, r) < 0)
		return;
	sr = _rule_find(ir, r, true);
	if (sr != NULL) {
		if (sr->installed)
			_rule_uninstall(ir, &sr->r);
		_rule_del(sr);
	}
}

void
gtp_interface_rule_del_iface(struct gtp_interface *iface)
{
	struct gtp_bpf_interface_rule *ir;
	struct stored_rule *sr, *sr_tmp;

	ir = _get_ir(iface, NULL);
	if (ir == NULL)
		return;

	list_for_each_entry_safe(sr, sr_tmp, &ir->rule_list, list) {
		if (sr->r.from == iface || sr->r.to == iface) {
			if (sr->installed)
				_rule_uninstall(ir, &sr->r);
			_rule_del(sr);
		}
	}
}


/*
 *	vty dump
 */
void
gtp_interface_rule_set_custom_key_stringify(struct gtp_bpf_prog *p, key_stringify_cb_t cb)
{
	struct gtp_bpf_interface_rule *r = gtp_bpf_prog_tpl_data_get(p, "if_rules");

	if (r != NULL)
		r->key_stringify_cb = cb;
}

int
gtp_interface_rule_show(struct gtp_bpf_prog *p, void *arg)
{
	struct gtp_bpf_interface_rule *r = gtp_bpf_prog_tpl_data_get(p, "if_rules");
	struct gtp_interface *from = NULL, *to;
	struct if_rule_key_base *k;
	struct stored_rule *sr;
	struct vty *vty = arg;
	char buf[200], b1[60], b2[60];

	if (r == NULL || r->acl == NULL)
		return 0;

	if (!list_empty(&r->rule_list) && !r->rule_list_sorted) {
		list_sort(&r->rule_list, _rule_sort_cb);
		r->rule_list_sorted = true;
	}

	list_for_each_entry(sr, &r->rule_list, list) {
		if (r->key_stringify_cb != NULL && sr->r.key_size > sizeof (*k))
			r->key_stringify_cb(&sr->r, buf, sizeof (buf));
		k = sr->r.key;

		if (sr->r.from != from) {
			if (from != NULL)
				vty_out(vty, "%s", VTY_NEWLINE);
			from = sr->r.from;
			vty_out(vty, "=== from %s (if:%d) ===\n",
				from->ifname, k->ifindex);
		}
		to = sr->r.to;

		vty_out(vty, "%c match", sr->installed ? '*' : '-');
		if (k->vlan_id)
			vty_out(vty, " vlan:%d", k->vlan_id);
		if (k->vlan_id != from->vlan_id)
			vty_out(vty, " XXX vlan mismatch XXX");
		if (from->tunnel_mode)
			vty_out(vty, " %s local:%s remote:%s",
				from->tunnel_mode == 1 ? "gre" : "ipip",
				inet_ntop(AF_INET, &k->tun_local, b1, sizeof (b1)),
				inet_ntop(AF_INET, &k->tun_remote, b2, sizeof (b2)));
		if (*buf) {
			if (from->tunnel_mode)
				vty_out(vty, "%s    and", VTY_NEWLINE);
			vty_out(vty, " %s", buf);
		}
		if (!k->vlan_id && !from->tunnel_mode && !*buf)
			vty_out(vty, " all");
		vty_out(vty, "%s", VTY_NEWLINE);
		vty_out(vty, "  -> action %d", sr->r.action);
		if (from->table_id)
			vty_out(vty, " table-id:%d", from->table_id);
		if (to->vlan_id || to->tunnel_mode)
			vty_out(vty, " encap");
		if (to->vlan_id)
			vty_out(vty, " vlan:%d", to->vlan_id);
		if (to->tunnel_mode)
			vty_out(vty, " %s:%s",
				to->tunnel_mode == 1 ? "gre" : "ipip",
				addr_stringify(&to->tunnel_remote, b1, sizeof (b1)));
		vty_out(vty, " to %s", to->ifname);
		if (to->link_iface)
			vty_out(vty, " (if:%d)", to->link_iface->ifindex);

		vty_out(vty, "%s", VTY_NEWLINE);
	}

	return 0;
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

	if (!reload) {
		r->key_size = bpf_map__key_size(r->acl);
		INIT_LIST_HEAD(&r->rule_list);
	}

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
	gtp_interface_rule_del_iface(iface);
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
