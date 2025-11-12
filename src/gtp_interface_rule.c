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
#include "gtp_bpf_utils.h"
#include "utils.h"
#include "jhash.h"
#include "vty.h"
#include "addr.h"
#include "table.h"
#include "logger.h"
#include "bpf/lib/if_rule-def.h"

/* max number of interfaces (for automatic rule setting) on a bpf program */
#define IR_MAX			6

typedef __typeof__(((struct gtp_interface_rules_ops *)0)->key_stringify) key_stringify_t;

/* single rule */
struct stored_rule {
	struct gtp_if_rule		r;
	bool				installed;
	struct list_head		list;
	struct hlist_node		hlist;
};

/* bpf data, per bpf program */
struct gtp_bpf_interface_rule {
	struct bpf_map			*acl;

	/* single rules that goes into bpf map */
	int				key_size;
	key_stringify_t			key_stringify_cb;
	bool				rule_list_sorted;
	struct list_head		rule_list;
	struct hlist_head		rule_hlist[IF_RULE_MAX_RULE];

	/* interface rules */
	struct interface_rule		*ir_ingress[IR_MAX];
	struct interface_rule		*ir_egress[IR_MAX];
	uint32_t			ir_ingress_n;
	uint32_t			ir_egress_n;
};


/* interface's ruleset */
struct interface_rule {
	struct gtp_interface_rules_ctx	*irc;
	struct gtp_interface		*iface;
	bool				ingress;
	struct list_head		list;

	struct gtp_bpf_interface_rule	*bir;
	bool				bound;
	bool				rule_set[IR_MAX];
};

/* list of interface rulesets, context hold by user */
struct gtp_interface_rules_ctx {
	struct gtp_interface_rules_ops	ops;
	struct list_head		ir_list;
	struct list_head		list;
};

/* list of contexts */
static LIST_HEAD(ir_ctx_list);


static inline struct gtp_bpf_interface_rule *
_get_bir(struct gtp_interface *iface, int *ifindex)
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
	int r;

	if (ka->ifindex < kb->ifindex)
		return -1;
	if (ka->ifindex > kb->ifindex)
		return 1;
	r = strcmp(a->r.from->ifname, b->r.from->ifname);
	if (r < 0)
		return -1;
	if (r > 0)
		return 1;
	return a->r.prio < b->r.prio ? -1 : a->r.prio > b->r.prio ? 1 : 0;
}

static inline uint32_t
_rule_hash(const struct gtp_if_rule *r)
{
	return jhash(r->key, r->key_size, 0) % IF_RULE_MAX_RULE;
}

static inline struct stored_rule *
_rule_find(struct gtp_bpf_interface_rule *bir, const struct gtp_if_rule *r)
{
	struct stored_rule *sr;
	uint32_t h = _rule_hash(r);

	hlist_for_each_entry(sr, &bir->rule_hlist[h], hlist) {
		if (!memcmp(sr->r.key, r->key, r->key_size) &&
		    sr->r.from == r->from &&
		    sr->r.to == r->to &&
		    sr->r.prio == r->prio) {
			return sr;
		}
	}
	return NULL;
}

static inline struct stored_rule *
_rule_find_first(struct gtp_bpf_interface_rule *bir, const struct gtp_if_rule *r,
		 uint32_t h)
{
	struct stored_rule *sr;

	hlist_for_each_entry(sr, &bir->rule_hlist[h], hlist) {
		if (!memcmp(sr->r.key, r->key, r->key_size))
			return sr;
	}
	return NULL;
}

static struct stored_rule *
_rule_find_next(struct gtp_bpf_interface_rule *bir, const struct gtp_if_rule *r,
		uint32_t h, struct stored_rule *sr)
{
	hlist_for_each_entry_continue(sr, hlist) {
		if (!memcmp(sr->r.key, r->key, r->key_size))
			return sr;
	}
	return NULL;
}

static struct stored_rule *
_rule_store(struct gtp_bpf_interface_rule *bir, struct gtp_if_rule *r)
{
	uint32_t h = jhash(r->key, r->key_size, 0) % IF_RULE_MAX_RULE;
	struct stored_rule *sr;

	sr = calloc(1, sizeof (*sr) + r->key_size);
	sr->r = *r;
	sr->r.key = sr + 1;
	memcpy(sr + 1, r->key, r->key_size);
	list_add(&sr->list, &bir->rule_list);
	hlist_add_head(&sr->hlist, &bir->rule_hlist[h]);
	bir->rule_list_sorted = false;
	return sr;
}

static void
_rule_del(struct stored_rule *sr)
{
	list_del(&sr->list);
	hlist_del(&sr->hlist);
	free(sr);
}

static int
_rule_set_key_base(struct gtp_bpf_interface_rule *bir, int ifindex, struct gtp_if_rule *r)
{
	struct if_rule_key_base *k = r->key;

	if (bir->key_size != r->key_size) {
		log_message(LOG_INFO, "interface_rule: key size mismatch (%d != %d)",
			    bir->key_size, r->key_size);
		return -1;
	}

	/* set up key */
	k->ifindex = ifindex;
	k->vlan_id = r->from->vlan_id;
	if (r->from->tunnel_mode > 0) {
		k->tun_local = addr_toip4(&r->from->tunnel_local);
		k->tun_remote = addr_toip4(&r->from->tunnel_remote);
		k->flags = r->from->tunnel_mode == 1 ?
			IF_RULE_FL_TUNNEL_GRE :	IF_RULE_FL_TUNNEL_IPIP;
	} else {
		k->tun_local = 0;
		k->tun_remote = 0;
		k->flags = 0;
	}

	return 0;
}

static int
_rule_install(struct gtp_bpf_interface_rule *bir, struct gtp_if_rule *r,
	      bool overwrite)
{
	uint32_t nr_cpus = bpf_num_possible_cpus();
	struct if_rule_key_base *k = r->key;
	struct if_rule aar[nr_cpus];
	struct if_rule *ar = &aar[0];
	int i, ret;

	memset(aar, 0x00, sizeof (aar));

	/* set up rule */
	ar->action = r->action;
	ar->table = r->from->table_id;
	if (r->to != NULL) {
		ar->vlan_id = r->to->vlan_id;
		if (r->to->tunnel_mode == 1) {
			ar->tun_remote = addr_toip4(&r->to->tunnel_remote);
			ar->flags |= IF_RULE_FL_TUNNEL_GRE;
		} else if (r->to->tunnel_mode == 2) {
			ar->tun_remote = addr_toip4(&r->to->tunnel_remote);
			ar->flags |= IF_RULE_FL_TUNNEL_IPIP;
		}

		/* when output interface is a sub-interface, we force output
		 * ifindex to it (otherwise bpf_fib_lookup will send from it) */
		if (r->to->link_iface)
			ar->ifindex = r->to->link_iface->ifindex;
	}

	printf("add acl if:%d vlan:%d ip-table:%d tun:%d/%x/%x sizeof:%d\n",
	       k->ifindex, k->vlan_id, r->from->table_id,
	       r->from->tunnel_mode, k->tun_local, k->tun_remote, r->key_size);

	for (i = 1; i < nr_cpus; i++)
		aar[i] = aar[0];

	ret = bpf_map__update_elem(bir->acl, k, r->key_size,
				   ar, sizeof (aar),
				   overwrite ? 0 : BPF_NOEXIST);
	if (ret) {
		printf("cannot %s rule! (%d / %m)\n",
		       overwrite ? "update" : "add", ret);
		return -1;
	}

	return 0;
}

static void
_rule_uninstall(struct gtp_bpf_interface_rule *bir, struct gtp_if_rule *r)
{
	int ret;

	ret = bpf_map__delete_elem(bir->acl, r->key, r->key_size, 0);
	if (ret)
		printf("cannot delete rule! (%d / %m)\n", ret);
}

static int
_if_rule_add(struct gtp_if_rule *r)
{
	struct gtp_bpf_interface_rule *bir;
	struct stored_rule *sr;
	int ifindex, ret = -1;
	uint32_t h;

	/* retrieve 'physical' interface. we will install rules on it */
	bir = _get_bir(r->from, &ifindex);
	if (bir == NULL)
		return -1;

	if (_rule_set_key_base(bir, ifindex, r) < 0)
		return -1;

	h = _rule_hash(r);
	sr = _rule_find_first(bir, r, h);
	while (sr != NULL && !sr->installed)
		sr = _rule_find_next(bir, r, h, sr);
	if (sr == NULL || r->prio < sr->r.prio) {
		/* install new rule or with higher priority */
		ret = _rule_install(bir, r, sr != NULL);
		if (ret < 0)
			return -1;
		if (sr != NULL)
			sr->installed = false;
	}
	sr = _rule_store(bir, r);
	sr->installed = ret == 0;

	return 0;
}


static void
_if_rule_del(struct gtp_if_rule *r)
{
	struct gtp_bpf_interface_rule *bir;
	struct stored_rule *sr;
	int ifindex;

	bir = _get_bir(r->from, &ifindex);
	if (bir == NULL)
		return;

	if (_rule_set_key_base(bir, ifindex, r) < 0)
		return;
	sr = _rule_find(bir, r);
	if (sr != NULL) {
		if (sr->installed)
			_rule_uninstall(bir, &sr->r);
		_rule_del(sr);
	}
}

int
gtp_interface_rule_set(struct gtp_if_rule *r, bool add)
{
	if (add)
		return _if_rule_add(r);
	_if_rule_del(r);
	return 0;
}


static void
gtp_interface_rule_del_iface(struct gtp_interface *iface)
{
	struct gtp_bpf_interface_rule *bir;
	struct stored_rule *sr, *sr_tmp;

	bir = _get_bir(iface, NULL);
	if (bir == NULL)
		return;

	list_for_each_entry_safe(sr, sr_tmp, &bir->rule_list, list) {
		if (sr->r.from == iface || sr->r.from->link_iface == iface ||
		    sr->r.to == iface || sr->r.to->link_iface == iface) {
			if (sr->installed)
				_rule_uninstall(bir, &sr->r);
			_rule_del(sr);
		}
	}
}


/*
 * interface rules - higher level api, automatically set rules
 * between registered interfaces.
 */


static inline void
_ir_rules_exec(struct gtp_bpf_interface_rule *bir, bool ingress,
	       gtp_interface_rules_ctx_exec_cb_t cb, void *ud)
{
	struct interface_rule *ir, *rir;
	uint32_t i, j;

	for (i = 0; i < bir->ir_ingress_n; i++) {
		ir = bir->ir_ingress[i];
		for (j = 0; j < bir->ir_egress_n; j++) {
			rir = bir->ir_egress[j];
			if (ir->rule_set[j] && rir->rule_set[i]) {
				if (ir->ingress == ingress)
					cb(ud, ir->iface, ir->ingress, rir->iface);
				else
					cb(ud, rir->iface, rir->ingress, ir->iface);
			}
		}
	}
}

static inline void
_ir_rules_set(struct interface_rule *ir)
{
	struct gtp_bpf_interface_rule *bir = ir->bir;
	struct gtp_interface_rules_ctx *irc = ir->irc;
	struct interface_rule **prir, *rir;
	uint32_t i, rn;

	prir = ir->ingress ? bir->ir_egress : bir->ir_ingress;
	rn = ir->ingress ? bir->ir_egress_n : bir->ir_ingress_n;

	for (i = 0; i < rn; i++) {
		rir = prir[i];
		if (!ir->rule_set[i] && ir->bound && rir->bound) {
			if (ir->iface != rir->iface || ir->ingress)
				irc->ops.rule_set(irc->ops.ud,
						  ir->iface, ir->ingress,
						  rir->iface, true);
			if (ir->iface != rir->iface || !ir->ingress)
				irc->ops.rule_set(irc->ops.ud,
						  rir->iface, rir->ingress,
						  ir->iface, true);
			ir->rule_set[i] = true;
			rir->rule_set[i] = true;
		}
		if (ir->rule_set[i] && (!ir->bound || !rir->bound)) {
			if (ir->iface != rir->iface || ir->ingress)
				irc->ops.rule_set(irc->ops.ud,
						  ir->iface, ir->ingress,
						  rir->iface, false);
			if (ir->iface != rir->iface || !ir->ingress)
				irc->ops.rule_set(irc->ops.ud,
						  rir->iface, rir->ingress,
						  ir->iface, false);
			ir->rule_set[i] = false;
			rir->rule_set[i] = false;
		}
	}
}


static void
_ir_event_cb(struct gtp_interface *iface, enum gtp_interface_event type,
	     void *ud, void *arg)
{
	struct interface_rule *ir = ud;
	struct interface_rule **pir;
	struct gtp_bpf_interface_rule *bir = ir->bir;
	uint32_t i, *pn;

	log_message(LOG_DEBUG, "iface:%s event %d %s", iface->ifname, type,
		    ir->ingress ? "ingress" : "egress");

	switch (type) {
	case GTP_INTERFACE_EV_PRG_BIND:
		ir->bound = true;
		_ir_rules_set(ir);
		break;
	case GTP_INTERFACE_EV_PRG_UNBIND:
		ir->bound = false;
		_ir_rules_set(ir);
		break;
	case GTP_INTERFACE_EV_DESTROYING:
		ir->bound = false;
		_ir_rules_set(ir);
		gtp_interface_unregister_event(iface, _ir_event_cb, ir);
		pir = ir->ingress ? bir->ir_ingress : bir->ir_egress;
		pn = ir->ingress ? &bir->ir_ingress_n : &bir->ir_egress_n;
		for (i = 0; i < *pn; i++) {
			if (ir == pir[i]) {
				pir[i] = pir[--*pn];
				break;
			}
		}
		list_del(&ir->list);
		free(ir);
		break;
	default:
		break;
	}
}


static int
_ir_attach(struct interface_rule *ir, struct gtp_bpf_interface_rule *bir)
{
	struct interface_rule **pir;
	uint32_t i, *pn;

	if (!bir->key_stringify_cb && ir->irc->ops.key_stringify)
		bir->key_stringify_cb = ir->irc->ops.key_stringify;

	pir = ir->ingress ? bir->ir_ingress : bir->ir_egress;
	pn = ir->ingress ? &bir->ir_ingress_n : &bir->ir_egress_n;
	if (*pn == IR_MAX) {
		errno = ENOSPC;
		return -1;
	}
	for (i = 0; i < *pn; i++) {
		if (ir->iface == pir[i]->iface) {
			errno = EEXIST;
			return -1;
		}
	}
	pir[*pn] = ir;
	++*pn;

	ir->bir = bir;
	gtp_interface_register_event(ir->iface, _ir_event_cb, ir);
	return 0;
}

static int
_ir_detach(struct interface_rule *ir)
{
	struct gtp_bpf_interface_rule *bir = ir->bir;
	struct interface_rule **pir;
	uint32_t i, n;

	pir = ir->ingress ? bir->ir_ingress : bir->ir_egress;
	n = ir->ingress ? bir->ir_ingress_n : bir->ir_egress_n;
	for (i = 0; i < n; i++) {
		if (ir->iface == pir[i]->iface) {
			_ir_event_cb(ir->iface, GTP_INTERFACE_EV_DESTROYING,
				      pir[i], NULL);
			return 1;
		}
	}
	return 0;
}

static inline struct interface_rule *
_ir_find(struct gtp_interface_rules_ctx *irc, struct gtp_interface *iface,
	 bool ingress)
{
	struct interface_rule *ir;

	list_for_each_entry(ir, &irc->ir_list, list)
		if (iface == ir->iface && ingress == ir->ingress)
			return ir;
	return NULL;
}

int
gtp_interface_rules_ctx_add(struct gtp_interface_rules_ctx *irc,
			    struct gtp_interface *iface,
			    bool ingress)
{
	struct gtp_bpf_interface_rule *bir;
	struct interface_rule *ir;

	ir = _ir_find(irc, iface, ingress);
	if (ir != NULL) {
		errno = EEXIST;
		return -1;
	}

	ir = calloc(1, sizeof (*ir));
	if (ir == NULL)
		return -1;
	ir->irc = irc;
	ir->iface = iface;
	ir->ingress = ingress;
	ir->bound = false;
	list_add(&ir->list, &irc->ir_list);

	bir = _get_bir(iface, NULL);
	if (bir != NULL)
		return _ir_attach(ir, bir);
	return 0;
}

void
gtp_interface_rules_ctx_del(struct gtp_interface_rules_ctx *irc,
			   struct gtp_interface *iface,
			   bool ingress)
{
	struct interface_rule *ir;

	ir = _ir_find(irc, iface, ingress);
	if (ir == NULL)
		return;

	if (ir->bir != NULL) {
		if (_ir_detach(ir) == 1)
			return;
	}
	list_del(&ir->list);
	free(ir);
}

/* exec 'cb' on each installed link between ingress and egress */
void
gtp_interface_rules_ctx_exec(struct gtp_interface_rules_ctx *irc, bool ingress,
			     gtp_interface_rules_ctx_exec_cb_t cb)
{
	struct interface_rule *ir;

	list_for_each_entry(ir, &irc->ir_list, list) {
		if (ir->bir != NULL) {
			_ir_rules_exec(ir->bir, ingress, cb, irc->ops.ud);
			break;
		}
	}
}

int
gtp_interface_rules_ctx_list_bound(struct gtp_interface_rules_ctx *irc, bool ingress,
				   struct gtp_interface **iface_list, int iface_n)
{
	struct gtp_bpf_interface_rule *bir = NULL;
	struct interface_rule *ir, **pir;
	uint32_t i, n, k;

	list_for_each_entry(ir, &irc->ir_list, list) {
		if ((bir = ir->bir) != NULL)
			break;
	}
	if (bir == NULL)
		return -1;

	pir = ingress ? bir->ir_ingress : bir->ir_egress;
	n = ingress ? bir->ir_ingress_n : bir->ir_egress_n;
	for (i = 0, k = 0; k < n && i < iface_n; i++) {
		if (pir[i]->bound)
			iface_list[k++] = pir[i]->iface;
	}
	return k;
}



struct gtp_interface_rules_ctx *
gtp_interface_rules_ctx_new(const struct gtp_interface_rules_ops *ops)
{
	struct gtp_interface_rules_ctx *irc;

	irc = calloc(1, sizeof (*irc));
	if (irc == NULL)
		return NULL;
	irc->ops = *ops;
	INIT_LIST_HEAD(&irc->ir_list);
	list_add(&irc->list, &ir_ctx_list);
	return irc;
}

void
gtp_interface_rules_ctx_release(struct gtp_interface_rules_ctx *irc)
{
	struct interface_rule *ir, *ir_tmp;

	list_for_each_entry_safe(ir, ir_tmp, &irc->ir_list, list) {
		if (ir->bir == NULL || _ir_detach(ir) != 1)
			free(ir);
	}
	list_del(&irc->list);
	free(irc);
}


/*
 *	vty dump
 */

int
gtp_interface_rule_show_stored(struct gtp_bpf_prog *p, void *arg)
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
		*buf = 0;
		if (r->key_stringify_cb != NULL && sr->r.key_size > sizeof (*k))
			r->key_stringify_cb(&sr->r, buf, sizeof (buf), false);
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
		vty_out(vty, ", prio %d%s", sr->r.prio, VTY_NEWLINE);
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

int
gtp_interface_rule_show(struct gtp_bpf_prog *p, void *arg)
{
	struct gtp_bpf_interface_rule *r = gtp_bpf_prog_tpl_data_get(p, "if_rules");
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct if_rule aar[nr_cpus];
	struct if_rule *ar = &aar[0];
	struct gtp_if_rule gr = {};
	struct if_rule_key_base *k;
	struct stored_rule *sr;
	struct table *tbl;
	struct vty *vty = arg;
	char match[50], iface_buf[50], buf[200], b2[60];
	void *key = NULL;
	int i, l, err;
	uint32_t h;

	if (r == NULL || r->acl == NULL)
		return 0;

	tbl = table_init(5, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "iface", "match", "pkt in", "bytes in", "pkt fwd");

	/* Walk hashtab */
	uint8_t key_stor[r->key_size];
	gr.key_size = r->key_size;
	memset(aar, 0x00, sizeof (aar));
	while (!bpf_map__get_next_key(r->acl, key, &key_stor, r->key_size)) {
		key = key_stor;
		err = bpf_map__lookup_elem(r->acl, key, r->key_size,
					   ar, sizeof (aar), 0);
		if (err) {
			vty_out(vty, "%% error fetching value from table (%m)\n");
			break;
		}

		gr.key = key;
		h = _rule_hash(&gr);
		sr = _rule_find_first(r, &gr, h);
		while (sr && !sr->installed)
			sr = _rule_find_next(r, &gr, h, sr);
		if (sr == NULL) {
			vty_out(vty, "%% sync failure: bpf key not in userapp\n");
			continue;
		}
		k = sr->r.key;

		/* build iface string */
		snprintf(iface_buf, sizeof (iface_buf), "%s -> %s",
			 sr->r.from->ifname, sr->r.to->ifname);

		/* build match string */
		l = 0;
		*buf = 0;
		if (r->key_stringify_cb != NULL && sr->r.key_size > sizeof (*k))
			r->key_stringify_cb(&sr->r, buf, sizeof (buf), true);
		if (k->vlan_id)
			l += scnprintf(match + l, sizeof (match) - l, "vlan:%d ",
				       k->vlan_id);
		if (sr->r.from->tunnel_mode)
			l += scnprintf(match + l, sizeof (match) - l, "%s:%s ",
				sr->r.from->tunnel_mode == 1 ? "gre" : "ipip",
				inet_ntop(AF_INET, &k->tun_remote, b2, sizeof (b2)));
		if (*buf)
			l += scnprintf(match + l, sizeof (match) - l, "%s ", buf);
		if (!l)
			snprintf(match, sizeof (match), "all");
		else
			match[l - 1] = 0;


		/* compute metrics */
		for (i = 1; i < nr_cpus; i++) {
			ar->pkt_in += aar[i].pkt_in;
			ar->pkt_fwd += aar[i].pkt_fwd;
			ar->bytes_in += aar[i].bytes_in;
		}

		table_add_row_fmt(tbl, "%s|%s|%lld|%lld|%lld",
				  iface_buf, match,
				  ar->pkt_in, ar->bytes_in, ar->pkt_fwd);
	}

	table_vty_out(tbl, vty);
	table_destroy(tbl);
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
	struct gtp_bpf_interface_rule *r = udata, *bir;
	struct gtp_interface_rules_ctx *irc;
	struct interface_rule *ir;

	iface->rules = r;

	list_for_each_entry(irc, &ir_ctx_list, list) {
		list_for_each_entry(ir, &irc->ir_list, list) {
			if (ir->bir == NULL) {
				bir = _get_bir(ir->iface, NULL);
				if (bir == r)
					_ir_attach(ir, bir);
			}
		}
	}

	return 0;
}

static void
gtp_ifrule_unbind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct gtp_bpf_interface_rule *r = udata;
	struct interface_rule *ir;
	uint32_t i;

	for (i = 0; i < r->ir_ingress_n; i++) {
		ir = r->ir_ingress[i];
		if (ir->iface != iface && ir->iface->link_iface != iface)
			continue;
		gtp_interface_unregister_event(ir->iface, _ir_event_cb, ir);
		ir->bir = NULL;
		ir->bound = false;
		memset(ir->rule_set, 0x00, sizeof (ir->rule_set));
		r->ir_ingress[i--] = r->ir_ingress[--r->ir_ingress_n];
	}
	for (i = 0; i < r->ir_egress_n; i++) {
		ir = r->ir_egress[i];
		if (ir->iface != iface && ir->iface->link_iface != iface)
			continue;
		gtp_interface_unregister_event(ir->iface, _ir_event_cb, ir);
		ir->bir = NULL;
		ir->bound = false;
		memset(ir->rule_set, 0x00, sizeof (ir->rule_set));
		r->ir_egress[i--] = r->ir_egress[--r->ir_egress_n];
	}

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
