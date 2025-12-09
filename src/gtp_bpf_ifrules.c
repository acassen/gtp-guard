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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <arpa/inet.h>

/* local includes */
#include "gtp_interface.h"
#include "gtp_bpf_ifrules.h"
#include "gtp_bpf_utils.h"
#include "utils.h"
#include "jhash.h"
#include "vty.h"
#include "addr.h"
#include "table.h"
#include "logger.h"
#include "bitops.h"
#include "bpf/lib/if_rule-def.h"


/* input rule */
struct stored_rule {
	struct gtp_if_rule		r;
	bool				installed;
	struct list_head		list;
	struct hlist_node		hlist;
};

/* output rule */
struct output_rule {
	struct gtp_interface		*iface;
	int				refcnt;
	bool				installed;
	struct list_head		list;
};

/* bpf data, per bpf program */
struct gtp_bpf_ifrules {
	struct bpf_map			*if_rule;
	struct bpf_map			*if_rule_attr;

	/* single rule that ends up in bpf map */
	int				key_size;
	void				*key_cur;
	bool				rule_list_sorted;
	struct list_head		rule_list;
	struct hlist_head		rule_hlist[IF_RULE_MAX_RULE];

	/* started interfaces attached to this bpf-program */
	struct list_head		out_rule_list;
	bool				out_rule_list_sorted;
};



static inline struct gtp_bpf_ifrules *
_get_bir(struct gtp_interface *iface, int *ifindex)
{
	/* retrieve 'physical' interface, where bpf map are located */
	if (iface->bpf_prog == NULL && iface->link_iface)
		iface = iface->link_iface;
	if (ifindex)
		*ifindex = iface->ifindex;
	return iface->bpf_ifrules && iface->bpf_ifrules->if_rule ? iface->bpf_ifrules : NULL;
}

static int
_rule_sort_cb(struct list_head *al, struct list_head *bl)
{
	struct stored_rule *a = container_of(al, struct stored_rule, list);
	struct stored_rule *b = container_of(bl, struct stored_rule, list);
	struct if_rule_key_base *ka = a->r.key;
	struct if_rule_key_base *kb = b->r.key;
	const char *ifna = a->r.from ? a->r.from->ifname : "_all";
	const char *ifnb = b->r.from ? b->r.from->ifname : "_all";
	int r;

	if (ka->ifindex < kb->ifindex)
		return -1;
	if (ka->ifindex > kb->ifindex)
		return 1;
	r = strcmp(ifna, ifnb);
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
_rule_find(struct gtp_bpf_ifrules *bir, const struct gtp_if_rule *r)
{
	struct stored_rule *sr;
	uint32_t h = _rule_hash(r);

	hlist_for_each_entry(sr, &bir->rule_hlist[h], hlist) {
		if (!memcmp(sr->r.key, r->key, r->key_size) &&
		    sr->r.from == r->from &&
		    sr->r.prio == r->prio) {
			return sr;
		}
	}
	return NULL;
}

static inline struct stored_rule *
_rule_find_first(struct gtp_bpf_ifrules *bir, const struct gtp_if_rule *r,
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
_rule_find_next(struct gtp_bpf_ifrules *bir, const struct gtp_if_rule *r,
		uint32_t h, struct stored_rule *sr)
{
	hlist_for_each_entry_continue(sr, hlist) {
		if (!memcmp(sr->r.key, r->key, r->key_size))
			return sr;
	}
	return NULL;
}

static struct stored_rule *
_rule_store(struct gtp_bpf_ifrules *bir, struct gtp_if_rule *r)
{
	uint32_t h = jhash(r->key, r->key_size, 0) % IF_RULE_MAX_RULE;
	struct stored_rule *sr;

	sr = calloc(1, sizeof (*sr) + r->key_size);
	if (sr == NULL)
		return NULL;
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
_rule_set_key_base(struct gtp_bpf_ifrules *bir, int ifindex, struct gtp_if_rule *r)
{
	struct if_rule_key_base *k;

	if (r->key != NULL) {
		if (bir->key_size != r->key_size) {
			log_message(LOG_INFO, "ifr: key size mismatch (%d != %d)",
				    bir->key_size, r->key_size);
			return -1;
		}
		return 0;
	}

	if (r->from == NULL)
		return -1;

	/* set default key */
	k = bir->key_cur;
	r->key = k;
	r->key_size = bir->key_size;
	memset(r->key, 0x00, r->key_size);

	switch (r->from->tunnel_mode) {
	case GTP_INTERFACE_TUN_NONE:
		k->ifindex = ifindex;
		k->vlan_id = r->from->vlan_id;
		break;
	case GTP_INTERFACE_TUN_GRE:
	case GTP_INTERFACE_TUN_IPIP:
		k->tun_local = addr_toip4(&r->from->tunnel_local);
		k->tun_remote = addr_toip4(&r->from->tunnel_remote);
		k->flags = r->from->tunnel_mode == GTP_INTERFACE_TUN_GRE ?
			IF_RULE_FL_TUNNEL_GRE : IF_RULE_FL_TUNNEL_IPIP;
		break;
	default:
		return -1;
	}

	return 0;
}

static int
_rule_install(struct gtp_bpf_ifrules *bir, struct gtp_if_rule *r,
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
	ar->table_id = r->table_id ?: r->from ? r->from->table_id : 0;
	ar->force_ifindex = r->force_ifindex;
	ar->xsk_base_idx = ~0;

	/* printf("add input rule if:%d vlan:%d ip-table:%d tun:%d/%x/%x\n", */
	/*        k->ifindex, k->vlan_id, ar->table_id, */
	/*        k->flags, k->tun_local, k->tun_remote); */

	for (i = 1; i < nr_cpus; i++)
		aar[i] = aar[0];

	ret = bpf_map__update_elem(bir->if_rule, k, r->key_size,
				   ar, sizeof (aar),
				   overwrite ? 0 : BPF_NOEXIST);
	if (ret) {
		log_message(LOG_ERR, "cannot %s rule! (%d / %m)",
		       overwrite ? "update" : "add", ret);
		return -1;
	}

	return 0;
}

static void
_rule_uninstall(struct gtp_bpf_ifrules *bir, struct gtp_if_rule *r)
{
	int ret;

	ret = bpf_map__delete_elem(bir->if_rule, r->key, r->key_size, 0);
	if (ret)
		log_message(LOG_ERR, "cannot delete rule! (%d / %m)", ret);
}

static int
_if_rule_add(struct gtp_bpf_ifrules *bir, struct gtp_if_rule *r, int ifindex)
{
	struct stored_rule *sr;
	int ret = -1;
	uint32_t h;

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
	if (sr == NULL)
		return -1;
	sr->installed = ret == 0;

	return 0;
}


static void
_if_rule_del(struct gtp_bpf_ifrules *bir, struct gtp_if_rule *r, int ifindex)
{
	struct stored_rule *sr;

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
gtp_bpf_ifrules_set(struct gtp_if_rule *r, bool add)
{
	struct gtp_bpf_ifrules *bir = r->bir;
	int ifindex = 0;

	if (bir == NULL) {
		/* retrieve 'physical' interface. we will install rules on it */
		bir = _get_bir(r->from, &ifindex);
		if (bir == NULL)
			return -1;
	}

	if (add)
		return _if_rule_add(bir, r, ifindex);
	_if_rule_del(bir, r, ifindex);
	return 0;
}


static void
_rule_del_iface(struct gtp_interface *iface)
{
	struct gtp_bpf_ifrules *bir;
	struct stored_rule *sr, *sr_tmp;

	bir = _get_bir(iface, NULL);
	if (bir == NULL)
		return;

	list_for_each_entry_safe(sr, sr_tmp, &bir->rule_list, list) {
		if (sr->r.from != NULL && (sr->r.from == iface ||
					   sr->r.from->link_iface == iface)) {
			if (sr->installed)
				_rule_uninstall(bir, &sr->r);
			_rule_del(sr);
		}
	}
}


/*
 *	Output rules
 */

static int
_out_rule_sort_cb(struct list_head *al, struct list_head *bl)
{
	struct output_rule *a = container_of(al, struct output_rule, list);
	struct output_rule *b = container_of(bl, struct output_rule, list);

	if (a->iface->ifindex < b->iface->ifindex)
		return -1;
	if (a->iface->ifindex > b->iface->ifindex)
		return 1;
	return 0;
}

static void
_rule_set_attr(struct gtp_interface *iface, struct if_rule_attr *a)
{
	if (iface->tunnel_mode == GTP_INTERFACE_TUN_GRE) {
		a->tun_local = addr_toip4(&iface->tunnel_local);
		a->tun_remote = addr_toip4(&iface->tunnel_remote);
		a->flags = IF_RULE_FL_TUNNEL_GRE;
	} else if (iface->tunnel_mode == GTP_INTERFACE_TUN_IPIP) {
		a->tun_local = addr_toip4(&iface->tunnel_local);
		a->tun_remote = addr_toip4(&iface->tunnel_remote);
		a->flags = IF_RULE_FL_TUNNEL_IPIP;
	} else {
		a->tun_local = 0;
		a->tun_remote = 0;
		a->flags = 0;
	}

	a->vlan_id = iface->vlan_id;

	a->ifindex = iface->ifindex;
	if (iface->link_iface)
		a->ifindex = iface->link_iface->ifindex;
}

static void
_out_rule_attr_add(struct gtp_bpf_ifrules *bir, struct gtp_interface *iface)
{
	struct output_rule *or;
	struct if_rule_attr a;
	int ifindex, ret;

	list_for_each_entry(or, &bir->out_rule_list, list) {
		if (or->iface == iface) {
			or->refcnt++;
			if (!or->installed)
				goto install;
			return;
		}
	}
	or = malloc(sizeof (*or));
	if (or == NULL)
		return;
	or->iface = iface;
	or->refcnt = 1;
	or->installed = false;
	list_add(&or->list, &bir->out_rule_list);
	bir->out_rule_list_sorted = false;

 install:
	ifindex = iface->ifindex;
	_rule_set_attr(iface, &a);
	ret = bpf_map__update_elem(bir->if_rule_attr,
				   &ifindex, sizeof (ifindex),
				   &a, sizeof (a),
				   BPF_NOEXIST);
	if (ret) {
		log_message(LOG_ERR, "cannot insert rule_attr ifindex:%d (%d / %m)",
		       ifindex, ret);
	} else {
		or->installed = true;
	}
}

static void
_out_rule_attr_del(struct gtp_bpf_ifrules *bir, struct gtp_interface *iface)
{
	struct output_rule *or;
	int ifindex, ret;

	list_for_each_entry(or, &bir->out_rule_list, list) {
		if (or->iface == iface) {
			if (--or->refcnt == 0)
				goto uninstall;
			break;
		}
	}
	return;

 uninstall:
	if (or->installed) {
		ifindex = iface->ifindex;
		ret = bpf_map__delete_elem(bir->if_rule_attr,
					   &ifindex, sizeof (ifindex), 0);
		if (ret) {
			log_message(LOG_ERR, "cannot delete rule_attr "
				    "ifindex:%d (%d / %m)\n", ifindex, ret);
		}
	}
	list_del(&or->list);
	free(or);
}


static void
_out_rule_event_cb(struct gtp_interface *iface, enum gtp_interface_event type,
		      void *udata, void *arg)
{
	struct gtp_bpf_ifrules *bir = udata;
	struct gtp_interface *child = arg;
	bool def_route = !__test_bit(GTP_INTERFACE_FL_BPF_NO_DEFAULT_ROUTE_BIT,
				     &child->flags);

	struct gtp_if_rule ifr = {
		.from = child,
		.action = XDP_IFR_DEFAULT_ROUTE,
		.prio = 900,
	};

	if (type == GTP_INTERFACE_EV_PRG_START) {
		_out_rule_attr_add(bir, child);
		if (def_route)
			_if_rule_add(bir, &ifr, iface->ifindex);

	} else if (type == GTP_INTERFACE_EV_PRG_STOP) {
		if (def_route)
			_if_rule_del(bir, &ifr, iface->ifindex);
		_out_rule_attr_del(bir, child);
	}
}

void
gtp_bpf_ifrules_set_auto_input_rule(struct gtp_interface *iface, bool set)
{
	struct gtp_interface *master = iface->link_iface ?: iface;
	struct gtp_bpf_ifrules *bir = master->bpf_ifrules;

	if (bir == NULL)
		return;

	struct gtp_if_rule ifr = {
		.from = iface,
		.action = XDP_IFR_DEFAULT_ROUTE,
		.prio = 900,
	};

	if (set)
		_if_rule_add(bir, &ifr, master->ifindex);
	else
		_if_rule_del(bir, &ifr, master->ifindex);
}


/*
 *	vty dump
 */

static void
gtp_ifrule_vty_output(struct gtp_bpf_ifrules *bir, struct vty *vty)
{
	struct gtp_interface *to;
	struct if_rule_attr a;
	struct output_rule *or;
	char b1[60], b2[60];
	int ifindex = 0, err;
	struct table *tbl;

	tbl = table_init(3, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column_align(tbl, ALIGN_LEFT, ALIGN_LEFT, ALIGN_LEFT);
	table_set_column(tbl, "output iface", "encapsulate with", "to iface");

	if (!bir->out_rule_list_sorted) {
		list_sort(&bir->out_rule_list, _out_rule_sort_cb);
		bir->out_rule_list_sorted = true;
	}

	list_for_each_entry(or, &bir->out_rule_list, list) {
		ifindex = or->iface->ifindex;

		err = bpf_map__lookup_elem(bir->if_rule_attr, &ifindex, sizeof (ifindex),
					   &a, sizeof (a), 0);
		if (err && errno == EEXIST) {
			vty_out(vty, "%% !!! Missing ifindex:%d in bpf map "
				"'if_rule_attr'\n", ifindex);
			break;
		} else if (err) {
			vty_out(vty, "%% error fetching value from table (%m)\n");
			break;
		}

		if (!(a.flags & IF_RULE_FL_TUNNEL_MASK)) {
			to = gtp_interface_get_by_ifindex(a.ifindex, false);
			b1[0] = 0;
			if (a.vlan_id)
				snprintf(b1, sizeof (b1), "vlan:%d", a.vlan_id);
			table_add_row_fmt(tbl, "(if:%d) %s|%s|(if:%d) %s",
					  ifindex, or->iface->ifname, b1,
					  a.ifindex, to ? to->ifname : "<unset>");
			continue;
		}

		table_add_row_fmt(tbl, "(if:%d) %s|%s local:%s remote:%s|%s",
				  ifindex, or->iface->ifname,
				  a.flags & IF_RULE_FL_TUNNEL_GRE ? "gre" : "ipip",
				  inet_ntop(AF_INET, &a.tun_local, b1, sizeof (b1)),
				  inet_ntop(AF_INET, &a.tun_remote, b2, sizeof (b2)),
				  "fib_lookup");
	}

	/* check for consistency */
	ifindex = 0;
	while (!bpf_map__get_next_key(bir->if_rule_attr, &ifindex, &ifindex,
				      sizeof (ifindex))) {
		bool found = false;
		list_for_each_entry(or, &bir->out_rule_list, list) {
			if (or->iface->ifindex == ifindex) {
				found = true;
				break;
			}
		}
		if (!found) {
			vty_out(vty, "%% !!! Unexpected ifindex:%d in bpf map "
				"'if_rule_attr'\n", ifindex);
		}
	}

	table_vty_out(tbl, vty);
	table_destroy(tbl);
}

static void
gtp_ifrule_vty_all(struct gtp_bpf_ifrules *bir, struct vty *vty)
{
	struct gtp_interface *from = NULL;
	struct if_rule_key_base *k;
	struct stored_rule *sr;
	struct gtp_if_rule *r;
	char buf[200], b1[60], b2[60];

	if (list_empty(&bir->rule_list))
		return;

	if (!bir->rule_list_sorted) {
		list_sort(&bir->rule_list, _rule_sort_cb);
		bir->rule_list_sorted = true;
	}

	vty_out(vty, "=== from any interface ===\n");

	list_for_each_entry(sr, &bir->rule_list, list) {
		*buf = 0;
		r = &sr->r;
		k = r->key;
		if (r->key_stringify != NULL && sr->r.key_size > sizeof (*k))
			r->key_stringify(&sr->r, buf, sizeof (buf), false);

		if (sr->r.from != from) {
			vty_out(vty, "%s", VTY_NEWLINE);
			from = sr->r.from;
			vty_out(vty, "=== from %s (if:%d) ===\n",
				from->ifname, k->ifindex);
		}

		vty_out(vty, "%c match", sr->installed ? '*' : '-');
		if (k->vlan_id)
			vty_out(vty, " vlan:%d", k->vlan_id);
		if (k->flags)
			vty_out(vty, " %s local:%s remote:%s",
				k->flags & IF_RULE_FL_TUNNEL_GRE ? "gre" : "ipip",
				inet_ntop(AF_INET, &k->tun_local, b1, sizeof (b1)),
				inet_ntop(AF_INET, &k->tun_remote, b2, sizeof (b2)));
		if (*buf) {
			if (k->flags)
				vty_out(vty, "%s    and", VTY_NEWLINE);
			vty_out(vty, " %s", buf);
		}
		if (!k->vlan_id && !k->flags && !*buf)
			vty_out(vty, " all");
		vty_out(vty, ", prio %d%s", r->prio, VTY_NEWLINE);
		vty_out(vty, "  -> action %d", r->action);
		if (r->table_id)
			vty_out(vty, " table-id:%d", r->table_id);
		if (r->force_ifindex)
			vty_out(vty, " force ifindex:%d", r->force_ifindex);
		else
			vty_out(vty, " then fib_lookup");

		vty_out(vty, "%s", VTY_NEWLINE);
	}
}

static void
gtp_ifrule_vty_input(struct gtp_bpf_ifrules *bir, struct vty *vty)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct if_rule aar[nr_cpus];
	struct if_rule *ar = &aar[0];
	struct gtp_if_rule gr = {};
	struct gtp_if_rule *r;
	struct if_rule_key_base *k;
	struct stored_rule *sr;
	struct table *tbl;
	char match[50], iface_buf[50], buf[200], b2[60];
	void *key = NULL;
	int i, l, err;
	uint32_t h;

	tbl = table_init(5, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "iface", "match", "pkt in", "bytes in", "pkt fwd");

	/* Walk hashtab */
	uint8_t key_stor[bir->key_size];
	gr.key_size = bir->key_size;
	memset(aar, 0x00, sizeof (aar));
	while (!bpf_map__get_next_key(bir->if_rule, key, &key_stor, bir->key_size)) {
		key = key_stor;
		err = bpf_map__lookup_elem(bir->if_rule, key, bir->key_size,
					   ar, sizeof (aar), 0);
		if (err) {
			vty_out(vty, "%% error fetching value from table (%m)\n");
			break;
		}

		gr.key = key;
		h = _rule_hash(&gr);
		sr = _rule_find_first(bir, &gr, h);
		while (sr && !sr->installed)
			sr = _rule_find_next(bir, &gr, h, sr);
		if (sr == NULL) {
			vty_out(vty, "%% sync failure: bpf key not in userapp\n");
			continue;
		}
		r = &sr->r;
		k = r->key;

		/* build iface string */
		snprintf(iface_buf, sizeof (iface_buf), "%s",
			 r->from ? r->from->ifname : "<any>");

		/* build match string */
		l = 0;
		*buf = 0;
		if (r->key_stringify != NULL && r->key_size > sizeof (*k))
			r->key_stringify(r, buf, sizeof (buf), true);
		if (k->vlan_id)
			l += scnprintf(match + l, sizeof (match) - l, "vlan:%d ",
				       k->vlan_id);
		if (k->flags)
			l += scnprintf(match + l, sizeof (match) - l, "%s:%s ",
				k->flags & IF_RULE_FL_TUNNEL_GRE ? "gre" : "ipip",
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
}


/*
 *	eBPF template for interface
 */


static void
gtp_ifrule_vty(struct gtp_bpf_prog *p, void *ud, struct vty *vty,
	       int argc, const char **argv)
{
	struct gtp_bpf_ifrules *bir = ud;

	if (bir->if_rule == NULL)
		return;

	if (!strcmp(argv[0], "input"))
		gtp_ifrule_vty_input(bir, vty);
	else if (!strcmp(argv[0], "output"))
		gtp_ifrule_vty_output(bir, vty);
	else if (!strcmp(argv[0], "all"))
		gtp_ifrule_vty_all(bir, vty);
}


static int
gtp_ifrule_loaded(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct gtp_bpf_ifrules *bir = udata;

	bir->if_rule = gtp_bpf_prog_load_map(p->obj_load, "if_rule");
	bir->if_rule_attr = gtp_bpf_prog_load_map(p->obj_load, "if_rule_attr");
	if (bir->if_rule == NULL || bir->if_rule_attr == NULL)
		return -1;

	if (!reload) {
		bir->key_size = bpf_map__key_size(bir->if_rule);
		bir->key_cur = malloc(bir->key_size);
		if (bir->key_cur == NULL)
			return -1;
	}

	return 0;
}

static int
gtp_ifrule_bind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct gtp_bpf_ifrules *bir = udata;

	iface->bpf_ifrules = bir;

	gtp_interface_register_event(iface, _out_rule_event_cb, bir);

	return 0;
}

static void
gtp_ifrule_unbind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct gtp_bpf_ifrules *bir = udata;

	gtp_interface_unregister_event(iface, _out_rule_event_cb, bir);
	_rule_del_iface(iface);

	iface->bpf_ifrules = NULL;
}

static void *
gtp_ifrule_alloc(struct gtp_bpf_prog *p)
{
	struct gtp_bpf_ifrules *bir;

	bir = calloc(1, sizeof (struct gtp_bpf_ifrules));
	INIT_LIST_HEAD(&bir->rule_list);
	INIT_LIST_HEAD(&bir->out_rule_list);
	return bir;
}

static void
gtp_ifrule_release(struct gtp_bpf_prog *p, void *udata)
{
	struct gtp_bpf_ifrules *bir = udata;
	struct stored_rule *sr, *sr_tmp;
	struct output_rule *or, *or_tmp;

	list_for_each_entry_safe(sr, sr_tmp, &bir->rule_list, list)
		free(sr);
	list_for_each_entry_safe(or, or_tmp, &bir->out_rule_list, list)
		free(or);
	free(bir->key_cur);
	free(bir);
}


static struct gtp_bpf_prog_tpl gtp_bpf_ifrules_module = {
	.name = "if_rules",
	.description = "Interface rules dispatcher",
	.alloc = gtp_ifrule_alloc,
	.release = gtp_ifrule_release,
	.loaded = gtp_ifrule_loaded,
	.iface_bind = gtp_ifrule_bind_itf,
	.iface_unbind = gtp_ifrule_unbind_itf,
	.vty_out = gtp_ifrule_vty,
};

static void __attribute__((constructor))
gtp_bpf_ifrules_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_ifrules_module);
}
