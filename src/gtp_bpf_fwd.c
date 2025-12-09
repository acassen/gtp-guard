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

#include "inet_utils.h"
#include "gtp_data.h"
#include "gtp_bpf_fwd.h"
#include "gtp_bpf_utils.h"
#include "gtp_session.h"
#include "gtp_proxy.h"
#include "bitops.h"
#include "table.h"
#include "logger.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	TEID rules handling
 */

static void
gtp_bpf_teid_rule_set(struct gtp_proxy *p, struct gtp_teid_rule *r, struct gtp_teid *t)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	uint32_t local = ~0;
	int i;

	if (__test_bit(GTP_TEID_FL_INGRESS, &t->flags))
		local = inet_sockaddrip4(&p->gtpu_egress.s.addr);
	if (local == ~0)
		local = inet_sockaddrip4(&p->gtpu.s.addr);

	for (i = 0; i < nr_cpus; i++) {
		r[i].vteid = t->vid;
		r[i].teid = t->id;
		r[i].dst_addr = t->ipv4;
		r[i].src_addr = local;
		r[i].packets = 0;
		r[i].bytes = 0;
	}
}

int
gtp_bpf_teid_action(struct gtp_proxy *p, int action, struct gtp_teid *t)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule rules[nr_cpus];
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	struct bpf_map *map;
	uint32_t key;
	int err;

	if (!p || !p->bpf_data || !(map = p->bpf_data->teid_xlat))
		return -1;

	memset(rules, 0x00, sizeof(rules));
	key = htonl(t->vid);

	if (action == RULE_ADD) {
		gtp_bpf_teid_rule_set(p, rules, t);
		err = bpf_map__update_elem(map,
					   &key, sizeof(uint32_t),
					   rules, nr_cpus * sizeof(struct gtp_teid_rule),
					   BPF_NOEXIST);
	} else if (action == RULE_DEL)
		err = bpf_map__delete_elem(map, &key, sizeof(uint32_t), 0);
	else
		return -1;

	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s rule for VTEID:0x%.8x (%s)"
				    , __FUNCTION__
				    , action ? "del" : "add"
				    , t->vid
				    , errmsg);
		return -1;
	}

	gtp_proxy_rules_remote_set(p, t->ipv4, action,
				   __test_bit(GTP_TEID_FL_INGRESS, &t->flags));

	log_message(LOG_INFO, "%s(): %s XDP forwarding rule "
			      "{vteid:0x%.8x, teid:0x%.8x, dst_addr:%u.%u.%u.%u}"
			    , __FUNCTION__
			    , (action) ? "deleting" : "adding"
			    , t->vid, ntohl(t->id), NIPQUAD(t->ipv4));
	return 0;
}

int
gtp_bpf_fwd_teid_action(int action, struct gtp_teid *t)
{
	struct gtp_proxy *proxy = t->session->srv->ctx;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	return gtp_bpf_teid_action(proxy, action, t);
}

int
gtp_bpf_fwd_teid_vty(struct vty *vty, struct gtp_teid *t)
{
	struct gtp_proxy *proxy = t->session->srv->ctx;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule r[nr_cpus];
	size_t sz = nr_cpus * sizeof(struct gtp_teid_rule);
	struct bpf_map *map;
	const char *dir_str;
	bool egress;
	uint32_t id;
	int i, err;

	if (!proxy || !proxy->bpf_data || !(map = proxy->bpf_data->teid_xlat))
		return -1;

	/* Specific VTEID lookup */
	id = ntohl(t->vid);
	memset(r, 0x00, sizeof(r));
	err = bpf_map__lookup_elem(map, &id, sizeof(uint32_t), r, sz, 0);
	if (err) {
		vty_out(vty, "%%      teid=0x%08x not in data-plane ?! (%m)\n", id);
		return 0;
	}

	for (i = 1; i < nr_cpus; i++) {
		r[0].packets += r[i].packets;
		r[0].bytes += r[i].bytes;
	}

	dir_str = "Unknown";
	if (!gtp_proxy_rules_remote_exists(proxy, r[0].dst_addr, &egress))
		dir_str = egress ? "Egress" : "Ingress";

	vty_out(vty, "       %.7s pkts:%lld bytes:%lld\n", dir_str,
		r[0].packets, r[0].bytes);

	return 0;
}

int
gtp_bpf_fwd_teid_bytes(struct gtp_teid *t, uint64_t *bytes)
{
	struct gtp_proxy *proxy = t->session->srv->ctx;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule r[nr_cpus];
	struct bpf_map *map;
	uint32_t id;
	int err = 0, i;
	size_t sz = sizeof(r);

	if (!proxy || !proxy->bpf_data || !(map = proxy->bpf_data->teid_xlat))
		return -1;

	/* Specific VTEID lookup */
	id = ntohl(t->vid);
	err = bpf_map__lookup_elem(map, &id, sizeof(uint32_t), r, sz, 0);
	if (err)
		return 0;

	for (i = 0; i < nr_cpus; i++)
		*bytes += r[i].bytes;

	return 0;
}


static void
gtp_bpf_fwd_vty(struct gtp_bpf_prog *p, void *ud, struct vty *vty,
		int argc, const char **argv)
{
	struct gtp_bpf_fwd_data *pf = ud;
	struct table *tbl;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule r[nr_cpus];
	struct gtp_proxy *proxy;
	const char *dir_str;
	char addr_ip[16];
	uint32_t key = 0;
	bool egress;
	int err = 0, i;

	if (!pf->teid_xlat)
		return;

	tbl = table_init(6, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "VTEID", "TEID", "Endpoint Address",
			 "Direction", "Packets", "Bytes");
	table_set_header_align(tbl, ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
			       ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER);

	vty_out(vty, "bpf-program '%s'\n", p->name);

	/* Walk hashtab */
	memset(r, 0x00, sizeof(r));
	while (!bpf_map__get_next_key(pf->teid_xlat, &key, &key, sizeof(uint32_t))) {
		err = bpf_map__lookup_elem(pf->teid_xlat, &key, sizeof(uint32_t),
					   r, sizeof (r), 0);
		if (err) {
			vty_out(vty, "%% error fetching value for "
				"teid_key:0x%.8x (%m)\n", key);
			break;
		}

		dir_str = "Unknown";
		list_for_each_entry(proxy, &pf->gtp_proxy_list, bpf_list) {
			if (!gtp_proxy_rules_remote_exists(proxy, r[0].dst_addr,
							   &egress)) {
				dir_str = egress ? "Egress" : "Ingress";
				break;
			}
		}

		for (i = 1; i < nr_cpus; i++) {
			r[0].packets += r[i].packets;
			r[0].bytes += r[i].bytes;
		}

		table_add_row_fmt(tbl, "0x%.8x|0x%.8x|%s|%s|%lld|%lld",
				  r[0].vteid, ntohl(r[0].teid),
				  inet_ntoa2(r[0].dst_addr, addr_ip),
				  dir_str, r[0].packets, r[0].bytes);
	}

	table_vty_out(tbl, vty);
	table_destroy(tbl);
}

static void *
gtp_bpf_fwd_alloc(struct gtp_bpf_prog *p)
{
	struct gtp_bpf_fwd_data *pf;

	pf = calloc(1, sizeof (*pf));
	if (pf == NULL)
		return NULL;

	INIT_LIST_HEAD(&pf->gtp_proxy_list);
	return pf;
}

static void
gtp_bpf_fwd_release(struct gtp_bpf_prog *p, void *udata)
{
	struct gtp_bpf_fwd_data *pf = udata;
	struct gtp_proxy *proxy, *tmp;

	list_for_each_entry_safe(proxy, tmp, &pf->gtp_proxy_list, bpf_list) {
		proxy->bpf_prog = NULL;
		proxy->bpf_data = NULL;
		proxy->bpf_ifrules = NULL;
		list_del_init(&proxy->bpf_list);
	}
	free(pf);
}

static int
gtp_bpf_fwd_load_maps(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct gtp_bpf_fwd_data *pf = udata;

	/* MAP ref for faster access */
	pf->teid_xlat = gtp_bpf_prog_load_map(p->obj_load, "teid_xlat");
	if (!pf->teid_xlat)
		return -1;

	return 0;
}

static struct gtp_bpf_prog_tpl gtp_bpf_tpl_fwd = {
	.name = "gtp_fwd",
	.description = "gtp-forward for gtp-proxy",
	.alloc = gtp_bpf_fwd_alloc,
	.release = gtp_bpf_fwd_release,
	.loaded = gtp_bpf_fwd_load_maps,
	.vty_out = gtp_bpf_fwd_vty,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_fwd);
}
