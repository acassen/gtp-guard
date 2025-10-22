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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include "inet_utils.h"
#include "gtp_interface.h"
#include "gtp_data.h"
#include "gtp_bpf.h"
#include "gtp_bpf_fwd.h"
#include "gtp_bpf_utils.h"
#include "gtp_session.h"
#include "gtp_proxy.h"
#include "bitops.h"
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
	__u8 flags = __test_bit(GTP_TEID_FL_INGRESS, &t->flags) ?
		GTP_FWD_FL_INGRESS : GTP_FWD_FL_EGRESS;
	int i;

	if (__test_bit(GTP_TEID_FL_INGRESS, &t->flags))
		local = inet_sockaddrip4(&p->gtpu_egress.s.addr);
	if (local == ~0)
		local = inet_sockaddrip4(&p->gtpu.s.addr);

	if (__test_bit(GTP_FL_DIRECT_TX_BIT, &p->flags))
		flags |= GTP_FWD_FL_DIRECT_TX;

	for (i = 0; i < nr_cpus; i++) {
		r[i].vteid = t->vid;
		r[i].teid = t->id;
		r[i].dst_addr = t->ipv4;
		r[i].src_addr = local;
		r[i].flags = flags;
		r[i].packets = 0;
		r[i].bytes = 0;
	}
}

int
gtp_bpf_teid_action(struct gtp_proxy *p, int action, struct gtp_teid *t)
{
	struct bpf_map *map = p->bpf_data->teid_xlat;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule rules[nr_cpus];
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	uint32_t key;
	int err;

	if (!t)
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

static void
gtp_bpf_teid_vty(struct bpf_map *map, struct vty *vty, __be32 id)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule r[nr_cpus];
	size_t sz = nr_cpus * sizeof(struct gtp_teid_rule);
	__be32 key = 0, next_key = 0;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char addr_ip[16];
	int err = 0, i;
	uint64_t packets, bytes;

	memset(r, 0x00, sizeof(r));

	/* Specific VTEID lookup */
	if (id) {
		err = bpf_map__lookup_elem(map, &id, sizeof(uint32_t), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "       %% No data-plane ?! (%s)\n", errmsg);
			return;
		}

		packets = bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			packets += r[i].packets;
			bytes += r[i].bytes;
		}

		vty_out(vty, "       %.7s pkts:%ld bytes:%ld%s"
			   , (r[0].flags & GTP_FWD_FL_EGRESS) ? "egress" : "ingress"
			   , packets, bytes, VTY_NEWLINE);
		return;
	}

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(uint32_t)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:0x%.8x (%s)%s"
				   , key, errmsg, VTY_NEWLINE);
			continue;
		}

		packets = bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			packets += r[i].packets;
			bytes += r[i].bytes;
		}

		vty_out(vty, "| 0x%.8x | 0x%.8x | %16s | %9s | %12ld | %19ld |%s"
			   , r[0].vteid, ntohl(r[0].teid)
			   , inet_ntoa2(r[0].dst_addr, addr_ip)
			   , (r[0].flags & GTP_FWD_FL_EGRESS) ? "egress" : "ingress"
			   , packets, bytes, VTY_NEWLINE);
	}
}

static int
gtp_bpf_teid_bytes(struct bpf_map *map, __be32 id, uint64_t *bytes)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule r[nr_cpus];
	int err = 0, i;
	size_t sz;

	/* Specific VTEID lookup */
	err = bpf_map__lookup_elem(map, &id, sizeof(uint32_t), r, sz, 0);
	if (err)
		return 0;

	for (i = 0; i < nr_cpus; i++)
		*bytes += r[i].bytes;

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

	gtp_bpf_teid_vty(proxy->bpf_data->teid_xlat, vty, ntohl(t->vid));
	return 0;
}

int
gtp_bpf_fwd_vty(struct gtp_bpf_prog *p, void *arg)
{
	struct gtp_bpf_fwd_data *pf = gtp_bpf_prog_tpl_data_get(p, "gtp_fwd");
	struct vty *vty = arg;

	if (!pf)
		return -1;

	vty_out(vty, "bpf-program '%s'%s", p->name, VTY_NEWLINE);

	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		     "|    VTEID   |    TEID    | Endpoint Address | Direction |   Packets    |        Bytes        |%s"
		     "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	gtp_bpf_teid_vty(pf->teid_xlat, vty, 0);
	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE);
	return 0;
}

int
gtp_bpf_fwd_teid_bytes(struct gtp_teid *t, uint64_t *bytes)
{
	struct gtp_proxy *proxy = t->session->srv->ctx;

	return gtp_bpf_teid_bytes(proxy->bpf_data->teid_xlat, ntohl(t->vid), bytes);
}




static int
gtp_bpf_fwd_load_maps(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct gtp_bpf_fwd_data *pf = udata;

	/* MAP ref for faster access */
	pf->teid_xlat = gtp_bpf_load_map(p->load.obj, "teid_xlat");
	if (!pf->teid_xlat)
		return -1;

	return 0;
}

static struct gtp_bpf_prog_tpl gtp_bpf_tpl_fwd = {
	.name = "gtp_fwd",
	.description = "gtp-forward for gtp-proxy",
	.udata_alloc_size = sizeof (struct gtp_bpf_fwd_data),
	.loaded = gtp_bpf_fwd_load_maps,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_fwd);
}
