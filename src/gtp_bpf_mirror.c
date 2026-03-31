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

#include <net/if.h>

#include "gtp_data.h"
#include "gtp_bpf_utils.h"
#include "gtp_bpf_mirror.h"
#include "gtp_mirror.h"
#include "bitops.h"
#include "logger.h"
#include "inet_utils.h"

/* Extern data */
extern struct data *daemon_data;


struct gtp_bpf_mirror
{
	struct bpf_map *mrules;
};

/*
 *	MAP related
 */
static int
gtp_bpf_mirror_load_maps(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct gtp_bpf_mirror *pm = udata;

	/* MAP ref for faster access */
	pm->mrules = gtp_bpf_prog_load_map(p->obj_load, "mirror_rules");
	if (!pm->mrules)
		return -1;

	return 0;
}


/*
 *	Mirroring handling
 */
static int
gtp_bpf_mirror_rule_set(struct gtp_bpf_mirror_rule *r,  struct gtp_mirror_rule *m)
{
	r->addr = ((struct sockaddr_in *) &m->addr)->sin_addr.s_addr;
	r->port = ((struct sockaddr_in *) &m->addr)->sin_port;
	r->protocol = m->protocol;
	r->ifindex = m->ifindex;
	return 0;
}

int
gtp_bpf_mirror_action(int action, void *arg, struct gtp_bpf_prog *p)
{
	struct gtp_bpf_mirror *pm = gtp_bpf_prog_tpl_data_get(p, "gtp_mirror");
	struct gtp_mirror_rule *m = arg;
	struct bpf_map *map;
	struct gtp_bpf_mirror_rule r;
	const char *action_str = "adding";
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	if (!p || !pm)
		return -1;
	map = pm->mrules;

	/* skip inconsistent call */
	if ((action == RULE_ADD && m->active) ||
	    (action == RULE_DEL && !m->active))
		return -1;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	memset(&r, 0, sizeof(struct gtp_bpf_mirror_rule));
	gtp_bpf_mirror_rule_set(&r, m);

	if (action == RULE_ADD) {
		err = bpf_map__update_elem(map, &r.addr, sizeof(uint32_t)
					      , &r, sizeof(struct gtp_bpf_mirror_rule), BPF_NOEXIST);
	} else if (action == RULE_DEL) {
		action_str = "deleting";
		err = bpf_map__delete_elem(map, &r.addr, sizeof(uint32_t), 0);
	} else
		return -1;

	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s mirror_rule for [%s]:%d (%s)"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , inet_sockaddrtos(&m->addr)
				    , ntohs(inet_sockaddrport(&m->addr))
				    , errmsg);
		return -1;
	}

	m->active = (action == RULE_ADD);

	log_message(LOG_INFO, "%s(): %s XDP Mirroring rule "
			      "{addr:%s port:%u, protocol:%s, ifindex:%d}"
			    , __FUNCTION__
			    , action_str
			    , inet_sockaddrtos(&m->addr)
			    , ntohs(inet_sockaddrport(&m->addr))
			    , (m->protocol == IPPROTO_UDP) ? "UDP" : "TCP"
			    , m->ifindex);
	return 0;
}

static void
gtp_bpf_mirror_vty(struct gtp_bpf_prog *p, void *ud, struct vty *vty,
		   int argc, const char **argv)
{
	struct gtp_bpf_mirror *pm = ud;
	__be32 key, next_key;
	struct gtp_bpf_mirror_rule r;
	size_t sz = sizeof(struct gtp_bpf_mirror_rule);
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char ipaddr[16], ifname[IF_NAMESIZE];
	int err = 0;

	if (!pm->mrules)
		return;

	vty_out(vty, "+------------------+--------+----------+-------------+%s"
		     "|      Address     |  Port  | Protocol |  Interface  |%s"
		     "+------------------+--------+----------+-------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	/* Walk hashtab */
	while (bpf_map__get_next_key(pm->mrules, &key, &next_key, sizeof(uint32_t)) == 0) {
		key = next_key;
		memset(&r, 0, sizeof(struct gtp_bpf_mirror_rule));
		err = bpf_map__lookup_elem(pm->mrules, &key, sizeof(uint32_t), &r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:0x%.4x (%s)%s"
				   , key, errmsg, VTY_NEWLINE);
			continue;
		}

		vty_out(vty, "| %16s | %6d | %8s | %11s |%s"
			   , inet_ntoa2(r.addr, ipaddr)
			   , ntohs(r.port)
			   , (r.protocol == IPPROTO_UDP) ? "UDP" : "TCP"
			   , if_indextoname(r.ifindex, ifname)
			   , VTY_NEWLINE);
	}

	vty_out(vty, "+------------------+--------+----------+-------------+%s"
		   , VTY_NEWLINE);
}

static struct gtp_bpf_prog_tpl gtp_bpf_tpl_mirror = {
	.name = "gtp_mirror",
	.description = "gtp-mirror",
	.udata_alloc_size = sizeof (struct gtp_bpf_mirror),
	.loaded = gtp_bpf_mirror_load_maps,
	.vty_out = gtp_bpf_mirror_vty,
};

static void __attribute__((constructor))
gtp_bpf_mirror_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_mirror);
}
