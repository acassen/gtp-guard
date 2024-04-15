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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libbpf.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;

/* Local data */
static struct bpf_map *xdp_mirror_map;


/*
 *	Mirroring handling
 */
static int
gtp_xdp_mirror_rule_set(struct gtp_mirror_rule *r,  gtp_mirror_rule_t *m)
{
	r->addr = ((struct sockaddr_in *) &m->addr)->sin_addr.s_addr;
	r->port = ((struct sockaddr_in *) &m->addr)->sin_port;
	r->protocol = m->protocol;
	r->ifindex = m->ifindex;
	return 0;
}

int
gtp_xdp_mirror_action(int action, gtp_mirror_rule_t *m)
{
	struct bpf_map *map = xdp_mirror_map;
	struct gtp_mirror_rule r;
	const char *action_str = "adding";
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	memset(&r, 0, sizeof(struct gtp_mirror_rule));
	gtp_xdp_mirror_rule_set(&r, m);

	if (action == RULE_ADD) {
		err = bpf_map__update_elem(map, &r.addr, sizeof(uint32_t)
					      , &r, sizeof(struct gtp_mirror_rule), BPF_NOEXIST);
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

int
gtp_xdp_mirror_vty(vty_t *vty)
{
	struct bpf_map *map = xdp_mirror_map;
	__be32 key, next_key;
	struct gtp_mirror_rule r;
	size_t sz = sizeof(struct gtp_mirror_rule);
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char ipaddr[16], ifname[IF_NAMESIZE];
	int err = 0;

	vty_out(vty, "+------------------+--------+----------+-------------+%s"
		     "|      Address     |  Port  | Protocol |  Interface  |%s"
		     "+------------------+--------+----------+-------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(uint32_t)) == 0) {
		key = next_key;
		memset(&r, 0, sizeof(struct gtp_mirror_rule));
		err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), &r, sz, 0);
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
	return 0;
}

static int
gtp_xdp_qdisc_clsact_add(struct bpf_tc_hook *q_hook)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	bpf_tc_hook_destroy(q_hook);	/* Release previously stalled entry */
	err = bpf_tc_hook_create(q_hook);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant create TC_HOOK to ifindex:%d (%s)"
				    , __FUNCTION__
				    , q_hook->ifindex
				    , errmsg);
		return 1;
	}

	return 0;
}

static int
gtp_xdp_tc_filter_add(struct bpf_tc_hook *q_hook, enum bpf_tc_attach_point direction,
		      const struct bpf_program *bpf_prog)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 0,
			    .flags = BPF_TC_F_REPLACE);
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	q_hook->attach_point = direction;
	tc_opts.prog_fd = bpf_program__fd(bpf_prog);
	err = bpf_tc_attach(q_hook, &tc_opts);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant attach eBPF prog_fd:%d to ifindex:%d %s (%s)"
				    , __FUNCTION__
				    , tc_opts.prog_fd
				    , q_hook->ifindex
				    , (direction == BPF_TC_INGRESS) ? "ingress" : "egress"
				    , errmsg);
		return 1;
	}

	return 0;
}

void
gtp_xdp_mirror_unload(gtp_bpf_opts_t *opts)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, q_hook, .ifindex = opts->ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	bpf_tc_hook_destroy(&q_hook);
	bpf_object__close(opts->bpf_obj);
	xdp_mirror_map = NULL;
}

int
gtp_xdp_mirror_load(gtp_bpf_opts_t *opts)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, q_hook, .ifindex = opts->ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	struct bpf_program *bpf_prog = NULL;
	struct bpf_map *map;
	int err = 0;

	/* Load eBPF prog */
	bpf_prog = gtp_xdp_load_prog(opts);
	if (!bpf_prog)
		return -1;

	/* Create Qdisc Clsact & attach {in,e}gress filters */
	err = err ? : gtp_xdp_qdisc_clsact_add(&q_hook);
	err = err ? : gtp_xdp_tc_filter_add(&q_hook, BPF_TC_INGRESS, bpf_prog);
	err = err ? : gtp_xdp_tc_filter_add(&q_hook, BPF_TC_EGRESS, bpf_prog);
	if (err) {
		bpf_object__close(opts->bpf_obj);
		return -1;
	}

	map = gtp_bpf_load_map(opts->bpf_obj, "mirror_rules");
	if (!map) {
		gtp_xdp_mirror_unload(opts);
		return -1;
	}
	xdp_mirror_map = map;

	return 0;
}
