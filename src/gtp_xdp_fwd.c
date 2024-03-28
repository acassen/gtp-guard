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
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
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


/*
 *	XDP FWD BPF related
 */
int
gtp_xdp_fwd_load(gtp_bpf_opts_t *opts)
{
	struct bpf_map *map;
	int err;

	err = gtp_xdp_load(opts);
	if (err < 0)
		return -1;

	/* MAP ref for faster access */
	opts->bpf_maps = MALLOC(sizeof(gtp_bpf_maps_t) * XDPFWD_MAP_CNT);
	map = gtp_bpf_load_map(opts->bpf_obj, "teid_xlat");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	opts->bpf_maps[XDPFWD_MAP_TEID].map = map;

	map = gtp_bpf_load_map(opts->bpf_obj, "iptnl_info");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	opts->bpf_maps[XDPFWD_MAP_IPTNL].map = map;

	return 0;
}

void
gtp_xdp_fwd_unload(gtp_bpf_opts_t *opts)
{
	gtp_xdp_unload(opts);
}


/*
 *	TEID Switching handling
 */
static struct gtp_teid_rule *
gtp_xdp_teid_rule_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct gtp_teid_rule);
	return new;
}

static void
gtp_xdp_teid_rule_set(struct gtp_teid_rule *r, gtp_teid_t *t, int direction)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int i;

	for (i = 0; i < nr_cpus; i++) {
		r[i].vteid = t->vid;
		r[i].teid = t->id;
		r[i].dst_addr = t->ipv4;
		r[i].direction = direction;
		r[i].packets = 0;
		r[i].bytes = 0;
	}
}

static int
gtp_xdp_teid_action(struct bpf_map *map, int action, gtp_teid_t *t)
{
	struct gtp_teid_rule *new = NULL;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err = 0, direction;
	uint32_t key;
	size_t sz;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	if (!t)
		return -1;

	key = htonl(t->vid);
	direction = __test_bit(GTP_TEID_FL_EGRESS, &t->flags);

	/* Set rule */
	if (action == RULE_ADD) {
		/* fill per cpu rule */
		new = gtp_xdp_teid_rule_alloc(&sz);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate teid_rule !!!"
					    , __FUNCTION__);
			err = -1;
			goto end;
		}
		gtp_xdp_teid_rule_set(new, t, direction);
		err = bpf_map__update_elem(map, &key, sizeof(uint32_t), new, sz, BPF_NOEXIST);
	} else if (action == RULE_DEL)
		err = bpf_map__delete_elem(map, &key, sizeof(uint32_t), 0);
	else
		return -1;
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s rule for VTEID:0x%.8x (%s)"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , t->vid
				    , errmsg);
		err = -1;
		goto end;
	}

	log_message(LOG_INFO, "%s(): %s XDP forwarding rule "
			      "{vteid:0x%.8x, teid:0x%.8x, dst_addr:%u.%u.%u.%u}"
			    , __FUNCTION__
			    , (action) ? "deleting" : "adding"
			    , t->vid, ntohl(t->id), NIPQUAD(t->ipv4));
  end:
	if (new)
		free(new);
	return err;
}

static int
gtp_xdp_teid_vty(struct bpf_map *map, vty_t *vty, __be32 id)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__be32 key = 0, next_key = 0;
	struct gtp_teid_rule *r;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char addr_ip[16];
	int err = 0, i;
	uint64_t packets, bytes;
	size_t sz;

	/* Allocate temp rule */
	r = gtp_xdp_teid_rule_alloc(&sz);
	if (!r) {
		vty_out(vty, "%% Cant allocate temp teid_rule%s", VTY_NEWLINE);
		return -1;
	}

	/* Specific VTEID lookup */
	if (id) {
		err = bpf_map__lookup_elem(map, &id, sizeof(uint32_t), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "       %% No data-plane ?! (%s)%s", errmsg, VTY_NEWLINE);
			goto end;
		}

		packets = bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			packets += r[i].packets;
			bytes += r[i].bytes;
		}

		vty_out(vty, "       %.7s pkts:%ld bytes:%ld%s"
			   , r[0].direction ? "egress" : "ingress"
			   , packets, bytes, VTY_NEWLINE);
		goto end;
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
			   , r[0].direction ? "egress" : "ingress"
			   , packets, bytes, VTY_NEWLINE);
	}

  end:
	free(r);
	return 0;
}

int
gtp_xdp_fwd_teid_action(int action, gtp_teid_t *t)
{
	gtp_bpf_opts_t *bpf_opts = &daemon_data->xdp_gtpu;

	if (!__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags))
		return -1;

	return gtp_xdp_teid_action(bpf_opts->bpf_maps[XDPFWD_MAP_TEID].map, action, t);
}

int
gtp_xdp_fwd_teid_vty(vty_t *vty, __be32 id)
{
	gtp_bpf_opts_t *bpf_opts = &daemon_data->xdp_gtpu;

	if (!__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags))
		return -1;

	return gtp_xdp_teid_vty(bpf_opts->bpf_maps[XDPFWD_MAP_TEID].map, vty, id);
}

int
gtp_xdp_fwd_vty(vty_t *vty)
{
	gtp_bpf_opts_t *bpf_opts = &daemon_data->xdp_gtpu;

	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		     "|    VTEID   |    TEID    | Endpoint Address | Direction |   Packets    |        Bytes        |%s"
		     "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	gtp_xdp_teid_vty(bpf_opts->bpf_maps[XDPFWD_MAP_TEID].map, vty, 0);
	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE);
	return 0;
}

/*
 *	IP Tunneling related
 */
int
gtp_xdp_fwd_iptnl_action(int action, gtp_iptnl_t *t)
{
	gtp_bpf_opts_t *bpf_opts = &daemon_data->xdp_gtpu;

	if (!__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags))
		return -1;

	return gtp_xdp_iptnl_action(action, t, bpf_opts->bpf_maps[XDPFWD_MAP_IPTNL].map);
}

int
gtp_xdp_fwd_iptnl_vty(vty_t *vty)
{
	gtp_bpf_opts_t *bpf_opts = &daemon_data->xdp_gtpu;

	if (!__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags))
		return -1;

	return gtp_xdp_iptnl_vty(vty, bpf_opts->bpf_maps[XDPFWD_MAP_IPTNL].map);
}