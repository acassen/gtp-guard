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

/* Local data */
static xdp_exported_maps_t xdp_ppp_maps[XDP_RT_MAP_CNT];


/*
 *	XDP PPP BPF related
 */
int
gtp_xdp_ppp_load(gtp_bpf_opts_t *opts)
{
	struct bpf_map *map;
	int err;

	err = gtp_xdp_load(opts);
	if (err < 0)
		return -1;

	map = gtp_bpf_load_map(opts->bpf_obj, "ppp_ingress");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_ppp_maps[XDP_RT_MAP_PPP_INGRESS].map = map;
	return 0;
}

void
gtp_xdp_ppp_unload(gtp_bpf_opts_t *opts)
{
	gtp_xdp_unload(opts);
}


/*
 *	PPP Handling
 */
static struct gtp_rt_rule *
gtp_xdp_ppp_rule_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_rt_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct gtp_rt_rule);
	return new;
}

static void
gtp_xdp_ppp_rule_set(struct gtp_rt_rule *r, gtp_teid_t *t, spppoe_t *spppoe)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	gtp_session_t *s = t->session;
	gtp_conn_t *c = s->conn;
	gtp_router_t *rtr = c->ctx;
	gtp_server_t *srv = &rtr->gtpu;
	int i;

	for (i = 0; i < nr_cpus; i++) {
		/* PPP related */
		memcpy(r[i].h_src, &spppoe->hw_src, ETH_ALEN);
		memcpy(r[i].h_dst, &spppoe->hw_dst, ETH_ALEN);
		r[i].session_id = spppoe->session_id;

		/* TEID related */
		r[i].teid = t->id;
		r[i].saddr = inet_sockaddrip4(&srv->addr);
		r[i].daddr = t->ipv4;
		r[i].dst_key = 0;
		r[i].packets = 0;
		r[i].bytes = 0;
		r[i].flags = 0;
	}
}

static int
gtp_xdp_ppp_key_set(gtp_teid_t *t, struct ppp_key *ppp_k, spppoe_t *spppoe)
{
	/* Set PPP routing key */
	memcpy(ppp_k->hw, &spppoe->hw_src, ETH_ALEN);
	ppp_k->session_id = spppoe->session_id;
	return 0;
}

static int
gtp_xdp_ppp_map_action(int action, gtp_teid_t *t, struct bpf_map *map)
{
	gtp_session_t *s = t->session;
	spppoe_t *spppoe = s->s_pppoe;
	struct gtp_rt_rule *new = NULL;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err = 0;
	struct ip_rt_key rt_k;
	struct ppp_key ppp_k;
	size_t sz;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
		gtp_xdp_rt_key_set(t, &rt_k);
	else
		gtp_xdp_ppp_key_set(t, &ppp_k, spppoe);

	/* Set rule */
	if (action == RULE_ADD) {
		/* fill per cpu rule */
		new = gtp_xdp_ppp_rule_alloc(&sz);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate teid_rule !!!"
					    , __FUNCTION__);
			err = -1;
			goto end;
		}
		gtp_xdp_ppp_rule_set(new, t, spppoe);
		if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
			err = bpf_map__update_elem(map, &rt_k, sizeof(struct ip_rt_key),
						   new, sz, BPF_NOEXIST);
		else
			err = bpf_map__update_elem(map, &ppp_k, sizeof(struct ppp_key),
						   new, sz, BPF_NOEXIST);
	} else if (action == RULE_DEL)
		if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
			err = bpf_map__delete_elem(map, &rt_k, sizeof(struct ip_rt_key), 0);
		else
			err = bpf_map__delete_elem(map, &ppp_k, sizeof(struct ppp_key), 0);
	else
		return -1;
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s XDP PPP rule for TEID:0x%.8x (%s)"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , ntohl(t->id)
				    , errmsg);
		err = -1;
		goto end;
	}

	log_message(LOG_INFO, "%s(): %s %s XDP PPP rule "
			      "{teid:0x%.8x, dst_addr:%u.%u.%u.%u}"
			    , __FUNCTION__
			    , (action) ? "deleting" : "adding"
			    , (__test_bit(GTP_TEID_FL_EGRESS, &t->flags)) ? "egress" : "ingress"
			    , ntohl(t->id), NIPQUAD(t->ipv4));
  end:
	if (new)
		free(new);
	return err;
}

int
gtp_xdp_ppp_action(int action, gtp_teid_t *t,
		   struct bpf_map *map_ingress, struct bpf_map *map_egress)
{
	struct bpf_map *map_ppp_ingress = xdp_ppp_maps[XDP_RT_MAP_PPP_INGRESS].map;

	if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
		return gtp_xdp_ppp_map_action(action, t, map_egress);

	if (__test_bit(GTP_FL_PPP_INGRESS_LOADED_BIT, &daemon_data->flags))
		return gtp_xdp_ppp_map_action(action, t, map_ppp_ingress);

	return gtp_xdp_ppp_map_action(action, t, map_ingress);
}