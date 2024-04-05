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
	gtp_server_t *w_srv = s->w->srv;
	gtp_router_t *rtr = w_srv->ctx;
	gtp_server_t *srv = &rtr->gtpu;
	ip_vrf_t *vrf = s->apn->vrf;
	__u16 vlan_id = 0;
	__u8 flags = 0;
	int i;

	if (__test_bit(IP_VRF_FL_IPIP_BIT, &vrf->flags))
		flags |= GTP_RT_FL_IPIP;
	if (__test_bit(IP_VRF_FL_GTP_UDP_PORT_LEARNING_BIT, &vrf->flags))
		flags |= GTP_RT_FL_UDP_LEARNING;
	if (__test_bit(IP_VRF_FL_DIRECT_TX_BIT, &vrf->flags))
		flags |= GTP_RT_FL_DIRECT_TX;

	vlan_id = (vrf) ? vrf->encap_vlan_id : 0;
	if (__test_bit(GTP_TEID_FL_INGRESS, &t->flags))
		vlan_id = (vrf) ? vrf->decap_vlan_id : 0;

	for (i = 0; i < nr_cpus; i++) {
		/* PPP related */
		memcpy(r[i].h_src, &spppoe->hw_src, ETH_ALEN);
		memcpy(r[i].h_dst, &spppoe->hw_dst, ETH_ALEN);
		r[i].session_id = spppoe->session_id;

		/* TEID related */
		r[i].teid = t->id;
		r[i].saddr = inet_sockaddrip4(&srv->addr);
		r[i].daddr = t->ipv4;
		r[i].vlan_id = vlan_id;
		r[i].ifindex = spppoe->pppoe->ifindex;
		r[i].dst_key = 0;
		r[i].gtp_udp_port = 0;
		r[i].packets = 0;
		r[i].bytes = 0;
		r[i].flags = flags | GTP_RT_FL_PPPOE;
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
gtp_xdp_ppp_map_action(struct bpf_map *map, int action, gtp_teid_t *t, int ifindex)
{
	gtp_session_t *s = t->session;
	spppoe_t *spppoe = s->s_pppoe;
	struct gtp_rt_rule *new = NULL;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err = 0;
	struct ip_rt_key rt_k;
	struct ppp_key ppp_k;
	size_t sz;

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
	} else if (action == RULE_DEL) {
		if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
			err = bpf_map__delete_elem(map, &rt_k, sizeof(struct ip_rt_key), 0);
		else
			err = bpf_map__delete_elem(map, &ppp_k, sizeof(struct ppp_key), 0);
	} else
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

	log_message(LOG_INFO, "%s(): %s %s XDP PPP rule {teid:0x%.8x, dst_addr:%u.%u.%u.%u} (ifindex:%d)"
			    , __FUNCTION__
			    , (action) ? "deleting" : "adding"
			    , (__test_bit(GTP_TEID_FL_EGRESS, &t->flags)) ? "egress" : "ingress"
			    , ntohl(t->id), NIPQUAD(t->ipv4), ifindex);
  end:
	if (new)
		free(new);
	return err;
}

static int
gtp_xdp_teid_vty(struct bpf_map *map, vty_t *vty, gtp_teid_t *t, int ifindex)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ip_rt_key rt_k = { 0 };
	struct ppp_key ppp_k = { 0 }, next_ppp_k = { 0 };
	struct gtp_rt_rule *r;
	gtp_session_t *s;
	spppoe_t *spppoe;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err = 0, i;
	uint64_t packets, bytes;
	size_t sz;

	/* Allocate temp rule */
	r = gtp_xdp_ppp_rule_alloc(&sz);
	if (!r) {
		vty_out(vty, "%% Cant allocate temp rt_rule%s", VTY_NEWLINE);
		return -1;
	}

	if (t) {
		s = t->session;
		spppoe = s->s_pppoe;

		if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags)) {
			gtp_xdp_rt_key_set(t, &rt_k);
			err = bpf_map__lookup_elem(map, &rt_k, sizeof(struct ip_rt_key), r, sz, 0);
		} else {
			if (!spppoe)
				goto end;

			gtp_xdp_ppp_key_set(t, &ppp_k, spppoe);
			err = bpf_map__lookup_elem(map, &ppp_k, sizeof(struct ppp_key), r, sz, 0);
		}

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

		vty_out(vty, "       %.7s pkts:%ld bytes:%ld (ifindex:%d)%s"
			, __test_bit(GTP_TEID_FL_EGRESS, &t->flags) ? "egress" : "ingress"
			, packets, bytes, ifindex, VTY_NEWLINE);
		goto end;
	}

	/* ingress hashtab */
	while (bpf_map__get_next_key(map, &ppp_k, &next_ppp_k, sizeof(struct ppp_key)) == 0) {
		ppp_k = next_ppp_k;
		err = bpf_map__lookup_elem(map, &ppp_k, sizeof(struct ppp_key), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for session:0x%.4x (%s)%s"
				   , ppp_k.session_id, errmsg, VTY_NEWLINE);
			continue;
		}

		packets = bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			packets += r[i].packets;
			bytes += r[i].bytes;
		}

		vty_out(vty, "| 0x%.8x | " ETHER_FMT "| %9s | %12ld | %19ld |%s"
			   , ntohl(r[0].teid)
			   , ETHER_BYTES(r[0].h_dst)
			   , "ingress"
			   , packets, bytes
			   , VTY_NEWLINE);
	}
  end:
	free(r);
	return 0;
}

int
gtp_xdp_ppp_action(int action, gtp_teid_t *t, int ifindex,
		   struct bpf_map *map_ingress, struct bpf_map *map_egress)
{
	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
		return gtp_xdp_ppp_map_action(map_egress, action, t, ifindex);

	return gtp_xdp_ppp_map_action(map_ingress, action, t, ifindex);
}

int
gtp_xdp_ppp_teid_vty(vty_t *vty, gtp_teid_t *t, int ifindex,
		     struct bpf_map *map_ingress, struct bpf_map *map_egress)
{
	int err = 0;

	if (!t) {
		err = (map_ingress) ? gtp_xdp_teid_vty(map_ingress, vty, NULL, ifindex) : 0;
		err = (err) ? : (map_egress) ? gtp_xdp_teid_vty(map_egress, vty, NULL, ifindex) : 0;
		return err;
	}

	if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
		return gtp_xdp_teid_vty(map_egress, vty, t, ifindex);

	return gtp_xdp_teid_vty(map_ingress, vty, t, ifindex);
}
