/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>

#include "tools.h"
#include "if_rule-def.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct if_rule_key);
	__type(value, struct if_rule);
} if_rule SEC(".maps");

struct if_rule_data
{
	struct if_rule_key k;
	struct if_rule r;
	void *payload;
};



static inline void
swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];
	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static inline int
_acl_ipv4(struct if_rule_key *k, struct if_rule *out_rule)
{
	struct if_rule *r;

	bpf_printk("acl: searching if:%d vlan:%d gre:%x",
		   k->ifindex, k->vlan_id, k->gre_remote);

	r = bpf_map_lookup_elem(&if_rule, k);
	if (r == NULL)
		return XDP_PASS;

	bpf_printk("got the rule ! ifindex:%d vlan:%d action:%d",
		   r->ifindex, r->vlan_id, r->action);

	*out_rule = *r;
	return r->action;
}


/*
 * parse first layers of an ip packet (eth, vlan, ip, gre),
 * without modifying packet. usually the first call of xdp program.
 *
 * looks in 'if' a rule that can match incoming trafic.
 *
 * thes rules are set by userapp. if found, rule gives an 'action'.
 * action is either XDP_*, or a custom value that caller will know.
 *
 * eg. for cgn: 10 for traffic coming from 'network-in', 11 for
 * traffic coming from 'network-out'.
 *
 * returns action's rule, or any of XDP_*. unsupported protocols
 * will XDP_PASS, obviously invalid packets will XDP_DROP.
 */
static int
if_rule_parse_pkt(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethh = data;
	struct vlan_hdr *vlanh;
	struct iphdr *ip4h;
	void *payload;
	__u16 eth_type;
	int ret;

	if ((void *)(ethh + 1) > data_end)
		return XDP_DROP;

	eth_type = ethh->h_proto;

	/* handle outer VLAN tag */
	if (eth_type == __constant_htons(ETH_P_8021Q) ||
	    eth_type == __constant_htons(ETH_P_8021AD)) {
		vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_DROP;
		d->k.vlan_id = bpf_ntohs(vlanh->vlan_tci) & 0x0fff;
		eth_type = vlanh->next_proto;
		payload = vlanh + 1;
	} else {
		payload = ethh + 1;
	}

	d->k.ifindex = ctx->ingress_ifindex;

	switch (eth_type) {
	case __constant_htons(ETH_P_IP):
		/* check ipv4 header */
		ip4h = payload;
		if ((void *)(ip4h + 1) > data_end)
			return XDP_DROP;

		/* may be a gre tunnel */
		if (ip4h->version == 0x45 &&
		    ip4h->protocol == IPPROTO_GRE) {
			struct gre_hdr *gre = (struct gre_hdr *)(ip4h + 1);

			if ((void *)(gre + 1) > data_end)
				return 1;
			if (GRE_VERSION(gre) == GRE_VERSION_1701 && gre->flags == 0) {
				/* is a basic gre tunnel */
				d->payload = gre + 1;
				d->k.gre_remote = ip4h->saddr;
				switch (gre->proto) {
				case __constant_htons(ETH_P_IP):
					return _acl_ipv4(&d->k, &d->r);
				default:
					return XDP_PASS;
				}
			}
		}
		/* handle this ipv4 payload */
		d->payload = payload;
		return _acl_ipv4(&d->k, &d->r);

	case __constant_htons(ETH_P_IPV6):
		/* XXX: todo */
		return XDP_PASS;

	default:
		return XDP_PASS;
	}

	return 10;
}

/*
 * rewrite packet according to 'if_rule'. usually the latest
 * call from xdp program.
 *
 * packet is intended to be forwarded, so mac addresses are swapped.
 *
 * if packet is going to be processed locally, then return XDP_PASS
 * before.
 */
static int
if_rule_rewrite_pkt(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethh = data;
	struct vlan_hdr *vlanh = (struct vlan_hdr *)(ethh + 1);

	/* handle vlan id */
	if (d->k.vlan_id || d->r.vlan_id) {
		struct vlan_hdr *vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_DROP;

		if (!d->k.vlan_id && d->r.vlan_id) {
			/* add vlan */

		} else if (d->k.vlan_id && !d->r.vlan_id) {
			/* remove vlan */

		} else {
			/* modify vlan */
			vlanh->vlan_tci = d->r.vlan_id;
		}
	} else {
		if ((void *)(ethh + 1) > data_end)
			return XDP_DROP;
	}

	/* XXX: handle gre tunnel */

	/* going back from the same interface.
	 * it is enough to swap mac address */
	if (d->k.ifindex == d->r.ifindex) {
		swap_src_dst_mac(ethh);
		return XDP_TX;
	}

	__builtin_memcpy(ethh->h_source, d->r.h_local, ETH_ALEN);
	__builtin_memcpy(ethh->h_dest, d->r.h_remote, ETH_ALEN);

	return bpf_redirect(d->r.ifindex, 0);
}
