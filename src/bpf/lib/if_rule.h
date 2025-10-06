/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <sys/socket.h>
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
	struct if_rule *r;
	void *payload;
	__u32 dst_addr;
};



static inline int
_acl_ipv4(struct if_rule_key *k, struct if_rule_data *d)
{
	bpf_printk("acl: searching if:%d vlan:%d gre:%x",
		   k->ifindex, k->vlan_id, k->gre_remote);

	d->r = bpf_map_lookup_elem(&if_rule, k);
	if (d->r == NULL)
		return XDP_PASS;

	bpf_printk("got the rule ! table:%d vlan:%d gre_r:%x action:%d iface:%d",
		   d->r->table, d->r->vlan_id, d->r->gre_remote,
		   d->r->action, d->r->ifindex);

	return d->r->action;
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
static __attribute__((noinline)) int
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
		//d->family = AF_INET;

		/* check ipv4 header */
		ip4h = payload;
		if ((void *)(ip4h + 1) > data_end)
			return XDP_DROP;

		/* may be a gre tunnel */
		if (ip4h->version == 4 &&
		    ip4h->ihl == 5 &&
		    ip4h->protocol == IPPROTO_GRE) {
			struct gre_hdr *gre = (struct gre_hdr *)(ip4h + 1);
			if ((void *)(gre + 1) > data_end)
				return 1;
			if (GRE_VERSION(gre) == GRE_VERSION_1701 && gre->flags == 0) {
				/* is a basic gre tunnel */
				d->k.gre_remote = ip4h->saddr;

				ip4h = (struct iphdr *)(gre + 1);
				if ((void *)(ip4h + 1) > data_end)
					return XDP_DROP;
				d->payload = ip4h;
				switch (gre->proto) {
				case __constant_htons(ETH_P_IP):
					return _acl_ipv4(&d->k, d);
				default:
					return XDP_PASS;
				}
			}
		}

		/* handle this ipv4 payload */
		d->payload = payload;
		return _acl_ipv4(&d->k, d);

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
 * if packet is going to be processed locally, then return XDP_PASS
 * before.
 */
static __attribute__((noinline)) int
if_rule_rewrite_pkt(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data, *data_end, *payload;
	struct ethhdr *ethh;
	int adjust_sz = 0;
	int ret;

	struct bpf_fib_lookup fibp = {
		.ifindex = ctx->ingress_ifindex,
	};
	fibp.family = AF_INET;
	fibp.ipv4_dst = bpf_ntohl(d->dst_addr);

	__u32 flags = BPF_FIB_LOOKUP_DIRECT;
	if (d->r->gre_remote) {
		flags |= BPF_FIB_LOOKUP_SRC;
		fibp.ipv4_dst = d->r->gre_remote;
	} else {
		fibp.ipv4_dst = bpf_ntohl(d->dst_addr);
	}
	if (d->r->table) {
		flags |= BPF_FIB_LOOKUP_TBID;
		fibp.tbid = d->r->table;
	}

	ret = bpf_fib_lookup(ctx, &fibp, sizeof (fibp), flags);
	if (ret < 0) {
		bpf_printk("fib_lookup failed: %d", ret);
		return XDP_ABORTED;
	}
	bpf_printk("bpf_fib_lookup(%d): dst:%x if:%d->%d(=>%d) "
		   "from %x nh %x mac_src:%02x mac_dst:%02x",
		   ret, d->dst_addr, ctx->ingress_ifindex, fibp.ifindex,
		   d->r->ifindex ?: fibp.ifindex,
		   fibp.ipv4_src, fibp.ipv4_dst, fibp.smac[5], fibp.dmac[5]);
	if (ret != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_DROP;

	/* compute how much we need to shrink/expand pkt */
	if (!d->k.vlan_id && d->r->vlan_id) {
		adjust_sz -= sizeof (struct vlan_hdr);
	} else if (d->k.vlan_id && !d->r->vlan_id) {
		adjust_sz += sizeof (struct vlan_hdr);
	}
	if (!d->k.gre_remote && d->r->gre_remote) {
		adjust_sz -= sizeof (struct gre_hdr) + sizeof (struct iphdr);
	} else if (d->k.gre_remote && !d->r->gre_remote) {
		adjust_sz += sizeof (struct gre_hdr) + sizeof (struct iphdr);
	}

	/* and adjust it */
	if (adjust_sz && bpf_xdp_adjust_head(ctx, adjust_sz) < 0)
		return XDP_ABORTED;

	/* build output packet iface encap */
	ethh = data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (d->r->vlan_id && (d->k.vlan_id != d->r->vlan_id || adjust_sz)) {
		/* need to set/modify vlan hdr */
		struct vlan_hdr *vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_DROP;

		vlanh->vlan_tci = bpf_ntohs(d->r->vlan_id);
		vlanh->next_proto = __constant_htons(ETH_P_IP);
		ethh->h_proto = __constant_htons(ETH_P_8021Q);
		payload = vlanh + 1;

	} else {
		if ((void *)(ethh + 1) > data_end)
			return XDP_DROP;

		/* remove vlan header */
		if ((d->k.vlan_id && !d->r->vlan_id) || adjust_sz)
			ethh->h_proto = __constant_htons(ETH_P_IP);

		payload = ethh + 1;
	}

	/* add gre tunnel if necessary */
	if (d->r->gre_remote) {
		struct iphdr *ip4h = payload;
		if ((void *)(ip4h + 1) > data_end)
			return XDP_DROP;

		struct gre_hdr *gre = (struct gre_hdr *)(ip4h + 1);
		if ((void *)(gre + 1) > data_end)
			return XDP_DROP;

		__u32 csum = 0;

		ip4h->version = 4;
		ip4h->ihl = 5;
		ip4h->tos = 0;
		ip4h->tot_len = bpf_htons(data_end - payload);
		ip4h->id = 0;
		ip4h->frag_off = 0;
		ip4h->ttl = 64;
		ip4h->protocol = IPPROTO_GRE;
		ip4h->check = 0;
		ip4h->saddr = fibp.ipv4_src;
		ip4h->daddr = d->r->gre_remote;
		csum_ipv4(ip4h, sizeof(struct iphdr), &csum);
		ip4h->check = csum;
		gre->flags = 0;
		gre->version = GRE_VERSION_1701;
		gre->proto = __constant_htons(ETH_P_IP);
	}

	__builtin_memcpy(ethh->h_source, fibp.smac, ETH_ALEN);
	__builtin_memcpy(ethh->h_dest, fibp.dmac, ETH_ALEN);

	/* remember that forwarding must be enabled on these interfaces ! */
	return bpf_redirect(d->r->ifindex ?: fibp.ifindex, 0);
}
