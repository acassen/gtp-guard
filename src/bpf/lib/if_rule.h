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

/*
 * this is an optional way to add custom data to if_rule key: define
 * if_rule_key, IF_RULE_CUSTOM_KEY, and add a parser function to
 * if_rule_data.
 */
#ifndef IF_RULE_CUSTOM_KEY

struct if_rule_key
{
	struct if_rule_key_base b;
} __attribute__((packed));
typedef void *rule_selector_t;

#else /* ifdef IF_RULE_CUSTOM_KEY */

struct if_rule_data;
typedef int (*rule_selector_t)(struct if_rule_data *d, struct iphdr *iph);

#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 2048);
	__type(key, struct if_rule_key);
	__type(value, struct if_rule);
} if_rule SEC(".maps");

#define IF_RULE_FL_XDP_ADJUSTED		0x01


struct if_rule_data
{
	struct xdp_md *ctx;
	struct if_rule_key k;
	struct if_rule *r;
	__u16 flags;
	__u16 pl_off;
	__u32 dst_addr;
};



static __always_inline int
_acl_ipv4(struct if_rule_data *d, rule_selector_t rscb, struct iphdr *iph)
{
	struct if_rule_key_base *k = &d->k.b;
	int action = XDP_PASS;

	bpf_printk("acl: searching if:%d vlan:%d tun:%x|%x",
		   k->ifindex, k->vlan_id, k->tun_local, k->tun_remote);

#ifdef IF_RULE_CUSTOM_KEY
	action = rscb(d, iph);
#else
	d->r = bpf_map_lookup_elem(&if_rule, &d->k);
#endif

	if (d->r == NULL)
		return action;

	bpf_printk("got the rule ! table:%d vlan:%d gre_r:%x action:%d iface:%d",
		   d->r->table, d->r->vlan_id, d->r->tun_remote,
		   d->r->action, d->r->ifindex);

	d->r->pkt_in++;
	d->r->bytes_in += d->ctx->data_end - d->ctx->data;

	return d->r->action;
}


/*
 * parse first layers of an ip packet (eth, vlan, ip, gre),
 * without modifying packet. usually the first call of xdp program.
 *
 * looks in 'if_rule' a rule that can match incoming trafic.
 *
 * thes rules are set by userapp. if found, rule gives an 'action'.
 * action is either XDP_*, or a custom value that caller will know.
 *
 * eg. for cgn: 10 for traffic coming from 'network-in', 11 for
 * traffic coming from 'network-out'.
 *
 * returns action's rule, or any of XDP_*:
 *   - returns XDP_PASS on unsupported protocols
 *   - returns XDP_DROP on invalid packets
 */
static __attribute__((noinline)) int
if_rule_parse_pkt(struct if_rule_data *d, rule_selector_t rscb)
{
	struct xdp_md *ctx = d->ctx;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethh = data;
	struct vlan_hdr *vlanh;
	struct iphdr *ip4h, *ip4h_in;
	__u16 offset;
	__u16 eth_type;

	if ((void *)(ethh + 1) > data_end)
		return XDP_DROP;

	eth_type = ethh->h_proto;

	/* handle outer VLAN tag */
	if (eth_type == __constant_htons(ETH_P_8021Q) ||
	    eth_type == __constant_htons(ETH_P_8021AD)) {
		vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_DROP;
		d->k.b.vlan_id = bpf_ntohs(vlanh->vlan_tci) & 0x0fff;
		eth_type = vlanh->next_proto;
		offset = sizeof (*ethh) + sizeof (*vlanh);
	} else {
		offset = sizeof (*ethh);
	}

	d->k.b.ifindex = ctx->ingress_ifindex;

	switch (eth_type) {
	case __constant_htons(ETH_P_IP):
		//d->family = AF_INET;

		/* check ipv4 header */
		ip4h = data + offset;
		if ((void *)(ip4h + 1) > data_end)
			return XDP_DROP;

		/* may be an ipip tunnel */
		if (ip4h->version == 4 &&
		    ip4h->ihl == 5 &&
		    ip4h->protocol == IPPROTO_IPIP) {
			d->k.b.tun_local = ip4h->daddr;
			d->k.b.tun_remote = ip4h->saddr;

			offset += sizeof (*ip4h);
			ip4h_in = (struct iphdr *)(data + offset);
			if ((void *)(ip4h_in + 1) > data_end)
				return XDP_DROP;
			d->pl_off = offset;
			return _acl_ipv4(d, rscb, ip4h_in);
		}

		/* may be a gre tunnel */
		if (ip4h->version == 4 &&
		    ip4h->ihl == 5 &&
		    ip4h->protocol == IPPROTO_GRE) {
			offset += sizeof (*ip4h);
			struct gre_hdr *gre = (struct gre_hdr *)(data + offset);
			if ((void *)(gre + 1) > data_end)
				return 1;
			if (GRE_VERSION(gre) == GRE_VERSION_1701 && gre->flags == 0) {
				/* is a basic gre tunnel */
				d->k.b.tun_local = ip4h->daddr;
				d->k.b.tun_remote = ip4h->saddr;

				offset += sizeof (*gre);
				ip4h_in = (struct iphdr *)(data + offset);
				if ((void *)(ip4h_in + 1) > data_end)
					return XDP_DROP;
				d->pl_off = offset;
				switch (gre->proto) {
				case __constant_htons(ETH_P_IP):
					return _acl_ipv4(d, rscb, ip4h_in);
				default:
					return XDP_PASS;
				}
			}
		}

		/* handle this ipv4 payload */
		d->pl_off = offset;
		return _acl_ipv4(d, rscb, ip4h);

	case __constant_htons(ETH_P_IPV6):
		/* XXX: todo */
		return XDP_PASS;

	default:
		return XDP_PASS;
	}
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
	const struct if_rule_key_base *k = &d->k.b;
	void *data, *data_end, *payload;
	struct ethhdr *ethh;
	int adjust_sz = 0;
	int ret;

	struct bpf_fib_lookup fibp = {
		.ifindex = ctx->ingress_ifindex,
	};
	fibp.family = AF_INET;

	__u32 flags = BPF_FIB_LOOKUP_DIRECT;
	if (d->r->tun_remote) {
		flags |= BPF_FIB_LOOKUP_SRC;
		fibp.ipv4_dst = d->r->tun_remote;
	} else {
		fibp.ipv4_dst = d->dst_addr;
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
	if (!k->vlan_id && d->r->vlan_id) {
		adjust_sz -= sizeof (struct vlan_hdr);
	} else if (k->vlan_id && !d->r->vlan_id) {
		adjust_sz += sizeof (struct vlan_hdr);
	}
	if (!k->tun_remote && d->r->tun_remote) {
		adjust_sz -= sizeof (struct iphdr);
		if (d->r->flags & IF_RULE_FL_TUNNEL_GRE)
			adjust_sz -= sizeof (struct gre_hdr);
	} else if (k->tun_remote && !d->r->tun_remote) {
		adjust_sz += sizeof (struct iphdr);
		if (d->r->flags & IF_RULE_FL_TUNNEL_GRE)
			adjust_sz += sizeof (struct gre_hdr);
	}

	/* and adjust it */
	if (adjust_sz && bpf_xdp_adjust_head(ctx, adjust_sz) < 0)
		return XDP_ABORTED;

	/* adjusted in modules. rewrite all eth/vlan fields */
	if (d->flags & IF_RULE_FL_XDP_ADJUSTED)
		adjust_sz = 1;

	/* build output packet iface encap */
	ethh = data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (d->r->vlan_id && (k->vlan_id != d->r->vlan_id || adjust_sz)) {
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
		if ((k->vlan_id && !d->r->vlan_id) || adjust_sz)
			ethh->h_proto = __constant_htons(ETH_P_IP);

		payload = ethh + 1;
	}

	/* add ipip/gre tunnel if necessary */
	if (d->r->tun_remote) {
		struct iphdr *ip4h = payload;
		if ((void *)(ip4h + 1) > data_end)
			return XDP_DROP;

		__u32 csum = 0;

		ip4h->version = 4;
		ip4h->ihl = 5;
		ip4h->tos = 0;
		ip4h->tot_len = bpf_htons(data_end - payload);
		ip4h->id = 0;
		ip4h->frag_off = 0;
		ip4h->ttl = 64;
		ip4h->check = 0;
		ip4h->saddr = fibp.ipv4_src;
		ip4h->daddr = d->r->tun_remote;

		if (d->r->flags & IF_RULE_FL_TUNNEL_GRE) {
			ip4h->protocol = IPPROTO_GRE;
			struct gre_hdr *gre = (struct gre_hdr *)(ip4h + 1);
			if ((void *)(gre + 1) > data_end)
				return XDP_DROP;
			gre->flags = 0;
			gre->version = GRE_VERSION_1701;
			gre->proto = __constant_htons(ETH_P_IP);
		} else {
			ip4h->protocol = IPPROTO_IPIP;
		}

		csum_ipv4(ip4h, sizeof(struct iphdr), &csum);
		ip4h->check = csum;
	}

	/* metrics */
	d->r->pkt_fwd++;

	__builtin_memcpy(ethh->h_source, fibp.smac, ETH_ALEN);
	__builtin_memcpy(ethh->h_dest, fibp.dmac, ETH_ALEN);

	/* remember that forwarding must be enabled on these interfaces ! */
	return bpf_redirect(d->r->ifindex ?: fibp.ifindex, 0);
}
