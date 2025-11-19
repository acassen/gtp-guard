/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/types.h>
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
	__uint(max_entries, IF_RULE_MAX_RULE);
	__type(key, struct if_rule_key);
	__type(value, struct if_rule);
} if_rule SEC(".maps");

/* index by ifindex */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, IF_RULE_MAX_RULE);
	__type(key, __u32);
	__type(value, struct if_rule_attr);
} if_rule_attr SEC(".maps");



#define IF_RULE_FL_SRC_IPV6		0x0001
#define IF_RULE_FL_DST_IPV6		0x0002
#define IF_RULE_FL_XDP_ADJUSTED		0x0004
#define IF_RULE_FL_FILL_IPV4_SADDR	0x0008

struct if_rule_data
{
	struct xdp_md		*ctx;
	struct if_rule_key	k;
	struct if_rule		*r;
	__u16			flags;
	__u16			pl_off;
	union v4v6addr		dst_addr;
};



static __always_inline int
_acl_ipv4(struct if_rule_data *d, rule_selector_t rscb, struct iphdr *iph)
{
	struct if_rule_key_base *k = &d->k.b;
	int action = XDP_PASS;

	IFR_DBG("acl: in if:%d, searching if:%d vlan:%d tun:%pI4|%pI4",
		d->ctx->ingress_ifindex, k->ifindex, k->vlan_id,
		&k->tun_local, &k->tun_remote);

#ifdef IF_RULE_CUSTOM_KEY
	action = rscb(d, iph);
#else
	if (k->tun_remote) {
		/* tunnels are not bound to specific interface.
		 * remove these info for map lookup */
		__u32 ifindex = k->ifindex;
		__u16 vlan = k->vlan_id;
		k->ifindex = 0;
		k->vlan_id = 0;
		d->r = bpf_map_lookup_elem(&if_rule, k);
		k->ifindex = ifindex;
		k->vlan_id = vlan;
	} else {
		d->r = bpf_map_lookup_elem(&if_rule, k);
	}
#endif

	if (d->r == NULL)
		return action;

	IFR_DBG("got the rule! action:%d table:%d", d->r->action, d->r->table_id);

	d->r->pkt_in++;
	d->r->bytes_in += d->ctx->data_end - d->ctx->data;

	return d->r->action;
}

static __always_inline int
_acl_ipv6(struct if_rule_data *d, struct ipv6hdr *ip6h)
{
	struct if_rule_key_base *k = &d->k.b;

	IFR_DBG("acl: in6 if:%d, searching if:%d vlan:%d",
		d->ctx->ingress_ifindex, k->ifindex, k->vlan_id);

	d->r = bpf_map_lookup_elem(&if_rule, k);

	if (d->r == NULL)
		return XDP_PASS;

	IFR_DBG("got the 6rule! action:%d table:%d", d->r->action, d->r->table_id);

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
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6;
	struct if_rule_key_base *k = &d->k.b;
	__u16 offset;
	__u16 eth_type;
	__u8 proto;

	if ((void *)(ethh + 1) > data_end)
		return XDP_DROP;

	eth_type = ethh->h_proto;

	/* handle outer VLAN tag */
	if (eth_type == __constant_htons(ETH_P_8021Q) ||
	    eth_type == __constant_htons(ETH_P_8021AD)) {
		vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_DROP;
		k->vlan_id = bpf_ntohs(vlanh->vlan_tci) & 0x0fff;
		eth_type = vlanh->next_proto;
		offset = sizeof (*ethh) + sizeof (*vlanh);
	} else {
		offset = sizeof (*ethh);
	}

	k->ifindex = ctx->ingress_ifindex;

	switch (eth_type) {
	case __constant_htons(ETH_P_IP):
		/* check ipv4 header */
		ip4h = data + offset;
		if ((void *)(ip4h + 1) > data_end ||
		    ip4h->version != 4 || ip4h->ihl < 5)
			return XDP_DROP;

		/* may be an ipip tunnel */
		if (ip4h->ihl == 5 &&
		    ip4h->protocol == IPPROTO_IPIP) {
			k->tun_local = ip4h->daddr;
			k->tun_remote = ip4h->saddr;
			k->flags |= IF_RULE_FL_TUNNEL_IPIP;

			offset += sizeof (*ip4h);
			ip4h_in = (struct iphdr *)(data + offset);
			if ((void *)(ip4h_in + 1) > data_end)
				return XDP_DROP;
			d->pl_off = offset;
			return _acl_ipv4(d, rscb, ip4h_in);
		}

		/* may be a gre tunnel */
		if (ip4h->ihl == 5 &&
		    ip4h->protocol == IPPROTO_GRE) {
			offset += sizeof (*ip4h);
			struct gre_hdr *gre = (struct gre_hdr *)(data + offset);
			if ((void *)(gre + 1) > data_end)
				return 1;
			if (GRE_VERSION(gre) == GRE_VERSION_1701 && gre->flags == 0) {
				/* is a basic gre tunnel */
				k->tun_local = ip4h->daddr;
				k->tun_remote = ip4h->saddr;
				k->flags |= IF_RULE_FL_TUNNEL_GRE;

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
		ip6h = data + offset;
		if ((void *)(ip6h + 1) > data_end || ip6h->version != 6)
			return XDP_DROP;

		if (IN6_IS_ADDR_LINKLOCAL(&ip6h->saddr))
			return XDP_PASS;

		d->pl_off = offset;
		d->flags |= IF_RULE_FL_SRC_IPV6;
		return _acl_ipv6(d, ip6h);

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
if_rule_rewrite_pkt(struct if_rule_data *d)
{
	struct xdp_md *ctx = d->ctx;
	const struct if_rule_key_base *k = &d->k.b;
	struct bpf_fib_lookup fibp;
	struct if_rule_attr *a, *ia;
	void *data, *data_end, *payload;
	struct ethhdr *ethh;
	int fibl_ret, adjust_sz;
	__u32 flags;

	if (d->r->force_ifindex) {
		/* can only be used to enter a tunnel */
		fibp.ifindex = d->r->force_ifindex;
		fibl_ret = BPF_FIB_LKUP_RET_NO_NEIGH;

	} else {
		__builtin_memset(&fibp, 0x00, sizeof (fibp));
		fibp.ifindex = ctx->ingress_ifindex;
		if (d->flags & IF_RULE_FL_DST_IPV6) {
			fibp.family = AF_INET6;
			fibp.ipv6_dst[0] = d->dst_addr.ip6.addr4[0];
			fibp.ipv6_dst[1] = d->dst_addr.ip6.addr4[1];
			fibp.ipv6_dst[2] = d->dst_addr.ip6.addr4[2];
			fibp.ipv6_dst[3] = d->dst_addr.ip6.addr4[3];
		} else {
			fibp.family = AF_INET;
			fibp.ipv4_dst = d->dst_addr.ip4;
		}

		flags = BPF_FIB_LOOKUP_DIRECT;
		if (d->flags & IF_RULE_FL_FILL_IPV4_SADDR)
			flags |= BPF_FIB_LOOKUP_SRC;
		if (d->r->table_id) {
			flags |= BPF_FIB_LOOKUP_TBID;
			fibp.tbid = d->r->table_id;
		}

		fibl_ret = bpf_fib_lookup(ctx, &fibp, sizeof (fibp), flags);
		if (fibl_ret < 0) {
			bpf_printk("fib_lookup(if=%d) failed: %d",
				   ctx->ingress_ifindex, fibl_ret);
			return XDP_ABORTED;
		}
#ifdef IF_RULE_DEBUG
		if (d->flags & IF_RULE_FL_DST_IPV6) {
			bpf_printk("bpf_fib_lookup(%d): dst:%pI6 if:%d->%d "
				   "from %pI6 nh %pI6 mac_src:%02x mac_dst:%02x",
				   fibl_ret, d->dst_addr.ip6.addr4, ctx->ingress_ifindex,
				   fibp.ifindex, fibp.ipv6_src, fibp.ipv6_dst,
				   fibp.smac[5], fibp.dmac[5]);
		} else {
			bpf_printk("bpf_fib_lookup(%d): dst:%pI4 if:%d->%d "
				   "from %pI4 nh %pI4 mac_src:%02x mac_dst:%02x",
				   fibl_ret, &d->dst_addr.ip4, ctx->ingress_ifindex,
				   fibp.ifindex, &fibp.ipv4_src, &fibp.ipv4_dst,
				   fibp.smac[5], fibp.dmac[5]);
		}
#endif
		if (fibl_ret != BPF_FIB_LKUP_RET_SUCCESS &&
		    fibl_ret != BPF_FIB_LKUP_RET_NO_NEIGH)
			return XDP_DROP;

		if (d->flags & IF_RULE_FL_FILL_IPV4_SADDR) {
			struct iphdr *ip4h = (void *)(long)ctx->data + d->pl_off;
			if (d->pl_off > 256 ||
			    (void *)(ip4h + 1) > (void *)(long)ctx->data_end)
				return XDP_DROP;
			if (!ip4h->saddr) {
				ip4h->saddr = fibp.ipv4_src;
				__u32 sum = csum_diff32(0, 0, ip4h->saddr);
				ip4h->check = csum_replace(ip4h->check, sum);
			}
		}
	}

	/* retrieve output interface attributes */
	ia = bpf_map_lookup_elem(&if_rule_attr, &fibp.ifindex);
	if (ia == NULL) {
		IFR_DBG("iface:%d not in attr! drop", fibp.ifindex);
		return XDP_DROP;
	}
	IFR_DBG(" output to if:%d vlan:%d tun:%d %pI4->%pI4",
		ia->ifindex, ia->vlan_id, ia->flags, &ia->tun_local, &ia->tun_remote);

	/* do a second fib_lookup to retrieve outer mac addresss  */
	if (ia->tun_remote) {
		__builtin_memset(&fibp, 0x00, sizeof (fibp));
		flags = BPF_FIB_LOOKUP_DIRECT;
		fibp.ifindex = ctx->ingress_ifindex;
		fibp.family = AF_INET;
		fibp.ipv4_dst = ia->tun_remote;
		fibl_ret = bpf_fib_lookup(ctx, &fibp, sizeof (fibp), flags);
		if (fibl_ret < 0) {
			bpf_printk("fib_lookup(if=%d, dst=%pI4) tun failed: %d",
				   ctx->ingress_ifindex, &ia->tun_remote, fibl_ret);
			return XDP_ABORTED;
		}

		a = bpf_map_lookup_elem(&if_rule_attr, &fibp.ifindex);
		if (a == NULL) {
			IFR_DBG("outer iface:%d not in attr! drop", fibp.ifindex);
			return XDP_DROP;
		}
		IFR_DBG(" output outer tun to ret:%d if:%d vlan:%d tun:%d",
			fibl_ret, a->ifindex, a->vlan_id, a->flags);
	} else {
		if (fibl_ret != BPF_FIB_LKUP_RET_SUCCESS)
			return XDP_DROP;
		a = ia;
	}

	if (fibl_ret != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_DROP;

	/* compute how much we need to shrink/expand pkt */
	adjust_sz = 0;
	if (!k->vlan_id && a->vlan_id) {
		adjust_sz -= sizeof (struct vlan_hdr);
	} else if (k->vlan_id && !a->vlan_id) {
		adjust_sz += sizeof (struct vlan_hdr);
	}
	if (!k->tun_remote && ia->tun_remote) {
		adjust_sz -= sizeof (struct iphdr);
		if (ia->flags & IF_RULE_FL_TUNNEL_GRE)
			adjust_sz -= sizeof (struct gre_hdr);
	} else if (k->tun_remote && !ia->tun_remote) {
		adjust_sz += sizeof (struct iphdr);
		if (k->flags & IF_RULE_FL_TUNNEL_GRE)
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

	if (a->vlan_id && (k->vlan_id != a->vlan_id || adjust_sz)) {
		/* need to set/modify vlan hdr */
		struct vlan_hdr *vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_DROP;

		vlanh->vlan_tci = bpf_ntohs(a->vlan_id);
		vlanh->next_proto = d->flags & IF_RULE_FL_DST_IPV6 ?
			__constant_htons(ETH_P_IPV6) :
			__constant_htons(ETH_P_IP);
		ethh->h_proto = __constant_htons(ETH_P_8021Q);
		payload = vlanh + 1;

	} else {
		if ((void *)(ethh + 1) > data_end)
			return XDP_DROP;

		/* remove vlan header */
		ethh->h_proto = d->flags & IF_RULE_FL_DST_IPV6 ?
			__constant_htons(ETH_P_IPV6) :
			__constant_htons(ETH_P_IP);

		payload = ethh + 1;
	}

	/* add ipip/gre tunnel if necessary */
	if (ia->tun_remote) {
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
		ip4h->saddr = ia->tun_local;
		ip4h->daddr = ia->tun_remote;

		if (ia->flags & IF_RULE_FL_TUNNEL_GRE) {
			ip4h->protocol = IPPROTO_GRE;
			struct gre_hdr *gre = (struct gre_hdr *)(ip4h + 1);
			if ((void *)(gre + 1) > data_end)
				return XDP_DROP;
			gre->flags = 0;
			gre->version = GRE_VERSION_1701;
			gre->proto = d->flags & IF_RULE_FL_DST_IPV6 ?
				__constant_htons(ETH_P_IPV6) :
				__constant_htons(ETH_P_IP);
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

	/* remember that forwarding must be enabled on input interface ! */
	return bpf_redirect(a->ifindex, 0);
}
