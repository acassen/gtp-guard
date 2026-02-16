/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "upf-def.h"
#include "if_rule.h"


/*
 *	MAPs
 */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1000000);
	__type(key, struct upf_egress_key);
	__type(value, struct upf_fwd_rule);
} user_egress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000000);
	__type(key, struct upf_ingress_key);
	__type(value, struct upf_fwd_rule);
} user_ingress SEC(".maps");


static __always_inline int
_encap_gtpu(struct xdp_md *ctx, struct if_rule_data *d, struct upf_fwd_rule *u)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph;
	void *data, *data_end;
	int adjust_sz, pkt_len;
	__u32 csum = 0;

	/* encap in gtp-u, make room */
	adjust_sz = sizeof(*iph) + sizeof(*udph) + sizeof(*gtph);
	if (bpf_xdp_adjust_head(ctx, -adjust_sz) < 0)
		return XDP_ABORTED;

	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* then write encap headers */
	iph = data + d->pl_off;
	udph = (struct udphdr *)(iph + 1);
	gtph = (struct gtphdr *)(udph + 1);
	if (d->pl_off > 256 || (void *)(gtph + 1) > data_end)
		return XDP_PASS;

#if __clang_major__ == 21 && __clang_minor__ == 1
	/* fix '32-bit pointer arithmetic prohibited'.
	 * this could be a clang bug and should be removed */
	pkt_len = data_end - data;
	barrier_var(pkt_len);
	pkt_len -= d->pl_off;
#else
	pkt_len = data_end - data - d->pl_off;
#endif
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = IPPROTO_UDP;
	iph->tos = 0;
	iph->tot_len = bpf_htons(pkt_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->check = 0;
	iph->saddr = u->gtpu_local_addr;
	iph->daddr = u->gtpu_remote_addr;
	csum_ipv4(iph, sizeof(*iph), &csum);
	iph->check = csum;

	pkt_len -= sizeof(*iph);
	udph->source = u->gtpu_local_port;
	udph->dest = u->gtpu_remote_port;
	udph->len = bpf_htons(pkt_len);
	udph->check = 0;	/* hardware checksum feature, save us! */

	pkt_len -= sizeof(*udph) + sizeof(*gtph);
	gtph->flags = GTPU_FLAGS;
	gtph->type = GTPU_TPDU;
	gtph->length = bpf_htons(pkt_len);
	gtph->teid = u->gtpu_remote_teid;

	d->dst_addr.ip4 = u->gtpu_remote_addr;

	/* metrics */
	++u->fwd_packets;
	u->fwd_bytes += pkt_len;

	UPF_DBG("to_gtpu: encap teid:0x%08x src:%pI4:%d dst:%pI4:%d",
		   bpf_ntohl(u->gtpu_remote_teid),
		   &iph->saddr, bpf_ntohs(u->gtpu_local_port),
		   &iph->daddr, bpf_ntohs(u->gtpu_remote_port));

	return XDP_IFR_FORWARD;
}

/*
 *	Ingress direction (UE pov), ipv6 traffic from internet
 */
static __always_inline int
upf_handle_pubv6(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct upf_ingress_key k = {};
	struct upf_fwd_rule *u;
	struct ipv6hdr *ip6h;

	/* lookup user */
	ip6h = (struct ipv6hdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(ip6h + 1) > data_end)
		return XDP_PASS;

	k.flags = UE_IPV6;
	__builtin_memcpy(k.ue_addr.ip6.addr, ip6h->daddr.s6_addr, 16);
	u = bpf_map_lookup_elem(&user_ingress, &k);
	if (u == NULL)
		return XDP_PASS;

	return _encap_gtpu(ctx, d, u);
}

/*
 *	Ingress direction (UE pov), ipv4 traffic from internet
 */
static __always_inline int
upf_handle_pub(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct upf_ingress_key k = {};
	struct upf_fwd_rule *u;
	struct iphdr *iph;

	if (d->flags & IF_RULE_FL_SRC_IPV6)
		return upf_handle_pubv6(ctx, d);

	/* lookup user */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_PASS;

	k.flags = UE_IPV4;
	k.ue_addr.ip4 = iph->daddr;
	u = bpf_map_lookup_elem(&user_ingress, &k);
	if (u == NULL)
		return XDP_PASS;

	return _encap_gtpu(ctx, d, u);
}


static __always_inline int
_handle_gtpu(struct xdp_md *ctx, struct if_rule_data *d,
	     struct iphdr *iph, struct udphdr *udph)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct upf_egress_key k;
	struct upf_fwd_rule *u;
	struct iphdr *ip4h_inner;
	struct ipv6hdr *ip6h_inner;
	struct gtphdr *gtph;
	int adjust_sz, pkt_len;
	__u32 sum;

	gtph = (struct gtphdr *)(udph + 1);
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* only handle gtp-u data packet */
	if (gtph->type != 0xff)
		return XDP_PASS;

	/* lookup user */
	k.gtpu_local_teid = gtph->teid;
	k.gtpu_local_addr = iph->daddr;
	k.gtpu_local_port = udph->dest;
	u = bpf_map_lookup_elem(&user_egress, &k);
	UPF_DBG("from_gtpu: lookup dst:%pI4:%d teid:%x%s",
		   &iph->daddr, bpf_ntohs(udph->dest), bpf_ntohl(gtph->teid),
		   u == NULL ? " => NOT FOUND" : "");
	if (u == NULL)
		return XDP_PASS;

#if __clang_major__ == 21 && __clang_minor__ == 1
	pkt_len = data_end - data;
	barrier_var(pkt_len);
	pkt_len -= d->pl_off + adjust_sz;
#else
	pkt_len = data_end - data - d->pl_off - adjust_sz;
#endif

	if ((u->flags & UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) ==
	    UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) {
		/* forward gtp-u as-this */
		sum = csum_diff32(0, iph->saddr, u->gtpu_local_addr);
		sum = csum_diff32(sum, iph->daddr, u->gtpu_remote_addr);
		iph->saddr = u->gtpu_local_addr;
		iph->daddr = u->gtpu_remote_addr;
		--iph->ttl;
		iph->check = csum_replace(iph->check, sum - 1);

		if (udph->check) {
			sum = csum_diff16(sum, udph->source, u->gtpu_local_port);
			sum = csum_diff16(sum, udph->dest, u->gtpu_remote_port);
			sum = csum_diff32(sum, gtph->teid, u->gtpu_remote_teid);
			__u16 nsum = csum_replace(udph->check, sum);
			udph->check = nsum ?: 0xffff;
		}
		udph->source = u->gtpu_local_port;
		udph->dest = u->gtpu_remote_port;
		gtph->teid = u->gtpu_remote_teid;
		UPF_DBG("rewrite_gtpu: src:%pI4:%d dst:%pI4:%d teid:%x",
			   &iph->saddr, bpf_ntohs(udph->source),
			   &iph->daddr, bpf_ntohs(udph->dest),
			   bpf_ntohl(gtph->teid));

		/* metrics */
		++u->fwd_packets;
		u->fwd_bytes += pkt_len;

		d->dst_addr.ip4 = iph->daddr;
		return XDP_IFR_FORWARD;
	}

	/* for futur nh lookup */
	ip4h_inner = (struct iphdr *)(gtph + 1);
	if (ip4h_inner + 1 > data_end)
		return XDP_DROP;
	switch (ip4h_inner->version) {
	case 4:
		d->dst_addr.ip4 = ip4h_inner->daddr;
		break;
	case 6:
		ip6h_inner = (struct ipv6hdr *)ip4h_inner;
		if (ip6h_inner + 1 > data_end)
			return XDP_DROP;
		__builtin_memcpy(d->dst_addr.ip6.addr,
				 ip6h_inner->daddr.s6_addr, 16);
		d->flags |= IF_RULE_FL_DST_IPV6;
		break;
	default:
		return XDP_DROP;
	}

	/* decap gtp-u */
	adjust_sz = (void *)(gtph + 1) - (void *)iph;
	if (bpf_xdp_adjust_head(ctx, adjust_sz) < 0)
		return XDP_ABORTED;
	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	/* metrics */
	++u->fwd_packets;
	u->fwd_bytes += pkt_len - adjust_sz;

	return XDP_IFR_FORWARD;
}


/*
 *	Egress direction (UE pov), traffic from GTP-U endpoint
 */
static __attribute__((noinline)) int
upf_handle_gtpu(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *iph;
	struct udphdr *udph;

	/* check input gtp-u (proto udp and port) */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udph = (void *)(iph) + iph->ihl * 4;
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_PASS;

	return _handle_gtpu(ctx, d, iph, udph);
}


/*
 *	Choose between gtp-u and l3 side
 */
static __attribute__((noinline)) int
upf_traffic_selector(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *iph;
	struct udphdr *udph;

	if (d->flags & IF_RULE_FL_SRC_IPV6)
		return upf_handle_pubv6(ctx, d);

	/* check input gtp-u (proto udp and port) */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->protocol != IPPROTO_UDP)
		return upf_handle_pub(ctx, d);

	udph = (void *)(iph) + iph->ihl * 4;
	if (udph + 1 > data_end)
		return XDP_DROP;

	/* this is our gtp-u ! */
	if (udph->dest == bpf_htons(GTPU_PORT))
		return _handle_gtpu(ctx, d, iph, udph);

	return upf_handle_pub(ctx, d);
}
