/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <time.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "upf-def.h"


/*
 *	MAPs
 */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1000000);
	__type(key, struct upf_user_egress_key);
	__type(value, struct upf_user_egress);
} user_egress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000000);
	__type(key, struct upf_user_ingress_key);
	__type(value, struct upf_user_ingress);
} user_ingress SEC(".maps");


/*
 *	Ingress direction (UE pov), traffic from internet
 */
static __always_inline int
upf_handle_pub(struct if_rule_data *d)
{
	void *data = (void *)(long)d->ctx->data;
	void *data_end = (void *)(long)d->ctx->data_end;
	struct upf_user_ingress_key k = {};
	struct upf_user_ingress *u;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph;
	int adjust_sz, pkt_len;
	__u32 csum = 0;

	/* lookup user */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_PASS;

	k.flags = UE_IPV4;
	k.ue_addr.ip4 = iph->daddr;
	u = bpf_map_lookup_elem(&user_ingress, &k);
	if (u == NULL)
		return XDP_PASS;

	/* encap in gtp-u, make room */
	adjust_sz = sizeof(*iph) + sizeof(*udph) + sizeof(*gtph);
	if (bpf_xdp_adjust_head(d->ctx, -adjust_sz) < 0)
		return XDP_ABORTED;

	d->flags |= IF_RULE_FL_XDP_ADJUSTED | IF_RULE_FL_FILL_IPV4_SADDR;

	data = (void *)(long)d->ctx->data;
	data_end = (void *)(long)d->ctx->data_end;

	/* then write encap headers */
	iph = data + d->pl_off;
	udph = (struct udphdr *)(iph + 1);
	gtph = (struct gtphdr *)(udph + 1);
	if (d->pl_off > 256 || (void *)(gtph + 1) > data_end)
		return XDP_PASS;

	pkt_len = data_end - data - d->pl_off;
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = IPPROTO_UDP;
	iph->tos = 0;
	iph->tot_len = bpf_htons(pkt_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->check = 0;
	iph->saddr = 0;		/* filled by fib_lookup() */
	iph->daddr = u->gtpu_remote_addr;
	csum_ipv4(iph, sizeof(*iph), &csum);
	iph->check = csum;

	pkt_len -= sizeof(*iph);
	udph->source = bpf_htons(GTPU_PORT);
	udph->dest = u->gtpu_remote_port;
	udph->len = bpf_htons(pkt_len);
	udph->check = 0;	/* hardware checksum feature, save us! */

	pkt_len -= sizeof(*udph) + sizeof(*gtph);
	gtph->flags = GTPU_FLAGS;
	gtph->type = GTPU_TPDU;
	gtph->length = bpf_htons(pkt_len);
	gtph->teid = u->teid;

	d->dst_addr = u->gtpu_remote_addr;

	/* metrics */
	++u->packets;
	u->bytes += pkt_len;

	return XDP_IFR_FORWARD;
}


/*
 *	Egress direction (UE pov), traffic from GTP-U endpoint
 */
static __always_inline int
upf_handle_gtpu(struct if_rule_data *d)
{
	void *data = (void *)(long)d->ctx->data;
	void *data_end = (void *)(long)d->ctx->data_end;
	struct upf_user_egress_key k;
	struct upf_user_egress *u;
	struct iphdr *iph, *iph_inner;
	struct udphdr *udph;
	struct gtphdr *gtph;
	int adjust_sz, payload_len;

	/* check input gtp-u (proto udp and port) */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udph = (void *)(iph) + iph->ihl * 4;
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_PASS;

	gtph = (struct gtphdr *)(udph + 1);
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* only handle gtp-u data packet */
	if (gtph->type != 0xff)
		return XDP_PASS;

	/* lookup user */
	k.teid = gtph->teid;
	k.gtpu_remote_addr = iph->saddr;
	k.gtpu_remote_port = udph->source;
	u = bpf_map_lookup_elem(&user_egress, &k);
	if (u == NULL)
		return XDP_PASS;

	/* for futur nh lookup */
	iph_inner = (struct iphdr *)(gtph + 1);
	if (iph_inner + 1 > data_end)
		return XDP_DROP;
	d->dst_addr = iph_inner->daddr;

	adjust_sz = (void *)(gtph + 1) - (void *)iph;
	payload_len = data_end - data - d->pl_off - adjust_sz;

	/* now decap gtp-u */
	if (bpf_xdp_adjust_head(d->ctx, adjust_sz) < 0)
		return XDP_ABORTED;
	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	/* metrics */
	++u->packets;
	u->bytes += payload_len;

	return XDP_IFR_FORWARD;
}
