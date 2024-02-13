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

#define KBUILD_MODNAME "gtp_fwd"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <uapi/linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include "gtp_bpf_utils.h"
#include "gtp.h"

/*
 *	MAPs
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000000);
	__type(key, struct ip_rt_key);			/* TEID */
	__type(value, struct gtp_rt_rule);		/* GTP Encapsulation Rule */
} teid_egress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000000);
	__type(key, struct ip_rt_key);			/* TEID */
	__type(value, struct gtp_rt_rule);		/* GTP Encapsulation Rule */
} ppp_egress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000000);
	__type(key, struct ip_rt_key);			/* ipaddr + tunnelid */
	__type(value, struct gtp_rt_rule);		/* GTP Encapsulation Rule */
} teid_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000000);
	__type(key, struct ip_ppp_key);			/* hw + sessionid */
	__type(value, struct gtp_rt_rule);		/* GTP Encapsulation Rule */
} ppp_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_IPTNL_ENTRIES);
	__type(key, __be32);
	__type(value, struct gtp_iptnl_rule);
} iptnl_info SEC(".maps");


/*
 *	Checksum related
 */
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum>>16) + (csum & 0xffff);
	sum += (sum>>16);
	return ~sum;
}

static __always_inline void ipv4_csum(void *data_start, int data_size, __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}


/*
 *	FIB Lookup
 */
static __always_inline int
gtp_route_fib_lookup(struct xdp_md *ctx, struct ethhdr *ethh, struct iphdr *iph, struct bpf_fib_lookup *fib_params)
{
	int ret;

	fib_params->family	= AF_INET;
	fib_params->ipv4_src	= iph->saddr;
	fib_params->ipv4_dst	= iph->daddr;
	ret = bpf_fib_lookup(ctx, fib_params, sizeof(*fib_params), 0);

	/* Keep in mind that forwarding need to be enabled
	 * on interface we may need to redirect traffic to/from
	 */
	if (ret != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_DROP;

	/* Ethernet playground */
	__builtin_memcpy(ethh->h_dest, fib_params->dmac, ETH_ALEN);
	__builtin_memcpy(ethh->h_source, fib_params->smac, ETH_ALEN);

//	return bpf_redirect(fib_params->ifindex, 0);
	return XDP_TX;
}

/*
 *	Stats
 */
static __always_inline void
gtp_route_stats_update(struct gtp_rt_rule *rule, struct iphdr *iph)
{
	rule->packets++;
	rule->bytes += bpf_ntohs(iph->tot_len);
}

/*
 *	IPIP
 */
static __always_inline int
gtp_route_ipip_encap(struct parse_pkt *pkt, struct gtp_rt_rule *rt_rule)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct bpf_fib_lookup fib_params;
	struct gtp_iptnl_rule *iptnl_rule;
	struct ethhdr *new_eth;
	struct _vlan_hdr *vlanh = NULL;
	struct iphdr *iph, *iph_inner;
	int offset = sizeof(struct ethhdr);
	int headroom = sizeof(struct udphdr) + sizeof(struct gtphdr);
	__u16 payload_len;
	__u32 csum = 0;

	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &rt_rule->dst_key);
	if (!iptnl_rule)
		return XDP_PASS;

	/* Phase 0 : shrink headroom, recycle iphdr for encap */
	if (!(iptnl_rule->flags & IPTNL_FL_TAG_VLAN) && pkt->vlan_id != 0)
		headroom += sizeof(struct _vlan_hdr);

	if ((iptnl_rule->flags & IPTNL_FL_TAG_VLAN) && pkt->vlan_id == 0)
		headroom -= sizeof(struct _vlan_hdr);

	/* Phase 1 : decap GTP-U */
	if (bpf_xdp_adjust_head(ctx, headroom))
		return XDP_DROP;

	/* Phase 2 : IPIP Encapsulation */
	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;

	new_eth = data;
	if (new_eth + 1 > data_end)
		return XDP_DROP;
	new_eth->h_proto = bpf_htons(ETH_P_IP);

	if (iptnl_rule->flags & IPTNL_FL_TAG_VLAN) {
		new_eth->h_proto = bpf_htons(ETH_P_8021Q);
		vlanh = data + offset;
		if (vlanh + 1 > data_end)
			return XDP_DROP;
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
		vlanh->hvlan_TCI = bpf_htons(iptnl_rule->encap_vlan_id);
		offset += sizeof(struct _vlan_hdr);
	}

	/* IPIP Encapsulation header */
	iph = data + offset;
	if (iph + 1 > data_end)
		return XDP_DROP;

	offset += sizeof(struct iphdr);
	iph_inner = data + offset;
	if (iph_inner + 1 > data_end)
		return XDP_DROP;
	payload_len = bpf_ntohs(iph_inner->tot_len);
	gtp_route_stats_update(rt_rule, iph_inner);

	iph->version = 4;
	iph->ihl = sizeof(*iph) >> 2;
	iph->frag_off =	0;
	iph->protocol = IPPROTO_IPIP;
	iph->check = 0;
	iph->tos = 0;
	iph->tot_len = bpf_htons(payload_len + sizeof(*iph));
	iph->saddr = iptnl_rule->local_addr;
	iph->daddr = iptnl_rule->remote_addr;
	iph->ttl = 64;
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;

	/* We need to perform a fib lookup to resolv {s,d}mac properly
	 * and not re-invent the wheel by storing it locally in ruleset
	 */
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.ifindex = ctx->ingress_ifindex;
	return gtp_route_fib_lookup(ctx, new_eth, iph, &fib_params);
}

static __always_inline int
gtp_route_ipip_decap(struct parse_pkt *pkt)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct bpf_fib_lookup fib_params;
	struct gtp_iptnl_rule *iptnl_rule;
	struct gtp_rt_rule *rt_rule = NULL;
	struct ip_rt_key rt_key;
	struct ethhdr *new_eth;
	struct _vlan_hdr *vlanh = NULL;
	struct iphdr *iph_outer, *iph_inner, *iph;
	struct udphdr *udph;
	struct gtphdr *gtph;
	int offset = pkt->l3_offset;
	int headroom, use_vlan = 0;
	__u16 payload_len;
	__u32 csum = 0;

	iph_outer = data + offset;
	if (iph_outer + 1 > data_end)
		return XDP_PASS;

	offset += sizeof(struct iphdr);
	iph_inner = data + offset;
	if (iph_inner + 1 > data_end)
		return XDP_PASS;
	payload_len = bpf_ntohs(iph_inner->tot_len);

	/* Ingress lookup */
	__builtin_memset(&rt_key, 0, sizeof(struct ip_rt_key));
	rt_key.id = iph_outer->daddr;
	rt_key.addr = iph_inner->daddr;

	rt_rule = bpf_map_lookup_elem(&teid_ingress, &rt_key);
	if (!rt_rule)
		return XDP_PASS;
	gtp_route_stats_update(rt_rule, iph_inner);

	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &rt_rule->dst_key);
	if (!iptnl_rule)
		return XDP_PASS;

	/* Got it ! perform GTP-U encapsulation, recycle IPIP iph
	 * Prepare headroom.
	 */
	headroom = sizeof(struct udphdr) + sizeof(struct gtphdr);
	if (pkt->vlan_id != 0 && iptnl_rule->decap_vlan_id != 0) {
		use_vlan = 1;
	} else if (pkt->vlan_id == 0 && iptnl_rule->decap_vlan_id != 0) {
		use_vlan = 1;
		headroom += sizeof(struct _vlan_hdr);
	}
	if (bpf_xdp_adjust_head(ctx, 0 - headroom))
		return XDP_DROP;

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	new_eth = data;
	if (new_eth + 1 > data_end)
		return XDP_DROP;

	offset = sizeof(struct ethhdr);
	new_eth->h_proto = bpf_htons(ETH_P_IP);
	if (use_vlan) {
		new_eth->h_proto = bpf_htons(ETH_P_8021Q);

		vlanh = data + sizeof(*new_eth);
		if (vlanh + 1 > data_end)
			return XDP_DROP;
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
		vlanh->hvlan_TCI = bpf_htons(iptnl_rule->decap_vlan_id);
		offset += sizeof(*vlanh);
	}

	/* Build GTP-U IP Header */
	iph = data + offset;
	if (iph + 1 > data_end)
		return XDP_DROP;
	iph->version = 4;
	iph->ihl = sizeof(*iph) >> 2;
	iph->frag_off =	0;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->tos = 0;
	iph->tot_len = bpf_htons(payload_len + sizeof(*iph) + sizeof(*udph) + sizeof(*gtph));
	iph->saddr = rt_rule->saddr;
	iph->daddr = rt_rule->daddr;
	iph->ttl = 64;
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;

	offset += sizeof(*iph);

	/* Build GTP-U UDP Header */
	udph = data + offset;
	if (udph + 1 > data_end)
		return XDP_DROP;
	udph->dest = bpf_htons(GTPU_PORT);
	udph->source= bpf_htons(65000);
	udph->len = bpf_htons(payload_len + sizeof(*udph) + sizeof(*gtph));
	udph->check = 0;

	offset += sizeof(*udph);

	/* Build GTP-U GTP Header */
	gtph = data + offset;
	if (gtph + 1 > data_end)
		return XDP_DROP;
	gtph->flags = GTPU_FLAGS;		/* GTP Release 99 + GTP */
	gtph->type = GTPU_TPDU;
	gtph->teid = rt_rule->teid;
	gtph->length = bpf_htons(payload_len);	/* gtph not part of it !? */

	/* We need to perform a fib lookup to resolv {s,d}mac properly
	 * and not re-invent the wheel by storing it locally in ruleset
	 */
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.ifindex = ctx->ingress_ifindex;
	return gtp_route_fib_lookup(ctx, new_eth, iph, &fib_params);
}

/*
 *	GTP-ROUTE traffic selector
 */
static __always_inline int
gtp_route_traffic_selector(struct parse_pkt *pkt)
{
	void *data_end = (void *) (long) pkt->ctx->data_end;
	void *data = (void *) (long) pkt->ctx->data;
	struct gtp_rt_rule *rule = NULL;
	struct ip_rt_key rt_key;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = 0;

	iph = data + pkt->l3_offset;
	if (iph + 1 > data_end)
		return XDP_PASS;

	if (iph->protocol == IPPROTO_IPIP)
		return gtp_route_ipip_decap(pkt);

	offset += pkt->l3_offset;
	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udph = data + offset + sizeof(struct iphdr);
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_PASS;

	offset += sizeof(struct iphdr);
	gtph = data + offset + sizeof(struct udphdr);
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* UDP Traffic to GTP-U UDP port : Egress lookup */
	__builtin_memset(&rt_key, 0, sizeof(struct ip_rt_key));
	rt_key.id = gtph->teid;
	rt_key.addr = iph->daddr;

	rule = bpf_map_lookup_elem(&teid_egress, &rt_key);
	if (!rule)
		return XDP_PASS;

	if (rule->flags & GTP_RT_FL_IPIP)
		return gtp_route_ipip_encap(pkt, rule);

	return XDP_PASS;
}


/* Ethernet frame parsing and sanitize */
static __always_inline bool
parse_eth_frame(struct parse_pkt *pkt)
{
	void *data_end = (void *) (long) pkt->ctx->data_end;
	void *data = (void *) (long) pkt->ctx->data;
	struct _vlan_hdr *vlan_hdr;
	struct ethhdr *eth = data;
	__u16 eth_type, vlan = 0;
	__u8 offset;

	offset = sizeof(*eth);

	/* Make sure packet is large enough for parsing eth */
	if ((void *) eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

	/* Handle outer VLAN tag */
	if (eth_type == bpf_htons(ETH_P_8021Q) ||
	    eth_type == bpf_htons(ETH_P_8021AD)) {
		vlan_hdr = (void *) eth + offset;
		vlan = bpf_ntohs(vlan_hdr->hvlan_TCI);
		pkt->vlan_id = vlan & 0x0fff;
		offset += sizeof (*vlan_hdr);
		if ((void *) eth + offset > data_end)
			return false;

		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
		vlan_hdr->hvlan_TCI = bpf_htons(pkt->vlan_id);
	}

	pkt->l3_proto = bpf_ntohs(eth_type);
	pkt->l3_offset = offset;
	return true;
}

SEC("xdp")
int xdp_route(struct xdp_md *ctx)
{
	struct parse_pkt pkt = { .ctx = ctx,
				 .vlan_id = 0,
				 .l3_proto = 0,
				 .l3_offset = 0
			       };

	if (!parse_eth_frame(&pkt))
		return XDP_PASS;

	return gtp_route_traffic_selector(&pkt);
}

char _license[] SEC("license") = "GPL";
