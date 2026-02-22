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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#define KBUILD_MODNAME "gtp_route"
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
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
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
	__type(key, struct ip_rt_key);			/* ipaddr + tunnelid */
	__type(value, struct gtp_rt_rule);		/* GTP Encapsulation Rule */
} teid_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000000);
	__type(key, struct ppp_key);			/* hw + sessionid */
	__type(value, struct gtp_rt_rule);		/* GTP Encapsulation Rule */
} ppp_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_IPTNL_ENTRIES);
	__type(key, __be32);
	__type(value, struct gtp_iptnl_rule);
} iptnl_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8);
	__type(key, __u32);				/* ifindex */
	__type(value, struct ll_addr);
} if_lladdr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 32);
	__type(key, struct metrics_key);		/* ifindex + type + dir */
	__type(value, struct metrics);
} if_stats SEC(".maps");


/*
 *	Statistics
 */
static __always_inline void
gtp_rt_rule_stats_update(struct gtp_rt_rule *rule, int bytes)
{
	rule->packets++;
	rule->bytes += bytes;
}

static __always_inline int
if_metrics_update(int action, __u32 ifindex, __u8 type, __u8 direction, int bytes)
{
	struct metrics *metrics;
	struct metrics_key m_k;

	m_k.ifindex = ifindex;
	m_k.type = type;
	m_k.direction = direction;

	metrics = bpf_map_lookup_elem(&if_stats, &m_k);
	if (!metrics)
		return -1;

	switch (action) {
	case XDP_PASS:
	case XDP_TX:
	case XDP_REDIRECT:
		metrics->packets++;
		metrics->bytes += bytes;
		break;
	default:
		metrics->dropped_packets++;
		metrics->dropped_bytes += bytes;
	}
	return 0;
}


/*
 *	Checksum
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
gtp_route_fib_lookup(struct xdp_md *ctx, struct ethhdr *ethh, struct iphdr *iph,
		     struct bpf_fib_lookup *fib_params)
{
	int ret;

	fib_params->ifindex	= ctx->ingress_ifindex;
	fib_params->family	= AF_INET;
	fib_params->ipv4_src	= iph->saddr;
	fib_params->ipv4_dst	= iph->daddr;
	ret = bpf_fib_lookup(ctx, fib_params, sizeof(*fib_params)
				, BPF_FIB_LOOKUP_DIRECT);

	/* Keep in mind that forwarding need to be enabled
	 * on interface we may need to redirect traffic to/from
	 */
	if (ret != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_DROP;

	/* Ethernet playground */
	__builtin_memcpy(ethh->h_dest, fib_params->dmac, ETH_ALEN);
	__builtin_memcpy(ethh->h_source, fib_params->smac, ETH_ALEN);

	if (ctx->ingress_ifindex != fib_params->ifindex)
		return bpf_redirect(fib_params->ifindex, 0);

	return XDP_TX;
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
	int nbytes = data_end - data;
	struct bpf_fib_lookup fib_params;
	struct gtp_iptnl_rule *iptnl_rule;
	struct ethhdr *new_eth;
	struct _vlan_hdr *vlanh = NULL;
	struct iphdr *iph, *iph_inner;
	int offset = sizeof(struct ethhdr);
	int headroom = sizeof(struct udphdr) + sizeof(struct gtphdr);
	__u16 payload_len;
	__u32 csum = 0;
	int ret;

	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &rt_rule->dst_key);
	if (!iptnl_rule)
		return XDP_PASS;

	/* Phase 0 : shrink headroom, recycle iphdr for encap */
	if (!(iptnl_rule->flags & IPTNL_FL_TAG_VLAN) && pkt->vlan_id != 0)
		headroom += sizeof(struct _vlan_hdr);

	if ((iptnl_rule->flags & IPTNL_FL_TAG_VLAN) && pkt->vlan_id == 0)
		headroom -= sizeof(struct _vlan_hdr);

	/* Phase 1 : decap GTP-U */
	if (bpf_xdp_adjust_head(ctx, headroom)) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	/* Phase 2 : IPIP Encapsulation */
	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;

	new_eth = data;
	if (new_eth + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	new_eth->h_proto = bpf_htons(ETH_P_IP);

	if (iptnl_rule->flags & IPTNL_FL_TAG_VLAN) {
		new_eth->h_proto = bpf_htons(ETH_P_8021Q);
		vlanh = data + offset;
		if (vlanh + 1 > data_end) {
			if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
					  IF_METRICS_GTP, IF_DIRECTION_RX,
					  nbytes);
			return XDP_DROP;
		}
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
		vlanh->hvlan_TCI = bpf_htons(iptnl_rule->encap_vlan_id);
		offset += sizeof(struct _vlan_hdr);
	}

	/* IPIP Encapsulation header */
	iph = data + offset;
	if (iph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	offset += sizeof(struct iphdr);
	iph_inner = data + offset;
	if (iph_inner + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	payload_len = bpf_ntohs(iph_inner->tot_len);

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

	/* Statistics */
	gtp_rt_rule_stats_update(rt_rule, data_end - data);
	if_metrics_update(XDP_PASS, ctx->ingress_ifindex, IF_METRICS_GTP, IF_DIRECTION_RX,
			  nbytes);

	/* We need to perform a fib lookup to resolv {s,d}mac properly
	 * and not re-invent the wheel by storing it locally in ruleset
	 */
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	ret = gtp_route_fib_lookup(ctx, new_eth, iph, &fib_params);
	if_metrics_update(ret, fib_params.ifindex,
			  IF_METRICS_IPIP, IF_DIRECTION_TX,
			  data_end - data);
	return ret;
}

static __always_inline int
gtp_route_ipip_decap(struct parse_pkt *pkt)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	int nbytes = data_end - data;
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
	int headroom, use_vlan = 0, ret;
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
	rt_key.id = iph_outer->daddr;
	rt_key.addr = iph_inner->daddr;

	rt_rule = bpf_map_lookup_elem(&teid_ingress, &rt_key);
	if (!rt_rule)
		return XDP_PASS;

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
	if (bpf_xdp_adjust_head(ctx, 0 - headroom)) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_IPIP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	new_eth = data;
	if (new_eth + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_IPIP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	offset = sizeof(struct ethhdr);
	new_eth->h_proto = bpf_htons(ETH_P_IP);
	if (use_vlan) {
		new_eth->h_proto = bpf_htons(ETH_P_8021Q);

		vlanh = data + sizeof(*new_eth);
		if (vlanh + 1 > data_end) {
			if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
					  IF_METRICS_IPIP, IF_DIRECTION_RX,
					  nbytes);
			return XDP_DROP;
		}
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
		vlanh->hvlan_TCI = bpf_htons(iptnl_rule->decap_vlan_id);
		offset += sizeof(*vlanh);
	}

	/* Build GTP-U IP Header */
	iph = data + offset;
	if (iph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_IPIP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
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
	if (udph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_IPIP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	udph->dest = bpf_htons(GTPU_PORT);
	udph->source= bpf_htons(65000);
	udph->len = bpf_htons(payload_len + sizeof(*udph) + sizeof(*gtph));
	udph->check = 0;

	offset += sizeof(*udph);

	/* Build GTP-U GTP Header */
	gtph = data + offset;
	if (gtph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_IPIP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	gtph->flags = GTPU_FLAGS;		/* GTP Release 99 + GTP */
	gtph->type = GTPU_TPDU;
	gtph->teid = rt_rule->teid;
	gtph->length = bpf_htons(payload_len);	/* gtph not part of it !? */

	/* Statistics */
	gtp_rt_rule_stats_update(rt_rule, data_end - data);
	if_metrics_update(XDP_PASS, ctx->ingress_ifindex, IF_METRICS_IPIP, IF_DIRECTION_RX,
			  nbytes);

	/* We need to perform a fib lookup to resolv {s,d}mac properly
	 * and not re-invent the wheel by storing it locally in ruleset
	 */
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	ret = gtp_route_fib_lookup(ctx, new_eth, iph, &fib_params);
	if_metrics_update(ret, fib_params.ifindex,
			  IF_METRICS_GTP, IF_DIRECTION_TX,
			  data_end - data);
	return ret;
}


/*
 *	PPPoE
 */
static __always_inline int
gtp_route_ppp_encap(struct parse_pkt *pkt, struct gtp_rt_rule *rt_rule, __u16 length)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	int nbytes = data_end - data;
	struct ethhdr *ethh;
	struct _vlan_hdr *vlanh = NULL;
	struct pppoehdr *pppoeh;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	int offset = sizeof(struct ethhdr);
	__u16 *ppph;
	int headroom, payload_len;

	ethh = data;
	if (ethh + 1 > data_end)
		return XDP_PASS;

	/* Phase 0 : Build payload len */
	payload_len = length + 2;

	/* Phase 1 : shrink headroom */
	headroom = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtphdr);

	if (pkt->vlan_id == 0 && rt_rule->vlan_id != 0)
		headroom -= sizeof(struct _vlan_hdr);
	if (pkt->vlan_id != 0 && rt_rule->vlan_id == 0)
		headroom += sizeof(struct _vlan_hdr);
	headroom -= sizeof(struct pppoehdr) + 2;

	/* Phase 2 : GTP-U decap */
	if (bpf_xdp_adjust_head(ctx, headroom)) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;

	/* Phase 3 : Layer2 */
	ethh = data;
	if (ethh + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	__builtin_memcpy(ethh->h_dest, rt_rule->h_dst, ETH_ALEN);
	__builtin_memcpy(ethh->h_source, rt_rule->h_src, ETH_ALEN);
	ethh->h_proto = bpf_htons(ETH_P_PPP_SES);

	if (rt_rule->vlan_id != 0) {
		ethh->h_proto = bpf_htons(ETH_P_8021Q);
		vlanh = data + offset;
		if (vlanh + 1 > data_end) {
			if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
					  IF_METRICS_GTP, IF_DIRECTION_RX,
					  nbytes);
			return XDP_DROP;
		}
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_PPP_SES);
		vlanh->hvlan_TCI = bpf_htons(rt_rule->vlan_id);
		offset += sizeof(struct _vlan_hdr);
	}

	/* Phase 4 : PPPoE */
	pppoeh = data + offset;
	if (pppoeh + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	pppoeh->vertype = PPPOE_VERTYPE;
	pppoeh->code = PPPOE_CODE_SESSION;
	pppoeh->session = bpf_htons(rt_rule->session_id);
	offset += sizeof(struct pppoehdr);

	/* Phase 5 : PPP */
	ppph = data + offset;
	if (ppph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	offset += 2;

	/* Phase 6 : Complete PPPoE & PPP header according to L3 */
	iph = data + offset;
	if (iph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	if (iph->version == 4) {
		*ppph = bpf_htons(PPP_IP);
	} else if (iph->version == 6) {
		*ppph = bpf_htons(PPP_IPV6);
		ipv6h = data + offset;
		if (ipv6h + 1 > data_end) {
			if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
					  IF_METRICS_GTP, IF_DIRECTION_RX,
					  nbytes);
			return XDP_DROP;
		}
	} else {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP; /* only IPv4 & IPv6 */
	}

	pppoeh->plen = bpf_htons(payload_len);

	/* Statistics */
	gtp_rt_rule_stats_update(rt_rule, data_end - data);
	if_metrics_update(XDP_PASS, ctx->ingress_ifindex, IF_METRICS_GTP, IF_DIRECTION_RX,
			  nbytes);

	if (rt_rule->flags & GTP_RT_FL_DIRECT_TX) {
		if_metrics_update(XDP_TX, ctx->ingress_ifindex,
				  IF_METRICS_PPPOE, IF_DIRECTION_TX,
				  data_end - data);
		return XDP_TX;
	}

	if (ctx->ingress_ifindex != rt_rule->ifindex) {
		if_metrics_update(XDP_REDIRECT, rt_rule->ifindex,
				  IF_METRICS_PPPOE, IF_DIRECTION_TX,
				  data_end - data);
		return bpf_redirect(rt_rule->ifindex, 0);
	}

	if_metrics_update(XDP_TX, ctx->ingress_ifindex,
			  IF_METRICS_PPPOE, IF_DIRECTION_TX,
			  data_end - data);
	return XDP_TX;
}

static __always_inline int
gtp_route_ppp_decap(struct parse_pkt *pkt)
{
	struct xdp_md *ctx = pkt->ctx;
	__u32 key = ctx->ingress_ifindex;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	int nbytes = data_end - data;
	struct bpf_fib_lookup fib_params;
	struct gtp_rt_rule *rt_rule;
	struct ppp_key ppp_k;
	int offset = pkt->l3_offset;
	struct _vlan_hdr *vlanh = NULL;
	struct ethhdr *ethh;
	struct ll_addr *ll;
	struct pppoehdr *pppoeh;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph;
	__u16 *ppph;
	__u16 payload_len;
	__u32 csum = 0;
	int headroom, ret;

	ethh = data;
	if (ethh + 1 > data_end)
		return XDP_PASS;

	pppoeh = data + offset;
	if (pppoeh + 1 > data_end)
		return XDP_PASS;
	payload_len = bpf_ntohs(pppoeh->plen) - 2;
	offset += sizeof(*pppoeh);

	ppph = data + offset;
	if (ppph + 1 > data_end)
		return XDP_PASS;

	/* Only handle IPv4 and IPv6. Punt Control Protocol */
	if (*ppph != bpf_htons(PPP_IP) && *ppph != bpf_htons(PPP_IPV6))
		return XDP_PASS;

	/* Ingress lookup */
	__builtin_memcpy(ppp_k.hw, ethh->h_dest, ETH_ALEN);
	ppp_k.session_id = bpf_ntohs(pppoeh->session);

	/* If no session is matching then we drop to prevent against
	 * userland overflow while restarting. Only PPP-LCP are punt
	 * to the userland. */
	rt_rule = bpf_map_lookup_elem(&ppp_ingress, &ppp_k);
	if (!rt_rule) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_PPPOE, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	/* Phase 0 : Got it ! perform GTP-U encapsulation, prepare headroom */
	headroom = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtphdr);
	headroom -= sizeof(struct pppoehdr) + 2;
	if (pkt->vlan_id != 0 && rt_rule->vlan_id == 0)
		headroom -= sizeof(struct _vlan_hdr);
	else if (pkt->vlan_id == 0 && rt_rule->vlan_id != 0)
		headroom += sizeof(struct _vlan_hdr);
	if (bpf_xdp_adjust_head(ctx, 0 - headroom)) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_PPPOE, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}

	/* Phase 1 : Layer2 */
	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	ethh = data;
	if (ethh + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_PPPOE, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	offset = sizeof(*ethh);
	ethh->h_proto = bpf_htons(ETH_P_IP);
	if (rt_rule->vlan_id != 0) {
		ethh->h_proto = bpf_htons(ETH_P_8021Q);

		vlanh = data + offset;
		if (vlanh + 1 > data_end) {
			if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
					  IF_METRICS_PPPOE, IF_DIRECTION_RX,
					  nbytes);
			return XDP_DROP;
		}
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
		vlanh->hvlan_TCI = bpf_htons(rt_rule->vlan_id);
		offset += sizeof(*vlanh);
	}

	/* Phase 2 : Layer3 */
	iph = data + offset;
	if (iph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_PPPOE, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
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

	/* Phase 3 : Layer4 */
	udph = data + offset;
	if (udph + 1 > data_end) {
		if_metrics_update(XDP_DROP, ctx->ingress_ifindex,
				  IF_METRICS_PPPOE, IF_DIRECTION_RX,
				  nbytes);
		return XDP_DROP;
	}
	udph->source = bpf_htons(GTPU_PORT);
	udph->dest = bpf_htons(GTPU_PORT);
	udph->len = bpf_htons(payload_len + sizeof(*udph) + sizeof(*gtph));
	udph->check = 0;

	/* For diversification and efficiency some sGW implementation
	 * require src port diversification. To keep it state-less
	 * we are setting src_port transitively learnt from first
	 * packet originated from remote sGW */
	if (rt_rule->gtp_udp_port != 0)
		udph->source = rt_rule->gtp_udp_port;

	offset += sizeof(*udph);

	/* Phase 4 : GTP-U  */
	gtph = data + offset;
	if (gtph + 1 > data_end)
		return XDP_DROP;
	gtph->flags = GTPU_FLAGS;		/* GTP Release 99 + GTP */
	gtph->type = GTPU_TPDU;
	gtph->teid = rt_rule->teid;
	gtph->length = bpf_htons(payload_len);

	/* Statistics */
	gtp_rt_rule_stats_update(rt_rule, data_end - data);
	if_metrics_update(XDP_PASS, ctx->ingress_ifindex, IF_METRICS_PPPOE, IF_DIRECTION_RX,
			  nbytes);

	/* In direct-tx mode we are using pre-configured lladdr */
	if (rt_rule->flags & GTP_RT_FL_DIRECT_TX) {
		ll = bpf_map_lookup_elem(&if_lladdr, &key);
		if (ll) {
			__builtin_memcpy(ethh->h_dest, ll->remote, ETH_ALEN);
			__builtin_memcpy(ethh->h_source, ll->local, ETH_ALEN);

			/* TODO: for perfs, try to avoid this 2nd lookup */
			if_metrics_update(XDP_TX, ctx->ingress_ifindex,
					  IF_METRICS_GTP, IF_DIRECTION_TX,
					  data_end - data);
			return XDP_TX;
		}
	}

	/* We need to perform a fib lookup to resolv {s,d}mac properly
	 * and not re-invent the wheel by storing it locally in ruleset
	 */
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	ret = gtp_route_fib_lookup(ctx, ethh, iph, &fib_params);
	if_metrics_update(ret, fib_params.ifindex,
			  IF_METRICS_GTP, IF_DIRECTION_TX,
			  data_end - data);
	return ret;
}

/*
 *	GTP-ROUTE rules handling
 */
static int
gtp_rt_rule_update_ingress(__u32 index, struct rt_percpu_ctx *ctx)
{
	struct gtp_rt_rule *rt_rule;
	struct ppp_key ppp_k;

	/* Update ingress */
	__builtin_memcpy(ppp_k.hw, ctx->hw, ETH_ALEN);
	ppp_k.session_id = ctx->session_id;

	rt_rule = bpf_map_lookup_percpu_elem(&ppp_ingress, &ppp_k, index);
	if (!rt_rule)
		return 0;

	rt_rule->gtp_udp_port = ctx->dst_port;
	return 0;
}

static int
gtp_rt_rule_update_egress(__u32 index, struct rt_percpu_ctx *ctx)
{
	struct gtp_rt_rule *rt_rule;
	struct ip_rt_key rt_k;

	/* Update egress */
	rt_k.addr = ctx->addr;
	rt_k.id = ctx->id;

	rt_rule = bpf_map_lookup_percpu_elem(&teid_egress, &rt_k, index);
	if (!rt_rule)
		return 0;

	rt_rule->gtp_udp_port = ctx->dst_port;
	return 0;
}

static __always_inline int
gtp_rt_rule_dst_port_update(struct gtp_rt_rule *rt_rule, __u16 port)
{
	struct rt_percpu_ctx ctx;

	/* Prepare update context */
	__builtin_memset(&ctx, 0, sizeof(struct rt_percpu_ctx));
	__builtin_memcpy(ctx.hw, rt_rule->h_src, ETH_ALEN);
	ctx.session_id = rt_rule->session_id;
	ctx.id = rt_rule->teid;
	ctx.addr = rt_rule->saddr;
	ctx.dst_port = port;

	bpf_loop(nr_cpus, gtp_rt_rule_update_ingress, &ctx, 0);
	bpf_loop(nr_cpus, gtp_rt_rule_update_egress, &ctx, 0);
	return 0;
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

	if (pkt->l3_proto == ETH_P_PPP_SES)
		return gtp_route_ppp_decap(pkt);

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
	rt_key.id = gtph->teid;
	rt_key.addr = iph->daddr;

	/* If no session is matching then we drop to prevent against
	 * userland overflow while restarting. Only GTP-U bound to an
	 * existing session are kept into account. */
	rule = bpf_map_lookup_elem(&teid_egress, &rt_key);
	if (!rule) {
		if_metrics_update(XDP_DROP, pkt->ctx->ingress_ifindex,
				  IF_METRICS_GTP, IF_DIRECTION_RX,
				  data_end - data);
		return XDP_DROP;
	}

	/* remote GTP-U udp port learning */
	if (rule->flags & GTP_RT_FL_UDP_LEARNING && rule->gtp_udp_port == 0)
		gtp_rt_rule_dst_port_update(rule, udph->source);

	if (rule->flags & GTP_RT_FL_PPPOE)
		return gtp_route_ppp_encap(pkt, rule, bpf_ntohs(gtph->length));

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

const char _mode[] = "gtp_route";
char _license[] SEC("license") = "GPL";
