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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
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
	__uint(max_entries, 1000000);
	__type(key, __be32);				/* Virtual TEID */
	__type(value, struct gtp_teid_rule);		/* Rewrite GTP Rulez */
} teid_xlat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000000);
	__type(key, struct ip_frag_key);		/* saddr + daddr + id + protocol */
	__type(value, struct gtp_teid_frag);		/* dst_addr linked */
} ip_frag SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_IPTNL_ENTRIES);
	__type(key, __be32);
	__type(value, struct gtp_iptnl_rule);
} iptnl_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 16);
	__type(key, __u32);				/* ifindex */
	__type(value, struct ll_attr);			/* if attributes */
} if_llattr SEC(".maps");


/* Packet rewrite */
static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];
	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

#if 0
static __always_inline void
set_ethhdr(struct ethhdr *new_eth, const struct ethhdr *old_eth, __be16 h_proto)
{
	__builtin_memcpy(new_eth->h_source, old_eth->h_dest, ETH_ALEN);
	__builtin_memcpy(new_eth->h_dest, old_eth->h_source, ETH_ALEN);
	new_eth->h_proto = h_proto;
}
#endif

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

static __always_inline int
gtpu_fib_lookup(struct xdp_md *ctx, struct ethhdr *ethh, struct _vlan_hdr *vlanh,
		struct iphdr *iph, struct bpf_fib_lookup *fib_params)
{
	struct ll_attr *attr;
	int ret;

	fib_params->family	= AF_INET;
	fib_params->l4_protocol	= IPPROTO_UDP;
	fib_params->tot_len	= bpf_ntohs(iph->tot_len);
	fib_params->ipv4_src	= iph->saddr;
	fib_params->ipv4_dst	= iph->daddr;
	ret = bpf_fib_lookup(ctx, fib_params, sizeof(*fib_params), 0);

	/* Keep in mind that forwarding need to be enabled
	 * on interface we may need to redirect traffic to/from
	 */
	if (ret != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_DROP;

	/* Ethernet */
//	ethh->h_proto = bpf_htons(ETH_P_IP);
	__builtin_memcpy(ethh->h_dest, fib_params->dmac, ETH_ALEN);
	__builtin_memcpy(ethh->h_source, fib_params->smac, ETH_ALEN);

	/* VLAN */
	if (!vlanh) {
		attr = bpf_map_lookup_elem(&if_llattr, &fib_params->ifindex);
		if (attr) {
			vlanh->hvlan_TCI = bpf_htons(attr->vlan_id);
		}
	}

//	return bpf_redirect(fib_params->ifindex, 0);
	return XDP_TX;
}

static __always_inline int
gtpu_ipip_encap(struct parse_pkt *pkt, struct gtp_iptnl_rule *iptnl_rule)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *new_eth;
	struct _vlan_hdr *vlanh;
	struct iphdr *iph;
	__u16 payload_len;
	__u32 csum = 0;
	int headroom, use_vlan = 0, offset = 0;

	iph = data + pkt->l3_offset;
	if (iph + 1 > data_end)
		return XDP_DROP;
	payload_len = bpf_ntohs(iph->tot_len);

	/* Prepare headroom */
	headroom = (int)sizeof(struct iphdr);
	if (pkt->vlan_id != 0 && iptnl_rule->encap_vlan_id != 0) {
		use_vlan = 1;
	} else if (pkt->vlan_id == 0 && iptnl_rule->encap_vlan_id != 0) {
		headroom += (int)sizeof(struct _vlan_hdr);
		use_vlan = 1;
	}
	if (bpf_xdp_adjust_head(ctx, 0 - headroom))
		return XDP_DROP;

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	new_eth = data;
	if (new_eth + 1 > data_end)
		return XDP_DROP;

	new_eth->h_proto = bpf_htons(ETH_P_IP);
	if (use_vlan) {
		new_eth->h_proto = bpf_htons(ETH_P_8021Q);

		vlanh = data + sizeof(*new_eth);
		if (vlanh + 1 > data_end)
			return XDP_DROP;
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
		vlanh->hvlan_TCI = bpf_htons(iptnl_rule->encap_vlan_id);
		offset = sizeof(*vlanh);
	}

	iph = data + sizeof(*new_eth) + offset;
	if (iph + 1 > data_end)
		return XDP_DROP;

	/* Fill Encap header */
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
	return gtpu_fib_lookup(ctx, new_eth, vlanh, iph, &fib_params);
}

static __always_inline void
gtpu_xlat_iph(struct iphdr *iph, __be32 daddr)
{
	__u32 csum = 0;

	/* Phase 1 : rewrite IP header */
	iph->saddr = iph->daddr;
	iph->daddr = daddr;
	--iph->ttl;
	iph->check = 0;
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;
}

static __always_inline void
gtpu_xlat_header(struct gtp_teid_rule *rule, struct iphdr *iph, struct gtphdr *gtph)
{
	/* Phase 1 : rewrite IP header */
	gtpu_xlat_iph(iph, rule->dst_addr);

	/* Phase 2 : we are into transparent mode
	 * so just forward ingress src port.
	 * in reverse path from egress to ingress
	 * dst_port is fixed to 2152 : horrible
	 * since can expect to reply to the original
	 * src_port... crappy
	 */

	/* Phase 3 : rewrite GTP */
	gtph->teid = rule->teid;

	/* Phase 4 : Stats counter update */
	rule->packets++;
	rule->bytes += bpf_ntohs(iph->tot_len);
}

static struct gtp_teid_frag *
gtpu_teid_frag_get(struct iphdr *iph, __u16 *frag_off, __u16 *ipfl)
{
	struct gtp_teid_frag *gtpf = NULL;
	struct ip_frag_key frag_key;

	*frag_off = bpf_ntohs(iph->frag_off);
	*ipfl = *frag_off & ~IP_OFFSET;
	*frag_off &= IP_OFFSET;
	*frag_off <<= 3;		/* 8-byte chunk */

	if (*frag_off != 0) {
		__builtin_memset(&frag_key, 0, sizeof(struct ip_frag_key));
		frag_key.saddr = iph->saddr;
		frag_key.daddr = iph->daddr;
		frag_key.id = iph->id;
		frag_key.protocol = iph->protocol;

		gtpf = bpf_map_lookup_elem(&ip_frag, &frag_key);
	}

	return gtpf;
}

static __always_inline int
gtpu_ipip_decap(struct parse_pkt *pkt, struct gtp_iptnl_rule *iptnl_rule, struct gtp_teid_frag *gtpf)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct bpf_fib_lookup fib_params;
	struct gtp_teid_rule *rule;
	struct ethhdr *new_eth;
	struct _vlan_hdr *vlanh = NULL;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = sizeof(struct ethhdr);
	int headroom = sizeof(struct iphdr);

	if (iptnl_rule->flags & IPTNL_FL_UNTAG_VLAN)
		headroom += sizeof(struct _vlan_hdr);

	/* shrink headroom */
	if (bpf_xdp_adjust_head(ctx, headroom))
		return XDP_DROP;

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;

	new_eth = data;
	if (new_eth + 1 > data_end)
		return XDP_DROP;

	new_eth->h_proto = bpf_htons(ETH_P_8021Q);
	if (iptnl_rule->flags & IPTNL_FL_UNTAG_VLAN) {
		new_eth->h_proto = bpf_htons(ETH_P_IP);
	}
	
	if ((iptnl_rule->flags & IPTNL_FL_TAG_VLAN) && pkt->vlan_id != 0) {
		vlanh = data + offset;
		if (vlanh + 1 > data_end)
			return XDP_DROP;
		vlanh->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
		vlanh->hvlan_TCI = bpf_htons(iptnl_rule->decap_vlan_id);
		offset += sizeof(struct _vlan_hdr);
	}

	iph = data + offset;
	if (iph + 1 > data_end)
		return XDP_DROP;

	/* Fragmentation handling */
	if (gtpf) {
		if (iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP)
			gtpu_xlat_iph(iph, gtpf->dst_addr);

		__builtin_memset(&fib_params, 0, sizeof(fib_params));
		fib_params.ifindex = ctx->ingress_ifindex;

		return gtpu_fib_lookup(ctx, new_eth, vlanh, iph, &fib_params);
	}

	offset += sizeof(struct iphdr);
	udph = data + offset;
	if (udph + 1 > data_end)
		return XDP_DROP;

	/* Perform xlat if needed */
	offset += sizeof(struct udphdr);
	gtph = data + offset;
	if (gtph + 1 > data_end)
		return XDP_DROP;

	if (iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP) {
		rule = bpf_map_lookup_elem(&teid_xlat, &gtph->teid);
		if (rule)
			gtpu_xlat_header(rule, iph, gtph);
	}

	/* We need to perform a fib lookup to resolv {s,d}mac properly
	 * and not re-invent the wheel by storing it locally in ruleset
	 */
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.ifindex = ctx->ingress_ifindex;

	return gtpu_fib_lookup(ctx, new_eth, vlanh, iph, &fib_params);
}

static __always_inline int
gtpu_ipip_traffic_selector(struct parse_pkt *pkt)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct gtp_iptnl_rule *iptnl_rule;
	struct gtp_teid_frag *gtpf = NULL;
	struct iphdr *iph_outer, *iph_inner;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = pkt->l3_offset;
	__u16 frag_off = 0, ipfl = 0;

	iph_outer = data + offset;
	if (iph_outer + 1 > data_end)
		return XDP_PASS;

	offset += sizeof(struct iphdr);
	iph_inner = data + offset;
	if (iph_inner + 1 > data_end)
		return XDP_PASS;

	/* A bit more complicated here since we need to
	 * deduce if it is ingress or egress
	 */
	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &iph_inner->daddr);
	if (!iptnl_rule) {
		iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &iph_inner->saddr);
		if (!iptnl_rule) {
			return XDP_PASS;
		}
	}

	/* sender is trusted ? */
	if (iph_outer->saddr != iptnl_rule->remote_addr)
		return XDP_DROP;

	/* Drop everything but UDP datagram */
	if (iph_inner->protocol != IPPROTO_UDP)
		return XDP_DROP;

	/* Fragmentation handling */
	if (iph_inner->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
		gtpf = gtpu_teid_frag_get(iph_inner, &frag_off, &ipfl);
		if (gtpf)
			return gtpu_ipip_decap(pkt, iptnl_rule, gtpf);
	}

	offset += sizeof(struct iphdr);
	udph = data + offset;
	if (udph + 1 > data_end)
		return XDP_DROP;

	/* Only allow GTP-U decap !!! */
	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_DROP;

	/* Perform xlat if needed */
	offset += sizeof(struct udphdr);
	gtph = data + offset;
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* Punt into netstack GTP-U echo request */
	if (gtph->type == GTPU_ECHO_REQ_TYPE)
		return XDP_PASS;

	return gtpu_ipip_decap(pkt, iptnl_rule, NULL);
}

static __always_inline int
gtpu_xlat(struct parse_pkt *pkt, struct ethhdr *ethh, struct iphdr *iph, struct udphdr *udph,
	  struct gtphdr *gtph, struct gtp_teid_rule *rule)
{
	struct gtp_iptnl_rule *iptnl_rule;

	/* Phase 0 : IPIP tunneling if needed
	 * Traffic selector is based on original IP header
	 * destination address */
	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &iph->daddr);
	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD) &&
	    iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP &&
	    rule->flags & GTP_FWD_FL_INGRESS)
		return gtpu_ipip_encap(pkt, iptnl_rule);

	gtpu_xlat_header(rule, iph, gtph);

	/* Phase 5 : Tunnel apply in not transparent mode */
	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD))
		return gtpu_ipip_encap(pkt, iptnl_rule);

	/* No fib lookup needed, swap mac then */

	/* FIXME: Support vlanh append when needed */

	swap_src_dst_mac(ethh);
	return XDP_TX;
}

static __always_inline int
gtpu_xlat_frag(struct parse_pkt *pkt, struct ethhdr *ethh, struct iphdr *iph, __be32 daddr)
{
	struct gtp_iptnl_rule *iptnl_rule;

	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &iph->daddr);
	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD) &&
	    iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP)
		return gtpu_ipip_encap(pkt, iptnl_rule);

	gtpu_xlat_iph(iph, daddr);

	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD))
		return gtpu_ipip_encap(pkt, iptnl_rule);

	/* No fib lookup needed, swap mac then */

	/* FIXME: Support vlanh append when needed */

	swap_src_dst_mac(ethh);
	return XDP_TX;
}


/*
 *	IP Fragmentation clean-up timer
 */
static int
gtpu_ip_frag_timer(void *map, int *key, struct gtp_teid_frag *val)
{
	bpf_map_delete_elem(map, key);
	return 0;
}

static int
gtpu_ip_frag_timer_set(const struct ip_frag_key *frag_key)
{
	struct gtp_teid_frag *gtpf = NULL;
	int ret = 0;

	gtpf = bpf_map_lookup_elem(&ip_frag, frag_key);
	if (!gtpf)
		return -1;

	/* register expire timer for this entry */
	ret = bpf_timer_init(&gtpf->timer, &ip_frag, CLOCK_MONOTONIC);
	if (ret != 0) {
		bpf_map_delete_elem(&ip_frag, frag_key);
		return -1;
	}

	bpf_timer_set_callback(&gtpf->timer, gtpu_ip_frag_timer);
	/* Fragment tracking lifetime is 500ms */
	bpf_timer_start(&gtpf->timer, 500000000, 0);
	return 0;
}

/*
 *	GTP-U traffic selector
 */
static __always_inline int
gtpu_traffic_selector(struct parse_pkt *pkt)
{
	void *data_end = (void *) (long) pkt->ctx->data_end;
	void *data = (void *) (long) pkt->ctx->data;
	struct gtp_teid_rule *rule = NULL;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = 0;
	struct ip_frag_key frag_key;
	struct gtp_teid_frag *gtpf = NULL;
	struct gtp_teid_frag frag;
	__u16 frag_off = 0, ipfl = 0;
	long ret;


	ethh = data;
	iph = data + pkt->l3_offset;
	if (iph + 1 > data_end)
		return XDP_PASS;

	if (iph->protocol == IPPROTO_IPIP)
		return gtpu_ipip_traffic_selector(pkt);

	offset += pkt->l3_offset;
	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Fragmentation handling. If we are detecting
	 * first fragment then track related daddr */
	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
		gtpf = gtpu_teid_frag_get(iph, &frag_off, &ipfl);
		if (gtpf)
			return gtpu_xlat_frag(pkt, ethh, iph, gtpf->dst_addr);

		/* MISS but fragment offset present, this is an ordering issue.
		 * We simply drop to not flood kernel with unsollicited ip_frag.
		 */
		if (frag_off != 0)
			return XDP_DROP;
	}

	udph = data + offset + sizeof(struct iphdr);
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_PASS;

	offset += sizeof(struct iphdr);
	gtph = data + offset + sizeof(struct udphdr);
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* That is a nice feature of XDP here:
	 * punt to linux kernel stack path-management message.
	 * We get it back into userland where things are easier
	 */
	if (gtph->type != 0xff)
		return XDP_PASS;

	rule = bpf_map_lookup_elem(&teid_xlat, &gtph->teid);
	/* Prevent from GTP-U netstack flooding */
	if (!rule)
		return XDP_DROP;

	/* First fragment detected and handled only if related
	 * to an existing F-TEID */
	if ((ipfl & IP_MF) && (frag_off == 0)) {
		__builtin_memset(&frag_key, 0, sizeof(struct ip_frag_key));
		frag_key.saddr = iph->saddr;
		frag_key.daddr = iph->daddr;
		frag_key.id = iph->id;
		frag_key.protocol = iph->protocol;

		__builtin_memset(&frag, 0, sizeof(struct gtp_teid_frag));
		frag.dst_addr = rule->dst_addr;
		ret = bpf_map_update_elem(&ip_frag, &frag_key, &frag, BPF_NOEXIST);
		if (ret < 0)
			return XDP_DROP;

		gtpu_ip_frag_timer_set(&frag_key);
	}

	return gtpu_xlat(pkt, ethh, iph, udph, gtph, rule);
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
int xdp_fwd(struct xdp_md *ctx)
{
	struct parse_pkt pkt = { .ctx = ctx,
				 .vlan_id = 0,
				 .l3_proto = 0,
				 .l3_offset = 0
			       };

	if (!parse_eth_frame(&pkt))
		return XDP_PASS;

	return gtpu_traffic_selector(&pkt);
}

char _license[] SEC("license") = "GPL";
