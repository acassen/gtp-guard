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
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include "gtp_bpf_utils.h"
#include "gtp_fwd.h"

/*
 *	MAPs
 */
struct bpf_map_def SEC("maps") teid_xlat = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__be32),			/* Virtual TEID */
	.value_size = sizeof(struct gtp_teid_rule),	/* Rewrite GTP Rulez */
	.max_entries = 1000000,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ip_frag_teid = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ip_frag_key),		/* ip_src + id */
	.value_size = sizeof(struct gtp_teid_frag),	/* TEID linked */
	.max_entries = 1000000,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") iptnl_info = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__be32),
	.value_size = sizeof(struct gtp_iptnl_rule),
	.max_entries = MAX_IPTNL_ENTRIES,
};




/* Fragmentation handling */
static __always_inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;
}



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
gtpu_fib_lookup(struct xdp_md *ctx, struct ethhdr *ethh, struct iphdr *iph, struct bpf_fib_lookup *fib_params)
{
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

	/* Ethernet playground */
//	ethh->h_proto = bpf_htons(ETH_P_IP);
	__builtin_memcpy(ethh->h_dest, fib_params->dmac, ETH_ALEN);
	__builtin_memcpy(ethh->h_source, fib_params->smac, ETH_ALEN);

//	return bpf_redirect(fib_params->ifindex, 0);
	return XDP_TX;
}

static __always_inline int
gtpu_ipencap(struct parse_pkt *pkt, struct gtp_iptnl_rule *iptnl_rule)
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
	return gtpu_fib_lookup(ctx, new_eth, iph, &fib_params);
}

static __always_inline void
gtpu_xlat_header(struct gtp_teid_rule *rule, struct iphdr *iph, struct gtphdr *gtph)
{
	__u32 csum = 0;

	/* Phase 1 : rewrite IP header */
	iph->saddr = iph->daddr;
	iph->daddr = rule->dst_addr;
	--iph->ttl;
	iph->check = 0;
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;

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

static __always_inline int
gtpu_ipip_decap(struct parse_pkt *pkt, struct gtp_iptnl_rule *iptnl_rule)
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

	return gtpu_fib_lookup(ctx, new_eth, iph, &fib_params);
}

static __always_inline int
gtpu_ipip_traffic_selector(struct parse_pkt *pkt)
{
	struct xdp_md *ctx = pkt->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct gtp_iptnl_rule *iptnl_rule;
	struct iphdr *iph_outer, *iph_inner;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = pkt->l3_offset;

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

	return gtpu_ipip_decap(pkt, iptnl_rule);
}

static __always_inline int
gtpu_xlat(struct parse_pkt *pkt, struct ethhdr *ethh, struct iphdr *iph, struct udphdr *udph, struct gtphdr *gtph)
{
	struct gtp_teid_rule *rule;
	struct gtp_iptnl_rule *iptnl_rule;

	/* That is a nice feature of XDP here:
	 * punt to linux kernel stack path-management message.
	 * We get it back into userland where things are easier
	 */
	if (gtph->type != 0xff)
		return XDP_PASS;

	/* FIXME: Here we need to find out a way to handle this in a
	 * percpu design fashion */
	rule = bpf_map_lookup_elem(&teid_xlat, &gtph->teid);

	/* Prevent GTP-U to flood stack */
	if (!rule)
		return XDP_DROP;

	/* Phase 0 : IPIP tunneling if needed
	 * Traffic selector is based on original IP header
	 * destination address */
	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &iph->daddr);
	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD) &&
	    iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP &&
	    rule->direction == GTP_TEID_DIRECTION_INGRESS) 
		return gtpu_ipencap(pkt, iptnl_rule);

	gtpu_xlat_header(rule, iph, gtph);

	/* Phase 5 : Tunnel apply in not transparent mode */
	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD))
		return gtpu_ipencap(pkt, iptnl_rule);

	/* No fib lookup needed, swap mac then */
	swap_src_dst_mac(ethh);
	return XDP_TX;
}

/*
 *	IP Fragmentation handling
 */
static __always_inline void
gtpu_ipfrag_track(struct iphdr *iph)
{
	struct ip_frag_key key = {};
	__u16 frag_off = 0, ipfl = 0;

	frag_off = bpf_ntohs(iph->frag_off);
	if (frag_off) {
		ipfl = frag_off & ~IP_OFFSET;
		frag_off &= IP_OFFSET;
		frag_off <<= 3;		/* 8-byte chunk */
		/* First fragment detected */
		if ((ipfl & IP_MF) && (frag_off == 0)) {

		}
	}
}


/*
 *	GTP-U traffic selector
 */
static __always_inline int
gtpu_traffic_selector(struct parse_pkt *pkt)
{
	void *data_end = (void *) (long) pkt->ctx->data_end;
	void *data = (void *) (long) pkt->ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = 0, tot_len = 0;

	ethh = data;
	iph = data + pkt->l3_offset;
	if (iph + 1 > data_end)
		return XDP_PASS;

	if (iph->protocol == IPPROTO_IPIP)
		return gtpu_ipip_traffic_selector(pkt);

	/* Fragmentation handling. If we are detecting
	 * first fragment then track related TEID */
	gtpu_ipfrag_track(iph);

	tot_len = bpf_ntohs(iph->tot_len);
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
		
	return gtpu_xlat(pkt, ethh, iph, udph, gtph);
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

SEC("xdp_gtp_fwd")
int
xdp_fwd(struct xdp_md *ctx)
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
