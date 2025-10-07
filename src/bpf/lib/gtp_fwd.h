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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#pragma once

#include "if_rule.h"

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



static __always_inline int
gtpu_ipip_encap(struct if_rule_data *d, struct gtp_iptnl_rule *iptnl_rule)
{
	struct xdp_md *ctx = d->ctx;
	void *data, *data_end;
	struct iphdr *iph;
	__u16 payload_len;
	__u32 csum = 0;

	iph = data + d->pl_off;
	if (iph + 1 > data_end)
		return XDP_DROP;
	payload_len = bpf_ntohs(iph->tot_len);

	/* expand headroom */
	if (bpf_xdp_adjust_head(ctx, -(int)(sizeof (struct iphdr))))
		return XDP_DROP;

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;

	iph = data + d->pl_off;
	if (iph + 1 > data_end)
		return XDP_DROP;

	/* Fill IPIP Encap header */
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
	csum_ipv4(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;

	/* if_rule will do fib_lookup and set eth [vlan] [gre] headers */
	d->dst_addr = iptnl_rule->remote_addr;
	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	return 0;
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
	csum_ipv4(iph, sizeof(struct iphdr), &csum);
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
		frag_key.saddr = iph->saddr;
		frag_key.daddr = iph->daddr;
		frag_key.id = iph->id;
		frag_key.protocol = iph->protocol;
		frag_key.pad = 0;

		gtpf = bpf_map_lookup_elem(&ip_frag, &frag_key);
	}

	return gtpf;
}

static __always_inline int
gtpu_ipip_decap(struct if_rule_data *d, struct gtp_iptnl_rule *iptnl_rule, struct gtp_teid_frag *gtpf)
{
	struct xdp_md *ctx = d->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct gtp_teid_rule *rule;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	__be16 vlan_id = 0;
	int err, headroom, offset;
	__be32 daddr;

	/* Destination resolution */
	if (gtpf && (iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP)) {
		d->dst_addr = gtpf->dst_addr;
	} else if (iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP) {
		gtph = data + d->pl_off
			    + 2 * sizeof(struct iphdr)
			    + sizeof(struct udphdr);
		if (d->pl_off > 256 || gtph + 1 > data_end)
			return XDP_DROP;

		rule = bpf_map_lookup_elem(&teid_xlat, &gtph->teid);
		if (rule)
			d->dst_addr = rule->dst_addr;
	}

	/* Shrink headroom */
	if (bpf_xdp_adjust_head(ctx, sizeof(struct iphdr)))
		return XDP_DROP;

	d->flags |= IF_RULE_FL_XDP_ADJUSTED;
	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;

	/* IP */
	offset = d->pl_off;
	iph = data + offset;
	if (offset > 256 || iph + 1 > data_end)
		return XDP_DROP;

	/* Fragmentation handling */
	if (gtpf) {
		if (iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP)
			gtpu_xlat_iph(iph, gtpf->dst_addr);

		return 0;
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

	return 0;
}

static __always_inline int
gtpu_xlat(struct if_rule_data *d, struct iphdr *iph, struct udphdr *udph,
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
		return gtpu_ipip_encap(d, iptnl_rule);

	gtpu_xlat_header(rule, iph, gtph);

	/* Phase 5 : Tunnel apply in not transparent mode */
	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD))
		return gtpu_ipip_encap(d, iptnl_rule);

	/* if_rule will reencap packet */
	d->dst_addr = iph->daddr;
	return 0;
}

static __always_inline int
gtpu_xlat_frag(struct if_rule_data *d, struct iphdr *iph, __be32 daddr)
{
	struct gtp_iptnl_rule *iptnl_rule;

	iptnl_rule = bpf_map_lookup_elem(&iptnl_info, &iph->daddr);
	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD) &&
	    iptnl_rule->flags & IPTNL_FL_TRANSPARENT_EGRESS_ENCAP)
		return gtpu_ipip_encap(d, iptnl_rule);

	gtpu_xlat_iph(iph, daddr);

	if (iptnl_rule && !(iptnl_rule->flags & IPTNL_FL_DEAD))
		return gtpu_ipip_encap(d, iptnl_rule);

	d->dst_addr = iph->daddr;
	return 0;
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


static __always_inline int
gtpu_ipip_traffic_selector(struct if_rule_data *d)
{
	struct xdp_md *ctx = d->ctx;
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	struct gtp_iptnl_rule *iptnl_rule;
	struct gtp_teid_frag *gtpf = NULL;
	struct iphdr *iph_outer, *iph_inner;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = d->pl_off;
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

	d->dst_addr = iph_inner->daddr;

	/* Fragmentation handling */
	if (iph_inner->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
		gtpf = gtpu_teid_frag_get(iph_inner, &frag_off, &ipfl);
		if (gtpf)
			return gtpu_ipip_decap(d, iptnl_rule, gtpf);
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

	return gtpu_ipip_decap(d, iptnl_rule, NULL);
}

/*
 *	GTP-U traffic selector
 */
static __always_inline int
gtpu_traffic_selector(struct if_rule_data *d)
{
	struct xdp_md *ctx = d->ctx;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct gtp_teid_rule *rule = NULL;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	struct ip_frag_key frag_key;
	struct gtp_teid_frag *gtpf = NULL;
	struct gtp_teid_frag frag;
	__u16 frag_off = 0, ipfl = 0;
	__u16 offset = d->pl_off;
	long ret;

	iph = data + offset;
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_PASS;

	switch (iph->protocol) {
	case IPPROTO_IPIP:
		return gtpu_ipip_traffic_selector(d);
	case IPPROTO_UDP:
		break;
	default:
		return XDP_PASS;
	}

	/* Fragmentation handling. If we are detecting
	 * first fragment then track related daddr */
	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
		gtpf = gtpu_teid_frag_get(iph, &frag_off, &ipfl);
		if (gtpf)
			return gtpu_xlat_frag(d, iph, gtpf->dst_addr);

		/* MISS but fragment offset present, this is an ordering issue.
		 * We simply drop to not flood kernel with unsollicited ip_frag.
		 */
		if (frag_off != 0)
			return XDP_DROP;
	}

	offset += sizeof(struct iphdr);
	udph = data + offset;
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_PASS;

	offset += sizeof(struct udphdr);
	gtph = data + offset;
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
		frag_key.saddr = iph->saddr;
		frag_key.daddr = iph->daddr;
		frag_key.id = iph->id;
		frag_key.protocol = iph->protocol;
		frag_key.pad = 0;

		__builtin_memset(&frag, 0, sizeof(struct gtp_teid_frag));
		frag.dst_addr = rule->dst_addr;
		ret = bpf_map_update_elem(&ip_frag, &frag_key, &frag, BPF_NOEXIST);
		if (ret < 0)
			return XDP_DROP;

		gtpu_ip_frag_timer_set(&frag_key);
	}

	return gtpu_xlat(d, iph, udph, gtph, rule);
}
