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

#pragma once

#include <time.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf_helpers.h>

#include "gtp_fwd-def.h"
#include "if_rule.h"
#include "tools.h"

struct gtp_teid_rule {
	__be32		vteid;
	__be32		teid;
	__be32		dst_addr;
	__be32		src_addr;

	/* Some stats */
	__u64 		packets;
	__u64 		bytes;
} __attribute__ ((__aligned__(8)));

struct gtp_teid_frag {
	__be32		src_addr;
	__be32		dst_addr;
	struct bpf_timer timer;
};



static __always_inline int
gtp_fwd_rule_selection(struct if_rule_data *d, struct iphdr *iph)
{
	struct if_rule_key *k = &d->k;
	__u32 ifindex = k->b.ifindex;
	__u16 vlan_id = k->b.vlan_id;

	/* specific rule to enter/exit tunnel. this rule doesn't
	 * include interface spec */
	k->b.ifindex = 0;
	k->b.vlan_id = 0;
	k->saddr = iph->saddr;
	k->daddr = iph->daddr;
	d->r = bpf_map_lookup_elem(&if_rule, k);
	k->b.ifindex = ifindex;
	k->b.vlan_id = vlan_id;
	if (d->r != NULL)
		return d->r->action;

	/* direct egress <-> ingress */
	if (!k->b.tun_local) {
		k->saddr = 0;
		k->daddr = 0;
		d->r = bpf_map_lookup_elem(&if_rule, k);
		if (d->r != NULL)
			return d->r->action;
	}

	return XDP_PASS;
}


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
	__type(key, struct ip4_frag_key);		/* saddr + daddr + id + protocol */
	__type(value, struct gtp_teid_frag);		/* dst_addr linked */
} ip_frag SEC(".maps");


static __always_inline void
gtpu_xlat_iph(struct iphdr *iph, __be32 saddr, __be32 daddr)
{
	__u32 csum = 0;

	/* Phase 1 : rewrite IP header */
	iph->saddr = saddr;
	iph->daddr = daddr;
	--iph->ttl;
	iph->check = 0;
	csum_ipv4(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;
}

static __always_inline void
gtpu_xlat_header(struct gtp_teid_rule *rule, struct iphdr *iph, struct udphdr *udph,
		 struct gtphdr *gtph)
{
	/* Phase 0 : update udp checksum, if set */
	if (udph->check) {
		__u32 sum = csum_diff32(0, iph->saddr, rule->src_addr);
		sum = csum_diff32(sum, iph->daddr, rule->dst_addr);
		__u16 nsum = csum_replace(udph->check, sum - 1);
		udph->check = nsum ?: 0xffff;
	}

	/* Phase 1 : rewrite IP header */
	gtpu_xlat_iph(iph, rule->src_addr, rule->dst_addr);

	/* Phase 2 : we are into transparent mode
	 * so just forward ingress src port.
	 * in reverse path from egress to ingress
	 * dst_port is fixed to 2152 : horrible
	 * since can expect to reply to the original
	 * src_port... crappy
	 */

	/* Phase 3 : rewrite GTP TEID */
	gtph->teid = rule->teid;

	/* Phase 4 : Stats counter update */
	rule->packets++;
	rule->bytes += bpf_ntohs(iph->tot_len);
}

static struct gtp_teid_frag *
gtpu_teid_frag_get(struct iphdr *iph, __u16 *frag_off, __u16 *ipfl)
{
	struct gtp_teid_frag *gtpf = NULL;
	struct ip4_frag_key frag_key;

	*frag_off = bpf_ntohs(iph->frag_off);
	*ipfl = *frag_off & ~IP_OFFMASK;
	*frag_off &= IP_OFFMASK;
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
gtpu_ip_frag_timer_set(const struct ip4_frag_key *frag_key)
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
 *	IPIP traffic selector
 */
static __always_inline int
gtp_fwd_handle_ipip(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *) (long)ctx->data;
	void *data_end = (void *) (long)ctx->data_end;
	struct gtp_teid_frag *gtpf = NULL;
	struct gtp_teid_rule *rule;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	int offset = d->pl_off;
	__u16 frag_off = 0, ipfl = 0;

	/* --- ip layer --- */
	iph = data + offset;
	if (d->pl_off > 256 || iph + 1 > data_end)
		return XDP_PASS;

	/* Drop everything but UDP datagram */
	if (iph->protocol != IPPROTO_UDP)
		return XDP_DROP;

	/* Fragmentation handling (subsequent fragments) */
	if (iph->frag_off & bpf_htons(IP_OFFMASK)) {
		gtpf = gtpu_teid_frag_get(iph, &frag_off, &ipfl);
		if (!gtpf)
			return XDP_DROP;
		if (d->r->action == 13) {
			gtpu_xlat_iph(iph, gtpf->src_addr, gtpf->dst_addr);
			d->dst_addr.ip4 = gtpf->dst_addr;
		} else {
			d->dst_addr.ip4 = iph->daddr;
		}
		return XDP_IFR_FORWARD;
	}

	/* --- udp layer --- */
	offset += sizeof(struct iphdr);
	udph = data + offset;
	if (udph + 1 > data_end)
		return XDP_DROP;

	/* Only allow GTP-U decap !!! */
	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_DROP;

	/* --- gtp-u layer --- */
	offset += sizeof(struct udphdr);
	gtph = data + offset;
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* Punt into netstack GTP-U echo request */
	if (gtph->type == GTPU_ECHO_REQ_TYPE)
		return XDP_PASS;

	/* Perform xlat if needed */
	if (d->r->action == XDP_GTPFWD_TUN_XLAT) {
		rule = bpf_map_lookup_elem(&teid_xlat, &gtph->teid);
		if (!rule)
			return XDP_DROP;
		gtpu_xlat_header(rule, iph, udph, gtph);
		d->dst_addr.ip4 = rule->dst_addr;
		/* bpf_printk("ipip xlat now, dst=%x", d->dst_addr.ip4); */
	} else {
		d->dst_addr.ip4 = iph->daddr;
		/* bpf_printk("ipip no translation, dst=%x", d->dst_addr.ip4); */
	}

	return XDP_IFR_FORWARD;
}

/*
 *	GTP-U traffic selector
 */
static __always_inline int
gtp_fwd_handle_gtpu(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct gtp_teid_rule *rule = NULL;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph = NULL;
	struct ip4_frag_key frag_key;
	struct gtp_teid_frag *gtpf = NULL;
	struct gtp_teid_frag frag;
	__u16 frag_off = 0, ipfl = 0;
	__u16 offset = d->pl_off;
	long ret;

	/* --- ip layer --- */
	iph = (struct iphdr *)(data + offset);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Fragmentation handling. If we are detecting
	 * first fragment then track related saddr/daddr */
	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFMASK)) {
		gtpf = gtpu_teid_frag_get(iph, &frag_off, &ipfl);
		if (gtpf && d->r->action == 11) {
			/* xlat subsequent fragment. we need to add a new
			 * frag key to match when it will come back */
			gtpu_xlat_iph(iph, gtpf->src_addr, gtpf->dst_addr);
			d->dst_addr.ip4 = gtpf->dst_addr;

			frag_key.saddr = iph->saddr;
			frag_key.daddr = iph->daddr;
			frag_key.id = iph->id;
			frag_key.protocol = iph->protocol;
			frag_key.pad = 0;

			__builtin_memset(&frag, 0, sizeof(struct gtp_teid_frag));
			ret = bpf_map_update_elem(&ip_frag, &frag_key, &frag, BPF_NOEXIST);
			if (ret < 0)
				return XDP_DROP;

			gtpu_ip_frag_timer_set(&frag_key);

			/* bpf_printk("gtpu FRAG xlat header! dst=%x", d->dst_addr.ip4); */
			return XDP_IFR_FORWARD;

		} else if (gtpf) {
			/* no xlat here, let it go */
			d->dst_addr.ip4 = iph->daddr;
			return XDP_IFR_FORWARD;

		} else if (frag_off != 0) {
			/* MISS but fragment offset present, this is an ordering issue.
			 * We simply drop to not flood kernel with unsollicited ip_frag.
			 */
			return XDP_DROP;
		} else {
			/* first fragment, continue */
		}
	}

	/* --- udp layer --- */
	offset += sizeof(struct iphdr);
	udph = (struct udphdr *)(data + offset);
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != bpf_htons(GTPU_PORT))
		return XDP_PASS;

	/* --- gtp layer --- */
	offset += sizeof(struct udphdr);
	gtph = (struct gtphdr *)(data + offset);
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* That is a nice feature of XDP here:
	 * punt to linux kernel stack path-management message.
	 * We get it back into userland where things are easier,
	 * a socket is opened and ready to recv() */
	if (gtph->type != 0xff)
		return XDP_PASS;

	rule = bpf_map_lookup_elem(&teid_xlat, &gtph->teid);
	/* bpf_printk("process gtp-u data teid: 0x%x rule %p", gtph->teid, rule); */
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
		frag.src_addr = rule->src_addr;
		frag.dst_addr = rule->dst_addr;
		ret = bpf_map_update_elem(&ip_frag, &frag_key, &frag, BPF_NOEXIST);
		if (ret < 0)
			return XDP_DROP;

		gtpu_ip_frag_timer_set(&frag_key);
	}

	/* Perform xlat if needed */
	if (d->r->action == XDP_GTPFWD_GTPU_XLAT ||
	    d->r->action == XDP_IFR_DEFAULT_ROUTE) {
		gtpu_xlat_header(rule, iph, udph, gtph);
		d->dst_addr.ip4 = rule->dst_addr;
		/* bpf_printk("gtpu xlat header! dst=%x", rule->dst_addr); */
	} else {
		d->dst_addr.ip4 = iph->daddr;
		/* bpf_printk("gtpu no translation dst=%x", d->dst_addr.ip4); */
	}

	return XDP_IFR_FORWARD;
}


static __always_inline int
gtp_fwd_traffic_selector(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *iph;

	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_PASS;

	switch (iph->protocol) {
	case IPPROTO_UDP:
		return gtp_fwd_handle_gtpu(ctx, d);
	case IPPROTO_IPIP:
		return gtp_fwd_handle_ipip(ctx, d);
	default:
		return XDP_PASS;
	}
}
