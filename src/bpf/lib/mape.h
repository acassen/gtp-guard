/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <time.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf_helpers.h>

#include "tools.h"
#include "if_rule.h"
#include "mape-def.h"


/*
 * MAP-E Border Relay.
 *
 * RFC7597 compliant, with the following limitations:
 *  - psid offset fixed to 0
 *  - ipv6 subnet bits fixed to 0
 *    -> ea_bits = ipv4_suffix_bits + psid_bits
 *    -> ipv6_prefix bits + ea_bits = 64 bits
 *  - only 1 BMR (basic mapping rule) can be provisionned
 *  - no forwarding mapping rules
 *  - support encap of ipv4 fragments (only ordered ones)
 */


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct mape_bmr);
	__uint(max_entries, 1);
} mape_bmr SEC(".maps");


struct mape_frag_rule
{
	struct ipfrag_rule r;
	__u16 psid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8000);
	__type(key, struct ip4_frag_key);
	__type(value, struct mape_frag_rule);
} mape_ipfrag SEC(".maps");



static int
_ipfrag_timer_cb(void *map, int *key, struct mape_frag_rule *fr)
{
	bpf_map_delete_elem(map, key);
	return 0;
}

static int
_ipfrag_save(const struct iphdr *iph, __u16 psid)
{
	struct mape_frag_rule *fr;
	int ret;

	/* save psid for next fragments */
	struct ip4_frag_key fk = {
		.saddr = iph->saddr,
		.daddr = iph->daddr,
		.id = iph->id,
		.protocol = iph->protocol,
		.pad = 0,
	};
	struct mape_frag_rule nfr = {
		.r.flags = 0,
		.psid = psid,
	};
	ret = bpf_map_update_elem(&mape_ipfrag, &fk, &nfr, 0);
	if (ret < 0)
		return -1;

	/* need to retrieve from map to be able to set timer */
	fr = bpf_map_lookup_elem(&mape_ipfrag, &fk);
	if (fr == NULL)
		return -1;

	ret = bpf_timer_init(&fr->r.timer, &mape_ipfrag, CLOCK_MONOTONIC);
	if (ret != 0) {
		bpf_map_delete_elem(&mape_ipfrag, &fk);
		return -1;
	}

	bpf_timer_set_callback(&fr->r.timer, _ipfrag_timer_cb);
	bpf_timer_start(&fr->r.timer, 500000000, 0);
	return 0;
}

static __always_inline struct mape_frag_rule *
_ipfrag_get(const struct iphdr *iph)
{
	struct mape_frag_rule *fr = NULL;
	__u16 off;

	off = bpf_ntohs(iph->frag_off);
	off &= IP_OFFMASK;
	off <<= 3;
	if (!off)
		return NULL;

	const struct ip4_frag_key fk = {
		.saddr = iph->saddr,
		.daddr = iph->daddr,
		.id = iph->id,
		.protocol = iph->protocol,
		.pad = 0,
	};
	return bpf_map_lookup_elem(&mape_ipfrag, &fk);
}



static __always_inline int
_get_port_id(struct iphdr *iph, void *data_end, int rec)
{
	struct udphdr *udp;
	struct icmphdr *icmp;
	struct gre_hdr_pptp *gre;
	void *payload;
	__u16 pid;

	payload = (void *)iph + (iph->ihl << 2);
	switch (iph->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		udp = payload;
		if ((void *)(udp + 1) > data_end)
			return -1;
		return bpf_ntohs(!rec ? udp->dest : udp->source);

	case IPPROTO_GRE:
		gre = payload;
		if ((void *)(gre + 1) > data_end)
			return -1;
		if (gre->protocol != __constant_htonl(GRE_PROTOCOL_PPTP))
			return -1;
		return bpf_ntohs(gre->call_id);

	case IPPROTO_ICMP:
		icmp = payload;
		if ((void *)(icmp + 1) > data_end)
			return -1;

		switch (icmp->type) {
		case ICMP_ECHO:
			if (likely(rec == 0))
				return -1;
			/* fallthrough... */

		case ICMP_ECHOREPLY:
			return bpf_ntohs(icmp->un.echo.id);

		case ICMP_TIME_EXCEEDED:
		case ICMP_DEST_UNREACH:
			iph = (struct iphdr *)(icmp + 1);
			if (rec == 1 || (void *)(iph + 1) > data_end)
				return -1;
			return _get_port_id(iph, data_end, 1);
		}
	}

	return -1;
}


/*
 * downlink traffic. retrieve psid and encap in ipv6
 */
static __always_inline int
mape_encap(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6h;
	struct iphdr *ip4h;
	const struct mape_bmr *bmr;
	const struct mape_frag_rule *fr;
	__u32 dst_addr, ea_bits, ea_bit_n, idx;
	__u16 psid;
	int port, pkt_len;

	idx = 0;
	bmr = bpf_map_lookup_elem(&mape_bmr, &idx);
	if (bmr == NULL)
		return XDP_DROP;

	/* --- process ipv4 --- */
	ip4h = data + d->pl_off;
	if (d->pl_off > 256 || (void *)(ip4h + 1) > data_end)
		return XDP_DROP;

	dst_addr = bpf_ntohl(ip4h->daddr);
	pkt_len = ip4h->tot_len;

	/* subsequents fragments, retrieve psid */
	if (ip4h->frag_off & __constant_htons(IP_OFFMASK)) {
		fr = _ipfrag_get(ip4h);
		if (fr == NULL)
			return XDP_DROP;
		psid = fr->psid;
		goto encap;
	}

	/* extract psid from ipv4 header */
	port = _get_port_id(ip4h, data_end, 0);
	if (port < 0)
		return XDP_DROP;
	psid = port >> (16 - bmr->psid_bits);

	/* first fragment, save psid */
	if (ip4h->frag_off & __constant_htons(IP_MF))
		_ipfrag_save(ip4h, psid);

 encap:
	/* --- ipv6 encap --- */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(*ip6h)) < 0)
		return XDP_ABORTED;
	d->flags |= IF_RULE_FL_XDP_ADJUSTED | IF_RULE_FL_DST_IPV6;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	ip6h = data + d->pl_off;
	if (d->pl_off > 256 || (void *)(ip6h + 1) > data_end)
		return XDP_DROP;

	ip6h->version = 6;
	ip6h->priority = 0;
	ip6h->flow_lbl[0] = 0;
	ip6h->flow_lbl[1] = 0;
	ip6h->flow_lbl[2] = 0;
	ip6h->payload_len = pkt_len;
	ip6h->nexthdr = IPPROTO_IPIP;
	ip6h->hop_limit = 64;
	__builtin_memcpy(&ip6h->saddr, (const void *)&bmr->br_addr, 16);

	ea_bit_n = bmr->v4_suffix_bits + bmr->psid_bits;
	ea_bits = (dst_addr & bmr->v4_suffix_mask) << bmr->psid_bits;
	ea_bits |= psid;

	ip6h->daddr.s6_addr32[0] = bmr->v6_prefix.s6_addr32[0];
	ip6h->daddr.s6_addr[4] = bmr->v6_prefix.s6_addr[4];
	switch (ea_bit_n) {
	case 0 ... 7:
		ip6h->daddr.s6_addr[5] = bmr->v6_prefix.s6_addr[5];
		ip6h->daddr.s6_addr[6] = bmr->v6_prefix.s6_addr[6];
		ip6h->daddr.s6_addr[7] = bmr->v6_prefix.s6_addr[7];
		ip6h->daddr.s6_addr[7] |= ea_bits;
		break;
	case 8 ... 15:
		ip6h->daddr.s6_addr[5] = bmr->v6_prefix.s6_addr[5];
		ip6h->daddr.s6_addr[6] = bmr->v6_prefix.s6_addr[6];
		ip6h->daddr.s6_addr[6] |= (ea_bits >> 8);
		ip6h->daddr.s6_addr[7] = ea_bits;
		break;
	case 16 ... 23:
		ip6h->daddr.s6_addr[5] = bmr->v6_prefix.s6_addr[5];
		ip6h->daddr.s6_addr[5] |= (ea_bits >> 16);
		ip6h->daddr.s6_addr[6] = ea_bits >> 8;
		ip6h->daddr.s6_addr[7] = ea_bits;
		break;
	case 24 ... 32:
		ip6h->daddr.s6_addr[4] |= ea_bits >> 24;
		ip6h->daddr.s6_addr[5] = ea_bits >> 16;
		ip6h->daddr.s6_addr[6] = ea_bits >> 8;
		ip6h->daddr.s6_addr[7] = ea_bits;
		break;
	}

	ip6h->daddr.s6_addr[8] = 0;
	ip6h->daddr.s6_addr[9] = 0;
	ip6h->daddr.s6_addr[10] = dst_addr >> 24;
	ip6h->daddr.s6_addr[11] = dst_addr >> 16;
	ip6h->daddr.s6_addr[12] = dst_addr >> 8;
	ip6h->daddr.s6_addr[13] = dst_addr;
	ip6h->daddr.s6_addr[14] = psid >> 8;
	ip6h->daddr.s6_addr[15] = psid;

	/* to be able to resolve nh */
	__builtin_memcpy(&d->dst_addr.ip6, &ip6h->daddr, 16);

	return XDP_IFR_FORWARD;
}


/*
 * uplink traffic, remove ipv6 encap header and fwd ipv4.
 *
 * as it comes from trusted source, do not check inner ipv4.
 */
static __no_inline int
mape_decap(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6h;
	void *payload;
	__u32 dst_addr;
	__u8 nh;

	ip6h = data + d->pl_off;
	if (d->pl_off > 256 || (void *)(ip6h + 1) > data_end)
		return XDP_DROP;

	dst_addr =
		(ip6h->daddr.s6_addr[10]) |
		(ip6h->daddr.s6_addr[11] << 8) |
		(ip6h->daddr.s6_addr[12] << 16) |
		(ip6h->daddr.s6_addr[13] << 24);

	payload = ipv6_skip_exthdr(ip6h, data_end, &nh);
	if (payload == NULL || nh != IPPROTO_IPIP)
		return XDP_DROP;

	if (bpf_xdp_adjust_head(ctx, payload - (void *)ip6h) < 0)
		return XDP_DROP;
	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	/* to resolve nh */
	d->dst_addr.ip4 = dst_addr;

	return XDP_IFR_FORWARD;
}
