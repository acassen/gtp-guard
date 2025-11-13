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
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000000);
	__type(key, __be32);				/* TEID */
	__type(value, struct pfcp_teid_rule);
} teid_rule SEC(".maps");


/*
 *	Public traffic selector
 */
static __always_inline int
upf_handle_pub(struct if_rule_data *d)
{
	/*
	 * Should encap in gtpu here
	 */

	return XDP_PASS;
}


/*
 *	GTP-U traffic selector
 */
static __always_inline int
upf_handle_gtpu(struct if_rule_data *d)
{
	void *data = (void *)(long)d->ctx->data;
	void *data_end = (void *)(long)d->ctx->data_end;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph;
	__u16 offset = d->pl_off;
	long ret;

	/* --- ip layer --- */
	iph = (struct iphdr *)(data + offset);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

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

	/*
	 * should decap GTPU here
	 */

	d->dst_addr = iph->daddr;

	return 10;
}
