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

#define KBUILD_MODNAME "gtp_mirror"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
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
#include "gtp.h"


/*
 *	MAPs
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MIRROR_ENTRIES);
	__type(key, __be32);
	__type(value, struct gtp_mirror_rule);
} mirror_rules SEC(".maps");


SEC("tc")
int tc_gtp_mirror(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	int offset = sizeof(struct ethhdr);
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtp_mirror_rule *rule;

        if (unlikely(skb->protocol != __constant_htons(ETH_P_IP)))
                return TC_ACT_OK;

	iph = data + offset;
	if (iph + 1 > (typeof(iph))data_end)
		return TC_ACT_OK;

	/* First match destination address */
	rule = bpf_map_lookup_elem(&mirror_rules, &iph->daddr);
	rule = (rule) ? rule : bpf_map_lookup_elem(&mirror_rules, &iph->saddr);
	if (!rule)
		return TC_ACT_OK;

	if (iph->protocol != rule->protocol)
		return TC_ACT_OK;

        offset += sizeof(struct iphdr);
        udph = data + offset;
	if (udph + 1 > (typeof(udph))data_end)
		return TC_ACT_OK;

        if (!(udph->dest == rule->port || udph->source == rule->port))
        	return TC_ACT_OK;

        bpf_clone_redirect(skb, rule->ifindex, 0);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
