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


#include "lib/gtp_fwd.h"
#include "lib/gtp_mirror.h"
#include "lib/if_rule.h"


SEC("xdp")
int gtp_fwd_main(struct xdp_md *ctx)
{
	struct if_rule_data d = { };
	int action, ret;

	action = if_rule_parse_pkt_sel(ctx, &d, gtp_fwd_rule_selection);

	switch (action) {
	case XDP_ABORTED ... XDP_REDIRECT:
		return action;

	case XDP_IFR_DEFAULT_ROUTE:
		action = gtp_fwd_traffic_selector(ctx, &d);
		break;

	case XDP_GTPFWD_GTPU_XLAT:
	case XDP_GTPFWD_GTPU_NOXLAT:
		action = gtp_fwd_handle_gtpu(ctx, &d);
		break;

	case XDP_GTPFWD_TUN_XLAT:
	case XDP_GTPFWD_TUN_NOXLAT:
		action = gtp_fwd_handle_ipip(ctx, &d);
		break;

	default:
		return XDP_PASS;
	}

	if (action == XDP_IFR_FORWARD)
		return if_rule_rewrite_pkt(ctx, &d);

	return action;
}


SEC("tcx/ingress")
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
	if (iph + 1 > data_end)
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
	if (udph + 1 > data_end)
		return TC_ACT_OK;

	if (!(udph->dest == rule->port || udph->source == rule->port))
        	return TC_ACT_OK;

	bpf_clone_redirect(skb, rule->ifindex, 0);

	return TC_ACT_OK;
}



const char _mode[] = "if_rules,gtp_fwd,gtp_mirror";
char _license[] SEC("license") = "GPL";
