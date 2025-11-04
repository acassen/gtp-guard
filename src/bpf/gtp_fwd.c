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
#include <linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include "gtp.h"

#include "lib/gtp_fwd-def.h"
#include "lib/if_rule.h"
#include "lib/gtp_fwd.h"

static __always_inline int
rule_selection(struct if_rule_data *d, struct iphdr *iph)
{
	d->k.saddr = iph->saddr;
	d->k.daddr = iph->daddr;
	d->r = bpf_map_lookup_elem(&if_rule, &d->k);
	if (d->r != NULL)
		return d->r->action;

	/* direct egress <-> ingress */
	if (!d->k.b.tun_local) {
		d->k.saddr = 0;
		d->k.daddr = 0;
		d->r = bpf_map_lookup_elem(&if_rule, &d->k);
		if (d->r != NULL)
			return d->r->action;
	}

	return XDP_PASS;
}

SEC("xdp")
int gtp_fwd_main(struct xdp_md *ctx)
{
	struct if_rule_data d = { .ctx = ctx };
	int action, ret;

	action = if_rule_parse_pkt(&d, rule_selection);
	if (action <= XDP_REDIRECT)
		return action;

	if (action == 13 || action == 14)
		ret = gtpu_ipip_traffic_selector(&d);
	else
		ret = gtpu_traffic_selector(&d);

	if (ret == 10)
		return if_rule_rewrite_pkt(ctx, &d);

	return ret;
}

const char _mode[] = "if_rules,gtp_fwd";
char _license[] SEC("license") = "GPL";
