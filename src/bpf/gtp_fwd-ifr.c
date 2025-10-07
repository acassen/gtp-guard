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

#include "lib/gtp_fwd.h"


SEC("xdp")
int gtp_fwd_main(struct xdp_md *ctx)
{
	struct if_rule_data d = { .ctx = ctx };
	int action, ret;

	bpf_printk("hello world!\n");
	action = if_rule_parse_pkt(ctx, &d);
	if (action <= XDP_REDIRECT)
		return action;

	ret = gtpu_traffic_selector(&d);
	if (ret < 0)
		return XDP_DROP;

	return if_rule_rewrite_pkt(ctx, &d);

}

const char _mode[] = "if_rules,gtp_fwd-ifr";
char _license[] SEC("license") = "GPL";
