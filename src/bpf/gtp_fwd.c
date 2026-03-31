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

const char _mode[] = "if_rules,gtp_fwd";
char _license[] SEC("license") = "GPL";
