/* SPDX-License-Identifier: AGPL-3.0-or-later */


#include "lib/if_rule.h"
#include "lib/mape.h"


/*
 * standalone MAPE BR. only used as test program
 */

SEC("xdp")
int mape_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = { };
	int action;

	action = if_rule_parse_pkt(ctx, &d);
	if (action <= XDP_REDIRECT)
		return action;

	if (action == XDP_IFR_DEFAULT_ROUTE) {
		if (d.flags & IF_RULE_FL_SRC_IPV6)
			action = mape_decap(ctx, &d);
		else
			action = mape_encap(ctx, &d);
	}

	if (action == XDP_IFR_FORWARD)
		return if_rule_rewrite_pkt(ctx, &d);

	return action;
}

const char _mode[] = "if_rules,mape";

char _license[] SEC("license") = "GPL";
