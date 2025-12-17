/* SPDX-License-Identifier: AGPL-3.0-or-later */


#include "lib/if_rule.h"
#include "lib/upf.h"

/*
 * solo UPF
 */

SEC("xdp")
int upf_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = { };
	int action;

	/* phase 1: get from interface */
	action = if_rule_parse_pkt(ctx, &d);
	if (action <= XDP_REDIRECT)
		return action;

	/* phase 2: execute action */
	if (action == XDP_IFR_DEFAULT_ROUTE)
		action = upf_traffic_selector(ctx, &d);

	/* phase 3: rewrite to dst interface */
	if (action == XDP_IFR_FORWARD)
		return if_rule_rewrite_pkt(ctx, &d);

	return action;
}

const char _mode[] = "if_rules,upf";

char _license[] SEC("license") = "GPL";
