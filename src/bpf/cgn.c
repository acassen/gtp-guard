/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include "lib/if_rule.h"
#include "lib/cgn.h"


SEC("xdp")
int cgn_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = {};
	int action, ret;

	/* phase 1: parse interface encap */
	action = if_rule_parse_pkt(ctx, &d);
	if (action <= XDP_REDIRECT)
		return action;

	/* phase 2: execute action */
	if (action == 10) {
		/* packet from private-network */
		ret = cgn_pkt_handle(ctx, &d, 1);

	} else if (action == 11) {
		/* packet from public-network */
		ret = cgn_pkt_handle(ctx, &d, 0);

	} else {
		/* not expected */
		return XDP_PASS;
	}
	if (hit_bug || ret < 0) {
		hit_bug = 0;
		return XDP_ABORTED;
	}
	if (ret != 0)
		return XDP_DROP;

	/* phase 3: rewrite interface encap */
	return if_rule_rewrite_pkt(ctx, &d);
}


const char _mode[] = "if_rules,cgn";
char _license[] SEC("license") = "GPL";
