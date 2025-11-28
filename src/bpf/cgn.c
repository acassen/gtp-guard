/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include "lib/if_rule.h"
#include "lib/cgn.h"

/*
 * caution: CGN drops all trafic that isn't forwarded.
 *          nothing is sent back to kernel.
 *          do not set it up on your administrative interface.
 */

SEC("xdp")
int cgn_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = { };
	int action, ret;

	/* phase 1: parse interface encap */
	action = if_rule_parse_pkt(ctx, &d, NULL);

	/* phase 2: execute action */
	if (action == XDP_IFR_DEFAULT_ROUTE) {
		ret = cgn_pkt_handle(ctx, &d, 2);
		if (hit_bug || ret < 0) {
			hit_bug = 0;
			return XDP_ABORTED;
		}
		if (ret == 0)
			action = XDP_IFR_FORWARD;
		else
			action = XDP_DROP;
	}

	/* phase 3: rewrite interface encap */
	if (action == XDP_IFR_FORWARD)
		return if_rule_rewrite_pkt(ctx, &d);

	return action;
}


const char _mode[] = "if_rules,cgn";
char _license[] SEC("license") = "GPL";
