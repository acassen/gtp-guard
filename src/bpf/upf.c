/* SPDX-License-Identifier: AGPL-3.0-or-later */


#include "lib/if_rule.h"
#include "lib/upf.h"

/*
 * solo UPF
 */

SEC("xdp")
int upf_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = { .ctx = ctx };
	int action;

	/* phase 1: parse interface encap */
	action = if_rule_parse_pkt(&d, NULL);
	if (action <= XDP_REDIRECT)
		return action;

	/* phase 2: execute action */
	if (action == XDP_ACTION_FROM_INGRESS) {
		action = upf_handle_gtpu(&d);

	} else if (action == XDP_ACTION_FROM_EGRESS) {
		action = upf_handle_pub(&d);

	} else {
		/* not expected */
		action = XDP_PASS;
	}

	/* phase 3: rewrite interface encap */
	if (action == 10)
		return if_rule_rewrite_pkt(&d);

	return action;
}

const char _mode[] = "if_rules,upf";

char _license[] SEC("license") = "GPL";
