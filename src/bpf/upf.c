/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include "lib/if_rule.h"
#include "lib/cgn.h"
#include "lib/upf.h"

/*
 * sample file. does not compile (yet).
 */

SEC("xdp")
int upf_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = {};
	int action, ret;

	/* phase 1: parse interface encap */
	action = if_rule_parse_pkt(ctx, &d);
	if (action <= XDP_REDIRECT)
		return action;

	/* phase 2: execute action */
	if (action == 10) {
		/* packet from private-network. gtp(upf) then nat(cgn) */
		ret = upf_pkt_handle(ctx, &d);
		if (ret == 0)
			ret = cgn_pkt_handle(ctx, d.payload, 1);

	} else if (action == 11) {
		/* packet from public-network. nat(cgn) then gtp(upf) */
		ret = cgn_pkt_handle(ctx, d.payload, 0);
		if (ret == 0)
			ret = upf_pkt_handle(ctx, &d, 1);

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

/* inherit from these 3 modes */
const char *_mode = "if_rules,cgn,upf";

char _license[] SEC("license") = "GPL";
