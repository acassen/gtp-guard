/* SPDX-License-Identifier: AGPL-3.0-or-later */


#include "lib/if_rule.h"
#include "lib/upf.h"
#include "lib/cgn.h"


/*
 * combined UPF + CGN
 */


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = { };
	int action, ret = 0;

	/* phase 1: from interface */
	action = if_rule_parse_pkt(ctx, &d);

	/* phase 2: execute action */
	if (action == XDP_IFR_DEFAULT_ROUTE) {
		if (d.flags & IF_RULE_FL_SRC_IPV6) {
			/* ipv6 do not pass through cgn */
			action = upf_handle_pubv6(ctx, &d);
			goto phase3;
		}

		/* try if this is an opened flow from pub */
		switch (cgn_pkt_handle(ctx, &d, 0)) {
		case 0:
			/* yes, now encap */
			action = upf_handle_pub(ctx, &d);
			break;
		case 10:
			/* no, it may be a gtp-u tunnel  */
			action = upf_handle_gtpu(ctx, &d);
			if (action == XDP_IFR_FORWARD) {
				/* yes it was. ipv6 goes untranslated */
				if (d.flags & IF_RULE_FL_DST_IPV6)
					goto phase3;

				/* and ipv4 goes through cgn */
				ret = cgn_pkt_handle(ctx, &d, 1);
				if (ret == 0)
					action = XDP_IFR_FORWARD;
				else if (ret == 2)
					return XDP_REDIRECT;
				else
					action = XDP_DROP;
			}
			break;
		default:
			return XDP_DROP;
		}
	}

 phase3:
	/* phase 3: rewrite to dst interface */
	if (action == XDP_IFR_FORWARD)
		return if_rule_rewrite_pkt(ctx, &d);

	return action;
}


/* called from userspace after cgn flow creation */
SEC("xdp")
int cgn_xsk(struct xdp_md *ctx)
{
	struct gtp_xsk_metadata md;
	struct if_rule_data d = { };
	int action, ret;

	if (xsk_from_userspace(ctx, &md, NULL, NULL) < 0)
		return XDP_DROP;

	action = if_rule_parse_pkt(ctx, &d);
	if (action == XDP_IFR_DEFAULT_ROUTE) {
		ret = cgn_pkt_handle(ctx, &d, 1);
		if (ret == 0)
			return if_rule_rewrite_pkt(ctx, &d);
	}

	return action;
}



const char _mode[] = "if_rules,xsks,cgn,upf";

char _license[] SEC("license") = "GPL";
