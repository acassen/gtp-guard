/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include "lib/if_rule.h"
#include "lib/cgn.h"

/*
 * caution: CGN drops all trafic that isn't forwarded.
 *          nothing is sent back to kernel.
 *          do not set it up on your administrative interface.
 */


static int __always_inline
cgn_do(struct xdp_md *ctx, struct if_rule_data *d, int action)
{
	int ret;

	if (action == XDP_IFR_DEFAULT_ROUTE)
		ret = cgn_pkt_handle(ctx, d, 2);
	else if (action == XDP_CGN_FROM_PRIV)
		ret = cgn_pkt_handle(ctx, d, 1);
	else if (action == XDP_CGN_FROM_PUB)
		ret = cgn_pkt_handle(ctx, d, 0);
	else
		return action;

	if (ret == 0)
		return if_rule_rewrite_pkt(ctx, d);
	if (ret == 2)
		return XDP_REDIRECT;
	return XDP_DROP;
}


SEC("xdp")
int cgn_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = { };
	int action;

	action = if_rule_parse_pkt(ctx, &d);
	return cgn_do(ctx, &d, action);
}

SEC("xdp")
int cgn_xsk(struct xdp_md *ctx)
{
	struct gtp_xsk_metadata md;
	struct if_rule_data d = { };
	int action;

	if (xsk_from_userspace(ctx, &md, NULL, NULL) < 0)
		return XDP_DROP;

	action = if_rule_parse_pkt(ctx, &d);
	return cgn_do(ctx, &d, action);
}

/* for test purpose */
SEC("xdp")
int xdp_tx_pkt_gen(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethh = data;
	struct iphdr *ip4h = (struct iphdr *)(ethh + 1);
	struct udphdr *udph = (struct udphdr *)(ip4h + 1);
	static __u16 srcp_next;

	if ((void *)(udph + 1) > data_end)
		return XDP_DROP;

	udph->source = bpf_htons(++srcp_next);

	return XDP_TX;
	//return bpf_redirect(ctx->ingress_ifindex, 0);
}


const char _mode[] = "if_rules,xsks,cgn";
char _license[] SEC("license") = "GPL";
