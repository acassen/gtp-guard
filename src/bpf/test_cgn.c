/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include "lib/if_rule.h"
#include "lib/cgn.h"

/*
 * this is a test/playground bpf program
 */


/*
 * map to test bpf-prog reload
 */
struct test_key
{
	int i;
	int j;
	int k;
};

struct test
{
	char v[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct test_key);
	__type(value, struct test);
} test_map SEC(".maps");


/*
 * block allocation/release log test
 */
#if 0
/* declared in lib/cgn.h */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 15000);
	__type(value, struct cgn_v4_block_log);
} v4_block_log_queue SEC(".maps");
#endif

static void push_log()
{
	struct cgn_v4_block_log s = {
		.prefix = "cmg-toto",
		.cgn_addr = 0x01010101,
		.priv_addr = 0x0a000001,
		.duration = 500,
		.port_start = 1500,
		.port_size = 50,
		.flag = CGN_BLOG_FL_ALLOC,
	};

	bpf_map_push_elem(&v4_block_log_queue, &s, 0);
	bpf_map_push_elem(&v4_block_log_queue, &s, 0);
	bpf_map_push_elem(&v4_block_log_queue, &s, 0);
}

SEC("xdp")
int test_block_log(struct xdp_md *ctx)
{
	push_log();

	return XDP_PASS;
}



SEC("xdp")
int xdp_entry_1(struct xdp_md *ctx)
{
	struct if_rule_data d = {};
	int action, ret;

	/* phase 1: parse interface encap */
	action = if_rule_parse_pkt(ctx, &d);
	if (action <= XDP_REDIRECT)
		return action;

	/* phase 3: rewrite interface encap */
	return if_rule_rewrite_pkt(ctx, &d);
}

SEC("xdp")
int cgn_test_flow(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct cgn_packet *cp = data;
	int ret;

	if (data + sizeof (*cp) > data_end)
		return XDP_ABORTED;

	if (cp->from_priv)
		ret = cgn_flow_handle_priv(cp);
	else
		ret = cgn_flow_handle_pub(cp);
	if (hit_bug) {
		hit_bug = 0;
		return -1;
	}
	return ret;
}


SEC("xdp")
int cgn_test_pkt(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	int ret;

	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return XDP_PASS;

	if ((void *)((struct iphdr *)(eth + 1) + 1) > data_end)
		return 1;

	struct if_rule_data ifd = {
		.pl_off = sizeof (*eth),
	};

	ret = cgn_pkt_handle(ctx, &ifd, eth->h_dest[5]);
	if (hit_bug || ret < 0) {
		hit_bug = 0;
		return XDP_ABORTED;
	}
	if (ret > 0)
		return XDP_DROP;
	return XDP_PASS;
}


SEC("tcx/ingress")
int tc_entry_1(struct __sk_buff *ctx)
{
#if 0
	/* valid code that won't please kernel valider */
	struct test_key k = { .i = 1 };
	struct test *t = bpf_map_lookup_elem(&test_map, &k);
	if (t != NULL)
		t->v[5] = 'a';
#endif

	bpf_printk("tc entry 6!!");
	return XDP_PASS;
}


const char _mode[] = "if_rules,cgn";
char _license[] SEC("license") = "GPL";
