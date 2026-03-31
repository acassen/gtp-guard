/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "tools.h"
#include "capture-def.h"
#include "if_rule-priv.h"


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 16);	/* XXX: set to max cpu before load */
	__type(key, int);
	__type(value, __u32);
} capture_perf_map SEC(".maps");


static __always_inline void
capture_xdp_to_userspc(struct xdp_md *ctx, void *data, void *data_end,
		       __u16 entry_id, __u16 cap_len, __u16 dir_fl)
{
	struct capture_metadata md;

	md.ifindex = ctx->ingress_ifindex;
	md.rx_queue = ctx->rx_queue_index;
	md.pkt_len = (__u16)(data_end - data);
	md.cap_len = min(md.pkt_len, cap_len);
	md.entry_id = entry_id;
	md.flags = dir_fl;
	md.action = 0;

	bpf_perf_event_output(ctx, &capture_perf_map,
			      ((__u64) md.cap_len << 32) | BPF_F_CURRENT_CPU,
			      &md, sizeof(md));
}


static __always_inline void
capture_xdp_to_userspc_in(struct xdp_md *ctx, struct capture_bpf_entry *e, __u16 dir_fl)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct capture_metadata md;

	if (!e->entry_id || (dir_fl & e->flags) != dir_fl)
		return;

	if (data >= data_end)
		return;

	capture_xdp_to_userspc(ctx, data, data_end, e->entry_id, e->cap_len, dir_fl);
}

static __always_inline void
capture_xdp_to_userspc_out(struct if_rule_data *d, struct capture_bpf_entry *e, __u16 dir_fl)
{
	int i;

	if (!e->entry_id || (dir_fl & e->flags) != dir_fl)
		return;
#pragma unroll
	for (i = 0; i < ARRAY_SIZE(d->cap_entries) && d->cap_entries[i]; i++)
		;
	if (i < ARRAY_SIZE(d->cap_entries)) {
		d->cap_entries[i] = e->entry_id;
		d->cap_len[i] = e->cap_len;
	}
}

