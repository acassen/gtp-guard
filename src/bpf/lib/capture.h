/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "tools.h"
#include "capture-def.h"


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 16);	/* XXX: set to max cpu before load */
	__type(key, int);
	__type(value, __u32);
} capture_perf_map SEC(".maps");


static inline void
capture_xdp_to_userspc(struct xdp_md *ctx, int action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct capture_metadata md;

	if (data >= data_end)
		return;

	md.ifindex = ctx->ingress_ifindex;
	md.rx_queue = ctx->rx_queue_index;
	md.pkt_len = (__u16)(data_end - data);
	md.cap_len = min(md.pkt_len, 64);
	md.action = action;

	bpf_perf_event_output(ctx, &capture_perf_map,
			      ((__u64) md.cap_len << 32) | BPF_F_CURRENT_CPU,
			      &md, sizeof(md));
}
