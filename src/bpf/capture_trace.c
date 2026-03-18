/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include "lib/capture.h"
#include <bpf_tracing.h>

/*
 * this bpf program is loaded separately from gtp_bpf_capture,
 * and is used to capture *all* incoming packets on interfaces where
 * associated gtp_bpf_prog is binded
 */

/* (re)definition of kernel data structures for use with BTF */
struct net_device {
	int ifindex;
} __attribute__((preserve_access_index));

struct xdp_rxq_info {
	struct net_device *dev;
	__u32 queue_index;
} __attribute__((preserve_access_index));

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	unsigned long handle;
	struct xdp_rxq_info *rxq;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct capture_bpf_entry);
	__uint(max_entries, 1);
} capture_prog_entry SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);			/* ifindex */
	__type(value, struct capture_bpf_entry);
	__uint(max_entries, 128);
} capture_iface_entries SEC(".maps");



static __always_inline void
capture_trace_to_userspc(struct xdp_buff *xdp, int action)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct capture_metadata md;
	struct capture_bpf_entry *e;
	int idx = 0;
	__u16 dir;

	if (data >= data_end)
		return;

	e = bpf_map_lookup_elem(&capture_prog_entry, &idx);
	if (e == NULL)
		return;

	dir = action == -1 ? BPF_CAPTURE_EFL_INPUT : BPF_CAPTURE_EFL_OUTPUT;

	md.ifindex = xdp->rxq->dev->ifindex;
	md.rx_queue = xdp->rxq->queue_index;
	md.pkt_len = (__u16)(data_end - data);
	md.flags = dir;
	md.action = action;

	/* capture all packets */
	if (e->entry_id && (dir & e->flags)) {
		md.cap_len = min(md.pkt_len, e->cap_len);
		md.entry_id = e->entry_id;
		bpf_xdp_output(xdp, &capture_perf_map,
			       ((__u64)md.cap_len << 32) | BPF_F_CURRENT_CPU,
			       &md, sizeof(md));
	}

	/* capture by iface. do lookup only if there are entries */
	if (e->flags & BPF_CAPTURE_EFL_BY_IFACE) {
		e = bpf_map_lookup_elem(&capture_iface_entries, &md.ifindex);
		if (e == NULL || !(dir & e->flags))
			return;

		md.cap_len = min(md.pkt_len, e->cap_len);
		md.entry_id = e->entry_id;
		bpf_xdp_output(xdp, &capture_perf_map,
			       ((__u64)md.cap_len << 32) | BPF_F_CURRENT_CPU,
			       &md, sizeof(md));
	}
}

/* usage of BPF_PROG is mandatory (else it must use BPF_CORE_READ and cie)
 * 'func' will be rewritten by real function name when attaching program */
SEC("fentry/func")
int BPF_PROG(entry_trace, struct xdp_buff *xdp)
{
	capture_trace_to_userspc(xdp, -1);
	return 0;
}

SEC("fexit/func")
int BPF_PROG(exit_trace, struct xdp_buff *xdp, int ret)
{
	capture_trace_to_userspc(xdp, ret);
	return 0;
}

char _license[] SEC("license") = "GPL";
