/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "xsk-def.h"
#include "if_rule.h"


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 256);
} xsks_base SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 256);
} xsks SEC(".maps");


/*
 * redirect packet being processed to userspace
 */
static __always_inline int
xsk_to_userspace(struct xdp_md *ctx, struct if_rule_data *d,
		 const void *udata, __u8 size)
{
	struct gtp_xsk_metadata *xmd;
	__u32 index;
	void *data;
	int xlen, ret;

	index = ctx->ingress_ifindex;
	__u32 *base = bpf_map_lookup_elem(&xsks_base, &index);
	if (base == NULL)
		return -1;
	index = *base + ctx->rx_queue_index;

	/* reserve space for metadata */
	xlen = sizeof(*xmd) + size;
	if (bpf_xdp_adjust_meta(ctx, -xlen))
		return -1;

	/* bpf_printk("xsk_to_userspace index %u xlen:%d", index, xlen); */

	/* verify meta area is accessible */
	data = (void *)(unsigned long)ctx->data;
	xmd = (void *)(unsigned long)ctx->data_meta;
	if ((void *)(xmd) + xlen > data)
		return 1;

	xmd->_unused[0] = 0;
	xmd->_unused[1] = 0;
	xmd->_unused[2] = 0;
	xmd->data_len = size;
	__builtin_memcpy(xmd->data, udata, size);

	if (bpf_map_lookup_elem(&xsks, &index)) {
		/* bpf_printk("redirect to xsks index %d", index); */
		if (bpf_redirect_map(&xsks, index, 0) == XDP_REDIRECT)
			return 0;
	} else {
		bpf_printk("xsks index %d is WRONG", index);
	}

	return -1;
}


/*
 * packet coming from userspace, readjust packet size
 */
static __always_inline int
xsk_from_userspace(struct xdp_md *ctx, struct gtp_xsk_metadata *out_md,
		   void *out_data, __u32 *out_data_len)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct gtp_xsk_metadata *md = data;
	int xlen;

	/* retrieve 'metadata' */
	if ((void *)(md + 1) > data_end)
		return -1;

	xlen = sizeof (*md) + md->data_len;

	/* copy meta if requested */
	if (out_md != NULL)
		*out_md = *md;
	if (out_data != NULL) {
		__builtin_memcpy(out_data, md + 1, md->data_len);
		if (out_data_len != NULL)
			*out_data_len = md->data_len;
	}

	/* restore packet */
	if (bpf_xdp_adjust_head(ctx, xlen) < 0)
		return -1;
	return 0;
}
