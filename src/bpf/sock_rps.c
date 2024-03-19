/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

#define KBUILD_MODNAME "sock_rps"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <uapi/linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include "gtp.h"


/*
 *	MAPs
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct rps_opts);
} socket_filter_opts SEC(".maps");


/*
 *	Hash function
 */
static __always_inline __u32
eth_hash(const __u8 *hw, const int size)
{
	__u32 hash = 0;
	int i = 0;

	while (i < size)
		hash = (hash << 8) | hw[i++];
	return hash;
}

SEC("socket")
int sock_rps(struct __sk_buff *skb)
{
	struct rps_opts *opts;
	int idx = 0;
	__u8 hw_dst[ETH_ALEN];
	__u32 hkey;

	opts = bpf_map_lookup_elem(&socket_filter_opts, &idx);
	if (!opts)
		return 0;

	/* "Direct Packet Access" via sock_filter just have limited support
	 * for security reasons since most of sock_filter are mostly run in
	 * unprivileged env. So we need to load at least hw_dst in context.
	 * Tested with CAP_BPF|CAP_PERFMON which didnt enable DPA :/
	 */
	bpf_skb_load_bytes(skb, 0, &hw_dst, ETH_ALEN);
	hkey = eth_hash(hw_dst, ETH_ALEN) & (opts->max_id - 1);

	return (hkey == opts->id) ? skb->len : 0;
}

char _license[] SEC("license") = "GPL";
