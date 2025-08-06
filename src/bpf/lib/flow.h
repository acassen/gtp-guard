/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

/*
 * common flow data/function for cgn or ip6fw
 */

#include "flow-def.h"


/*
 * flow timeout by port and protocol
 * bit 17: protocol: 0 (udp) or 1 (tcp)
 * lower 16 bits is port
 *
 * values are set from userspace on startup, read-only for bpf prg.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, union flow_timeout_config);
	__uint(max_entries, 1 << 17);
} flow_port_timeouts SEC(".maps");

/* icmp config */
const volatile __u64 icmp_timeout = FLOW_DEFAULT_TIMEOUT;


static inline __u64
flow_udp_timeout_ns(__u16 port)
{
	__u32 k = port;
	const union flow_timeout_config *v;

	v = bpf_map_lookup_elem(&flow_port_timeouts, &k);
	if (v != NULL)
		return v->udp * NSEC_PER_SEC;
	return FLOW_DEFAULT_TIMEOUT;
}

static inline __u64
flow_tcp_timeout_ns(__u16 port, __u8 state)
{
	__u32 k = (1 << 16) | port;
	const union flow_timeout_config *v;

	v = bpf_map_lookup_elem(&flow_port_timeouts, &k);
	if (v != NULL) {
		if (state == 1)
			return v->tcp_est * NSEC_PER_SEC;
		return v->tcp_synfin * NSEC_PER_SEC;
	}
	return FLOW_DEFAULT_TIMEOUT;
}

static inline __u64
flow_icmp_timeout_ns(void)
{
	return icmp_timeout;
}

static inline __u64
flow_timeout_ns(__u8 proto, __u16 port, __u8 state)
{
	switch (proto) {
	case IPPROTO_UDP:
		return flow_udp_timeout_ns(port);
	case IPPROTO_TCP:
		return flow_tcp_timeout_ns(port, state);
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	default:
		return flow_icmp_timeout_ns();
	}
}

/*
 * update tcp flow state. make it easy:
 *   0: init
 *   1: established, got syn+ack from pub
 *   2: fin or rst received from any side
 *
 * this flow will have bigger timeout in state 1 than in 0 or 2.
 */
static inline int
flow_update_priv_tcp_state(__u32 tcp_flags, __u8 *proto_state)
{
	if (tcp_flags & (TCP_FLAG_RST | TCP_FLAG_FIN)) {
		*proto_state = 2;
		return 1;
	}

	return 0;
}

static inline int
flow_update_pub_tcp_state(__u32 tcp_flags, __u8 *proto_state)
{
	if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) && *proto_state == 0) {
		/* got syn+ack, go to established */
		*proto_state = 1;
		return 1;

	} else if (tcp_flags & (TCP_FLAG_RST | TCP_FLAG_FIN)) {
		*proto_state = 2;
		return 1;
	}

	return 0;
}
