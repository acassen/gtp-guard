/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#define BPF_CAPTURE_EFL_INGRESS			0x0001
#define BPF_CAPTURE_EFL_EGRESS			0x0002
#define BPF_CAPTURE_EFL_BY_IFACE		0x0100

/* capture entries set by userspace */
struct capture_bpf_entry
{
	__u16		flags;
	__u16		entry_id;
	__u16		cap_len;
} __attribute__((packed));


/* metadata set by bpf before each captured packet */
struct capture_metadata
{
	__u32		ifindex;
	__u32		rx_queue;
	__u16		pkt_len;
	__u16		cap_len;
	__u16		flags;
	__u16		entry_id;
	int		action;
} __attribute__((packed));
