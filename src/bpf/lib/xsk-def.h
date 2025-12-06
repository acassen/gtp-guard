/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

/*
 * metadata used to keep information for packet recirculation:
 *   BPF RX (on nic) -(1)-> AF_XDP RX -> AF_XDP TX -(2)-> BPF RX (on veth)
 *
 * (1) transmitted as metadata (see xsk_to_userspace())
 * (2) transmitted by including in packet payload (increase headroom) on AF_XDP side,
 *     then read them adn remove headroom on XDP RX veth hook.
 *     using tx_metadata don't work because it targets is tx device driver, not
 *     some element further in network stack.
 */
struct gtp_xsk_metadata
{
	__u32		table_id;
	__u8		data_len;	/* must align to 4 bytes */
	__u8		_unused[3];
	__u8		data[];
} __attribute__((packed));
