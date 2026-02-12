/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"

#define UE_IPV4		(1 << 0)
#define UE_IPV6		(1 << 1)

struct upf_ingress_key {
	__u16		flags;
	__u16		_pad;
	union v4v6addr  ue_addr;
}  __attribute__((packed));

struct upf_egress_key {
	__be32		gtpu_local_teid;
	__be32		gtpu_local_addr;
	__be16		gtpu_local_port;
} __attribute__((packed));

#define UPF_FWD_FL_ACT_FWD			(1 << 0)
#define UPF_FWD_FL_ACT_BUFF			(1 << 1)
#define UPF_FWD_FL_ACT_DROP			(1 << 2)
#define UPF_FWD_FL_ACT_DUPL			(1 << 3)
#define UPF_FWD_FL_ACT_CREATE_OUTER_HEADER	(1 << 4)
#define UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER	(1 << 5)
#define UPF_FWD_FL_INGRESS			(1 << 6)
#define UPF_FWD_FL_EGRESS			(1 << 7)
struct upf_fwd_rule {
	__be32		gtpu_remote_teid;
	__be32		gtpu_remote_addr;
	__be32		gtpu_local_addr;
	__be16		gtpu_remote_port;
	__be16		gtpu_local_port;

	__u64 		fwd_packets;
	__u64 		fwd_bytes;
	__u64 		drop_packets;
	__u64 		drop_bytes;

	__u32		ul_mbr;
	__u32		dl_mbr;

	__u8		tos_tclass;
	__u8		tos_mask;

	__u16		flags;
}  __attribute__((packed));
