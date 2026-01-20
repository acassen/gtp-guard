/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"

#define UE_IPV4		(1 << 0)
#define UE_IPV6		(1 << 1)

struct upf_user_ingress_key {
	__u16		flags;
	__u16		_pad;
	union v4v6addr  ue_addr;
}  __attribute__((packed));

struct upf_user_ingress {
	__be32		teid;
	__be32		gtpu_remote_addr;
	__be32		gtpu_local_addr;
	__be16		gtpu_remote_port;
	__be16		gtpu_local_port;

	__u64 		packets;
	__u64 		bytes;
}  __attribute__((packed));


struct upf_user_egress_key {
	__be32		teid;
	__be32		gtpu_remote_addr;
	__be16		gtpu_remote_port;
} __attribute__((packed));

struct upf_user_egress {
	__u64 		packets;
	__u64 		bytes;
}  __attribute__((packed));


#define RULE_FL_ACT_FWD		(1 << 0)
#define RULE_FL_ACT_BUFF	(1 << 1)
#define RULE_FL_ACT_DROP	(1 << 2)
#define RULE_FL_ACT_DUPL	(1 << 3)
#define RULE_FL_ACT_GTPU_ENCAP	(1 << 4)
#define RULE_FL_ACT_GTPU_DECAP	(1 << 5)
#define RULE_FL_INGRESS		(1 << 6)
#define RULE_FL_EGRESS		(1 << 7)

struct upf_fwd_rule {
	__be32		remote_teid;
	__be32		gtpu_remote_addr;
	__be32		gtpu_local_addr;
	__be16		gtpu_remote_port;
	__be16		gtpu_local_port;

	__u64 		fwd_pkts;
	__u64 		fwd_bytes;
	__u64 		drop_pkts;
	__u64 		drop_bytes;

	__u32		mbr;

	__u8		tos_tclass;
	__u8		tos_mask;

	__u16		flags;
}  __attribute__((packed));
