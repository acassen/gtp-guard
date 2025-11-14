/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"
#include "if_rule-def.h"

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
	__be16		gtpu_remote_port;
	__u16		_pad[3];

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

