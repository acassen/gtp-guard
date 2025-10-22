/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "if_rule-def.h"

#define IPTNL_FL_TRANSPARENT_EGRESS_ENCAP	(1 << 1)
#define IPTNL_FL_DPD				(1 << 3)
#define IPTNL_FL_DEAD				(1 << 4)

#define IF_RULE_CUSTOM_KEY
struct if_rule_key
{
	struct if_rule_key_base b;	/* mandatory field */
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));
