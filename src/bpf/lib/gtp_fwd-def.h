/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "if_rule-def.h"


#define XDP_GTPFWD_GTPU_XLAT	10
#define XDP_GTPFWD_GTPU_NOXLAT	11
#define XDP_GTPFWD_TUN_XLAT	12
#define XDP_GTPFWD_TUN_NOXLAT	13

#define IF_RULE_CUSTOM_KEY
struct if_rule_key
{
	struct if_rule_key_base b;	/* mandatory field */
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));
