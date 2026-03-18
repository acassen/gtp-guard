/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"
#include "if_rule-def.h"

/*
 * this is an optional way to add custom data to if_rule key: define
 * if_rule_key, IF_RULE_CUSTOM_KEY, and add a parser function to
 * if_rule_data.
 */
#ifndef IF_RULE_CUSTOM_KEY
struct if_rule_key
{
	struct if_rule_key_base b;
} __attribute__((packed));
#endif


struct if_rule_data;
typedef int (*rule_selector_t)(struct if_rule_data *d, struct iphdr *iph);

#define IF_RULE_FL_SRC_IPV6		0x0001
#define IF_RULE_FL_DST_IPV6		0x0002
#define IF_RULE_FL_XDP_ADJUSTED		0x0004

struct if_rule_data
{
	struct if_rule_key	k;
	struct if_rule		*r;
	__u16			flags;
	__u16			pl_off;
	__u16			cap_entries[3];
	__u16			cap_len[3];
	union v4v6addr		dst_addr;
};
