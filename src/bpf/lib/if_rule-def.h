/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

struct if_rule_key
{
	int ifindex;
	__u32 gre_remote;
	__u16 vlan_id;
} __attribute__((packed));

struct if_rule
{
	int action;
	int ifindex;
	__u32 gre_remote;
	__u16 vlan_id;
	__u8 h_local[ETH_ALEN];
	__u8 h_remote[ETH_ALEN];
};
