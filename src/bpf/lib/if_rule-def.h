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
	__u32 table;
	__u32 gre_remote;
	__u16 vlan_id;
} __attribute__((packed));
