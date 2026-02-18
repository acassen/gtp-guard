/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

struct mape_bmr
{
	struct in6_addr		br_addr;
	struct in6_addr		v6_prefix;
	__u32			v4_suffix_mask;
	__u8			v4_suffix_bits;
	__u8			psid_bits;
};
