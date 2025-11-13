/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"
#include "if_rule-def.h"

/* as an example */
struct pfcp_teid_rule {
	__be32		teid;
	__be32		dst_addr;

	/* Some stats */
	__u64 		packets;
	__u64 		bytes;
};
