/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC		1000000000ULL
#endif

#define FLOW_DEFAULT_TIMEOUT	(120 * NSEC_PER_SEC)

union flow_timeout_config
{
	__u16 udp;
	struct {
		__u16 tcp_synfin;
		__u16 tcp_est;
	};
} __attribute__((packed));
