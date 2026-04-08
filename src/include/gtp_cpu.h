/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <stdint.h>
#include "ethtool.h"
#include "vty.h"

#define ETHTOOL_POLL_TICKS 15		/* 3seconds */

struct gtp_percpu_metrics {
	uint32_t		pfcp_sessions;		/* PFCP sessions on this CPU */
	float			load;			/* [0.0, 1.0] */

	/*
	 * Accumulation fields: zeroed before each ethtool tick.
	 */
	struct ethtool_q_stats	q_stats;

	/*
	 * Persistent fields: survive across ticks.
	 * Rate estimates derived from q_stats deltas.
	 */
	uint64_t		rx_bw_bps;
	uint64_t		tx_bw_bps;
	uint64_t		rx_pps;
	uint64_t		tx_pps;
	uint64_t		prev_rx_bytes;
	uint64_t		prev_tx_bytes;
	uint64_t		prev_rx_packets;
	uint64_t		prev_tx_packets;
};

/* Prototypes */
int gtp_cpu_init(void);
int gtp_cpu_destroy(void);
int gtp_cpu_show(struct vty *vty);
int gtp_cpu_matrix_show(struct vty *vty);
const struct gtp_percpu_metrics *gtp_percpu_metrics_get(int cpu);
void gtp_cpu_register_pfcp_count(int (*fn)(int cpu));
