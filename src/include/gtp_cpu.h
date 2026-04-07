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
#include "vty.h"

#define ETHTOOL_POLL_TICKS 15

struct gtp_percpu_metrics {
	uint32_t pfcp_sessions;		/* PFCP sessions on this CPU */
	float    load;			/* [0.0, 1.0] */

	/* ethtool queue metrics aggregated by CPU (via IRQ affinity) */
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t rx_xdp_drop;
	uint64_t rx_xdp_redirect;
	uint64_t rx_xdp_tx_xmit;
	uint64_t rx_xdp_tx_mpwqe;
	uint64_t rx_xdp_tx_inlnw;
	uint64_t rx_xdp_tx_nops;
	uint64_t rx_xdp_tx_full;
	uint64_t rx_xdp_tx_err;
	uint64_t rx_xdp_tx_cqes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t tx_stopped;
	uint64_t tx_dropped;
	uint64_t tx_xmit_more;
	uint64_t tx_xdp_xmit;
	uint64_t tx_xdp_mpwqe;
	uint64_t tx_xdp_inlnw;
	uint64_t tx_xdp_nops;
	uint64_t tx_xdp_full;
	uint64_t tx_xdp_err;
	uint64_t tx_xdp_cqes;

	/* BPF XDP counters (if_rule map, summed across all matching rules) */
	uint64_t bpf_pkt_in;
	uint64_t bpf_bytes_in;
	uint64_t bpf_pkt_fwd;

	/* traffic that bypassed XDP to the kernel network stack */
	uint64_t sys_rx_pkts;
};

/* Prototypes */
int gtp_cpu_init(void);
int gtp_cpu_destroy(void);
int gtp_cpu_show(struct vty *vty);
int gtp_cpu_matrix_show(struct vty *vty);
const struct gtp_percpu_metrics *gtp_percpu_metrics_get(int cpu);
