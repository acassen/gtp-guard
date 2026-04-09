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

#include <stdbool.h>
#include <stdint.h>
#include <linux/ethtool.h>


/*
 * PHY & QUEUE stats we care about.
 */
/* Physical NIC stats from ethtool -S (*_phy counters) */
#define N_PHY_STATS      18
struct ethtool_phy_stats {
	uint64_t	tx_packets;
	uint64_t	rx_packets;
	uint64_t	tx_bytes;
	uint64_t	rx_bytes;
	uint64_t	rx_discards;
	uint64_t	tx_discards;
	uint64_t	tx_errors;
	uint64_t	rx_out_of_buffer;
	/* rx frame-size histogram */
	uint64_t	rx_64;
	uint64_t	rx_65_127;
	uint64_t	rx_128_255;
	uint64_t	rx_256_511;
	uint64_t	rx_512_1023;
	uint64_t	rx_1024_1518;
	uint64_t	rx_1519_2047;
	uint64_t	rx_2048_4095;
	uint64_t	rx_4096_8191;
	uint64_t	rx_8192_10239;
};

/* Per-queue stats from ethtool -S (rx{N}_* / tx{N}_* counters) */
#define N_QUEUE_RX_STATS 12
#define N_QUEUE_TX_STATS 12
#define N_QUEUE_STATS    (N_QUEUE_RX_STATS + N_QUEUE_TX_STATS)
struct ethtool_q_stats {
	/* RX */
	uint64_t	rx_packets;
	uint64_t	rx_bytes;
	uint64_t	rx_xdp_drop;
	uint64_t	rx_xdp_redirect;
	uint64_t	rx_xdp_tx_xmit;
	uint64_t	rx_xdp_tx_mpwqe;
	uint64_t	rx_xdp_tx_inlnw;
	uint64_t	rx_xdp_tx_nops;
	uint64_t	rx_xdp_tx_full;
	uint64_t	rx_xdp_tx_err;
	uint64_t	rx_xdp_tx_cqes;
	uint64_t	rx_buff_alloc_err;
	/* TX */
	uint64_t	tx_packets;
	uint64_t	tx_bytes;
	uint64_t	tx_stopped;
	uint64_t	tx_dropped;
	uint64_t	tx_xmit_more;
	uint64_t	tx_xdp_xmit;
	uint64_t	tx_xdp_mpwqe;
	uint64_t	tx_xdp_inlnw;
	uint64_t	tx_xdp_nops;
	uint64_t	tx_xdp_full;
	uint64_t	tx_xdp_err;
	uint64_t	tx_xdp_cqes;
};


/*
 * Per-interface ethtool stats cache.
 * Built once at first collect; thereafter a single ETHTOOL_GSTATS ioctl
 * suffices to refresh all values via pre-resolved stat indices.
 */
struct ethtool_cache {
	int			fd;		/* persistent ethtool socket */
	uint32_t		nstats;		/* total driver stat count */
	struct ethtool_stats	*stats;		/* persistent GSTATS buffer */
	int			*phy_idx;	/* [n_phy]                    */
	int			*q_idx;		/* [nr_queues * n_per_queue]  */
	uint32_t		n_phy;
	uint32_t		n_per_queue;	/* n_rx + n_tx per queue      */
	uint32_t		nr_queues;
};

/* Return the stat value at pre-resolved index idx, or 0 if not found. */
static inline uint64_t
ethtool_gstats_val(const struct ethtool_cache *c, int idx)
{
	return (idx >= 0) ? c->stats->data[idx] : 0;
}

/* Accumulate all uint64_t fields from src into dst */
static inline void
ethtool_q_stats_add(struct ethtool_q_stats *dst, const struct ethtool_q_stats *src)
{
	const uint64_t *s = (const uint64_t *)src;
	uint64_t *d = (uint64_t *)dst;
	int i;

	for (i = 0; i < sizeof(*dst) / sizeof(uint64_t); i++)
		d[i] += s[i];
}

/* Prototypes */
int sysfs_set_iface_forwarding(const char *ifname, bool ipv4, bool ipv6);
int ethtool_get_nr_queues(const char *ifname, uint32_t *rx, uint32_t *tx);
int ethtool_gstats_cache_init(struct ethtool_cache **out,
			      const char *ifname,
			      uint32_t nr_queues);
int  ethtool_gstats_fetch(struct ethtool_cache *c, const char *ifname);
void ethtool_gstats_cache_destroy(struct ethtool_cache *c);
