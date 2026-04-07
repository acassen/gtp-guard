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

#ifndef _ETHTOOL_H
#define _ETHTOOL_H

#include <stdbool.h>
#include <stdint.h>
#include <linux/ethtool.h>

/*
 * Per-interface ethtool stats cache.
 * Built once at first collect; thereafter a single ETHTOOL_GSTATS ioctl
 * suffices to refresh all values via pre-resolved stat indices.
 */
struct gtp_if_ethtool_cache {
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
ethtool_gstats_val(const struct gtp_if_ethtool_cache *c, int idx)
{
	return (idx >= 0) ? c->stats->data[idx] : 0;
}

/* Prototypes */
int sysfs_set_iface_forwarding(const char *ifname, bool ipv4, bool ipv6);
int ethtool_get_nr_queues(const char *ifname, uint32_t *rx, uint32_t *tx);
int ethtool_gstats_get(const char *ifname, const char * const *names,
		       uint64_t *out, int n);
int ethtool_gstats_cache_init(struct gtp_if_ethtool_cache **out,
			      const char *ifname,
			      const char * const *phy_names, int n_phy,
			      const char (*rx_fmt)[ETH_GSTRING_LEN], int n_rx,
			      const char (*tx_fmt)[ETH_GSTRING_LEN], int n_tx,
			      uint32_t nr_queues);
int  ethtool_gstats_fetch(struct gtp_if_ethtool_cache *c, const char *ifname);
void ethtool_gstats_cache_destroy(struct gtp_if_ethtool_cache *c);

#endif
