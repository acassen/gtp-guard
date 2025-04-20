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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

/* local includes */
#include "gtp_guard.h"


/*
 *	Utilities
 */

/* FIXME: maybe inline this */
int
gtp_stats_rx(gtp_stats_msg_t *stats, uint8_t msg_type)
{
	stats->rx[msg_type].count++;
	return 0;
}

int
gtp_stats_rx_notsup(gtp_stats_msg_t *stats, uint8_t msg_type)
{
	stats->rx[msg_type].unsupported++;
	return 0;
}

int
gtp_stats_tx(gtp_stats_msg_t *stats, uint8_t msg_type)
{
	stats->tx[msg_type].count++;
	return 0;
}

int
gtp_stats_tx_notsup(gtp_stats_msg_t *stats, uint8_t msg_type)
{
	stats->tx[msg_type].unsupported++;
	return 0;
}

int
gtp_stats_pkt_update(gtp_stats_pkt_t *pstats, ssize_t nbytes)
{
	if (nbytes <= 0)
		return -1;

	pstats->bytes += nbytes;
	pstats->pkts++;
	return 0;
}

int
gtp_stats_cause_update(gtp_stats_cause_t *cstats, pkt_buffer_t *pbuff)
{
	gtp_ie_cause_t *ie_cause;
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, pbuff);
	if (!cp)
		return -1;

	ie_cause = (gtp_ie_cause_t *) cp;
	cstats->cause[ie_cause->value]++;
	return 0;
}
