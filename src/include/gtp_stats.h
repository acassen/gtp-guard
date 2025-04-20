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

#ifndef _GTP_STATS_H
#define _GTP_STATS_H

/* Statistics */
typedef struct _gtp_counter {
	uint32_t		count;
	uint32_t		unsupported;
} gtp_counter_t;

typedef struct _gtp_stats_msg {
	gtp_counter_t		rx[0xff];
	gtp_counter_t		tx[0xff];
} gtp_stats_msg_t;

typedef struct _gtp_stats_cause {
	uint32_t		cause[0xff];
} gtp_stats_cause_t;

typedef struct _gtp_stats_pkt {
	uint64_t		bytes;
	uint64_t		pkts;
} gtp_stats_pkt_t;


/* Prototypes */
extern int gtp_stats_rx(gtp_stats_msg_t *, uint8_t);
extern int gtp_stats_rx_notsup(gtp_stats_msg_t *, uint8_t);
extern int gtp_stats_tx(gtp_stats_msg_t *, uint8_t);
extern int gtp_stats_tx_notsup(gtp_stats_msg_t *, uint8_t);
extern int gtp_stats_pkt_update(gtp_stats_pkt_t *, ssize_t);
extern int gtp_stats_cause_update(gtp_stats_cause_t *, pkt_buffer_t *);

#endif
