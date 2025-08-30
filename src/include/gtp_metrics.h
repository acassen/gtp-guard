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
#pragma once

#include <stdint.h>
#include <sys/types.h>
#include "pkt_buffer.h"

/* defines */
#define GTP_METRIC_MAX_MSG	(1 << 8)
#define METRIC_PACKET		0
#define METRIC_BYTE		1

/* types */
typedef struct gtp_metric {
	uint32_t		count;
	uint32_t		unsupported;
} gtp_metric_t;

typedef struct gtp_metrics_msg {
	gtp_metric_t		rx[GTP_METRIC_MAX_MSG];
	gtp_metric_t		tx[GTP_METRIC_MAX_MSG];
} gtp_metrics_msg_t;

typedef struct gtp_metrics_cause {
	uint32_t		cause[GTP_METRIC_MAX_MSG];
} gtp_metrics_cause_t;

typedef struct gtp_metrics_pkt {
	uint64_t		count;
	uint64_t		bytes;
} gtp_metrics_pkt_t;


/* Prototypes */
int gtp_metrics_rx(gtp_metrics_msg_t *, uint8_t);
int gtp_metrics_rx_notsup(gtp_metrics_msg_t *, uint8_t);
int gtp_metrics_tx(gtp_metrics_msg_t *, uint8_t);
int gtp_metrics_tx_notsup(gtp_metrics_msg_t *, uint8_t);
int gtp_metrics_pkt_update(gtp_metrics_pkt_t *, ssize_t);
int gtp_metrics_cause_update(gtp_metrics_cause_t *, pkt_buffer_t *);
int gtp_metrics_init(void);
int gtp_metrics_destroy(void);
