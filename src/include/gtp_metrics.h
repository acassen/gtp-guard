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
#include <sys/types.h>
#include "pkt_buffer.h"

/* defines */
#define GTP_METRIC_MAX_MSG	(1 << 8)
#define METRIC_PACKET		0
#define METRIC_BYTE		1

/* types */
struct gtp_metric {
	uint32_t		count;
	uint32_t		unsupported;
};

struct gtp_metrics_msg {
	struct gtp_metric	rx[GTP_METRIC_MAX_MSG];
	struct gtp_metric	tx[GTP_METRIC_MAX_MSG];
};

struct gtp_metrics_cause {
	uint32_t		cause[GTP_METRIC_MAX_MSG];
};

struct gtp_metrics_pkt {
	uint64_t		count;
	uint64_t		bytes;
};


/* Prototypes */
int gtp_metrics_rx(struct gtp_metrics_msg *, uint8_t);
int gtp_metrics_rx_notsup(struct gtp_metrics_msg *, uint8_t);
int gtp_metrics_tx(struct gtp_metrics_msg *, uint8_t);
int gtp_metrics_tx_notsup(struct gtp_metrics_msg *, uint8_t);
int gtp_metrics_pkt_update(struct gtp_metrics_pkt *, ssize_t);
int gtp_metrics_cause_update(struct gtp_metrics_cause *, struct pkt_buffer *);
int gtp_metrics_init(void);
int gtp_metrics_destroy(void);
