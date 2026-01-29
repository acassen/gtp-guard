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

/* defines */
#define PFCP_METRIC_MAX_MSG	(1 << 8)
#define METRIC_PACKET		0
#define METRIC_BYTE		1

/* types */
struct pfcp_metric {
	uint32_t		count;
	uint32_t		unsupported;
};

struct pfcp_metrics_msg {
	struct pfcp_metric	rx[PFCP_METRIC_MAX_MSG];
	struct pfcp_metric	tx[PFCP_METRIC_MAX_MSG];
};

struct pfcp_metrics_pkt {
	uint64_t		count;
	uint64_t		bytes;
};

static inline int pfcp_metrics_pkt_is_null(struct pfcp_metrics_pkt *p)
{
	return !p->count && !p->bytes;
}

static inline int __attribute__((pure))
pfcp_metrics_pkt_cmp(struct pfcp_metrics_pkt *a, struct pfcp_metrics_pkt *b)
{
	if (a->bytes > b->bytes)
		return 1;
	if (a->bytes < b->bytes)
		return -1;
	if (a->count > b->count)
		return 1;
	if (a->count < b->count)
		return -1;
	return 0;
}

static inline void
pfcp_metrics_pkt_cpy(struct pfcp_metrics_pkt *a, struct pfcp_metrics_pkt *b)
{
	a->bytes = b->bytes;
	a->count = b->count;
}


/* Prototypes */
int pfcp_metrics_rx(struct pfcp_metrics_msg *m, uint8_t msg_types);
int pfcp_metrics_rx_notsup(struct pfcp_metrics_msg *m, uint8_t msg_types);
int pfcp_metrics_tx(struct pfcp_metrics_msg *m, uint8_t msg_types);
int pfcp_metrics_tx_notsup(struct pfcp_metrics_msg *m, uint8_t msg_types);
int pfcp_metrics_pkt_update(struct pfcp_metrics_pkt *m, ssize_t nbytes);
void pfcp_metrics_pkt_sub(struct pfcp_metrics_pkt *a, struct pfcp_metrics_pkt *b,
			  struct pfcp_metrics_pkt *r);
