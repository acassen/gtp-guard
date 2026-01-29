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

#include "gtp_data.h"
#include "pfcp_metrics.h"

/* Extern data */
extern struct data *daemon_data;


/*
 *	Utilities
 */
int
pfcp_metrics_rx(struct pfcp_metrics_msg *m, uint8_t msg_type)
{
	m->rx[msg_type].count++;
	return 0;
}

int
pfcp_metrics_rx_notsup(struct pfcp_metrics_msg *m, uint8_t msg_type)
{
	m->rx[msg_type].unsupported++;
	return 0;
}

int
pfcp_metrics_tx(struct pfcp_metrics_msg *m, uint8_t msg_type)
{
	m->tx[msg_type].count++;
	return 0;
}

int
pfcp_metrics_tx_notsup(struct pfcp_metrics_msg *m, uint8_t msg_type)
{
	m->tx[msg_type].unsupported++;
	return 0;
}

int
pfcp_metrics_pkt_update(struct pfcp_metrics_pkt *m, ssize_t nbytes)
{
	if (nbytes <= 0)
		return -1;

	m->bytes += nbytes;
	m->count++;
	return 0;
}

void
pfcp_metrics_pkt_sub(struct pfcp_metrics_pkt *a, struct pfcp_metrics_pkt *b,
		     struct pfcp_metrics_pkt *r)
{
	r->bytes = (a->bytes > b->bytes) ? a->bytes - b->bytes : 0;
	r->count = (a->count > b->count) ? a->count - b->count : 0;
}

/*
 *	Metrics dump
 *
 * TODO: Integrate into main GTP Metrics stuff
 */
