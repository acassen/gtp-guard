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

enum metric_direction {
	METRICS_DIR_IN = 0,
	METRICS_DIR_OUT,
	METRICS_DIR_MAX,
};

enum pppoe_metric {
	PPPOE_METRIC_TOTAL = 0,
	PPPOE_METRIC_DROPPED,
	PPPOE_METRIC_PADI,
	PPPOE_METRIC_PADR,
	PPPOE_METRIC_PADO,
	PPPOE_METRIC_PADS,
	PPPOE_METRIC_PADT,
	PPPOE_METRIC_MAX,
};

enum ppp_metric {
	PPP_METRIC_TOTAL = 0,
	PPP_METRIC_UP,
	PPP_METRIC_DOWN,
	PPP_METRIC_OPEN,
	PPP_METRIC_CLOSE,
	PPP_METRIC_CONF_ACK,
	PPP_METRIC_CONF_NAK,
	PPP_METRIC_MAX,
};

struct pppoe_metrics {
	uint64_t	m[METRICS_DIR_MAX][PPPOE_METRIC_MAX];
};

struct ppp_metrics {
	uint64_t	dropped[METRICS_DIR_MAX];
	uint64_t	lcp[METRICS_DIR_MAX][PPP_METRIC_MAX];
	uint64_t	pap[METRICS_DIR_MAX][PPP_METRIC_MAX];
	uint64_t	ipcp[METRICS_DIR_MAX][PPP_METRIC_MAX];
	uint64_t	ipv6cp[METRICS_DIR_MAX][PPP_METRIC_MAX];
};
