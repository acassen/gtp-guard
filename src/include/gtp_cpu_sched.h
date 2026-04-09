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

#include <sched.h>
#include "list_head.h"
#include "gtp_stddef.h"

#define GTP_CPU_SCHED_DEFAULT_WEIGHT	100

enum gtp_cpu_sched_algo {
	GTP_CPU_SCHED_RR,
	GTP_CPU_SCHED_WRR,
	GTP_CPU_SCHED_LC,
	GTP_CPU_SCHED_WLC,
	GTP_CPU_SCHED_SED,
	GTP_CPU_SCHED_NQ,
	GTP_CPU_SCHED_LL,
	GTP_CPU_SCHED_LBW,
	GTP_CPU_SCHED_LPPS,
};

struct gtp_cpu_sched_group {
	char			name[GTP_NAME_MAX_LEN];
	cpu_set_t		cpumask;
	int			nr_cpus;
	int			algo;
	int			*weights;
	int			rr_idx;
	int			wrr_cw;
	int			wrr_gcd;

	unsigned long		debug;

	struct list_head	next;
};

/* Prototypes */
int gtp_cpu_sched_elect(struct gtp_cpu_sched_group *grp);
struct gtp_cpu_sched_group *gtp_cpu_sched_get(const char *name);
struct gtp_cpu_sched_group *gtp_cpu_sched_alloc(const char *name);
void gtp_cpu_sched_group_destroy(struct gtp_cpu_sched_group *grp);
void gtp_cpu_sched_destroy(void);
void gtp_cpu_sched_wrr_update_gcd(struct gtp_cpu_sched_group *grp);
const char *gtp_cpu_sched_algo_str(int algo);
int gtp_cpu_sched_algo_parse(const char *str);
