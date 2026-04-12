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
#include "gtp_range_partition.h"

#define GTP_CPU_SCHED_DEFAULT_WEIGHT	100
#define GTP_CPU_SCHED_DEFAULT_WINDOW	25	/* 5s at 200ms/sample */
#define GTP_CPU_SCHED_DEFAULT_EWMA_ALPHA 0.2f

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
	GTP_CPU_SCHED_LS,
	GTP_CPU_SCHED_EWMA,
	GTP_CPU_SCHED_WSC,
	GTP_CPU_SCHED_CBS,
};

/* Multi-metric indices (shared by WSC and CBS) */
enum gtp_cpu_sched_metric {
	GTP_CPU_SCHED_M_LOAD,
	GTP_CPU_SCHED_M_SESSIONS,
	GTP_CPU_SCHED_M_BW,
	GTP_CPU_SCHED_M_PPS,
	GTP_CPU_SCHED_NR_METRICS,
};

/* Range-partition binding: maps CPU rank to rp part */
struct gtp_cpu_sched_rp_map {
	struct gtp_range_partition	*rp;
	struct list_head		next;
};

/* CBS constraint modes */
enum gtp_cpu_sched_cbs_mode {
	GTP_CPU_SCHED_CBS_INSTANT,
	GTP_CPU_SCHED_CBS_EWMA,
	GTP_CPU_SCHED_CBS_SLOPE,
};

#define GTP_CPU_SCHED_MAX_CONSTRAINTS	GTP_CPU_SCHED_NR_METRICS

struct gtp_cpu_sched_constraint {
	int		metric;		/* gtp_cpu_sched_metric */
	int		mode;		/* gtp_cpu_sched_cbs_mode */
	double		threshold;
	int		active;
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
	int			window;		/* ls: history samples for slope */
	float			ewma_alpha;	/* ewma: smoothing factor */
	float			metric_weights[GTP_CPU_SCHED_NR_METRICS]; /* wsc */

	/* CBS: constraint-based scheduling */
	struct gtp_cpu_sched_constraint	constraints[GTP_CPU_SCHED_MAX_CONSTRAINTS];
	int			nr_constraints;
	int			fallback_algo;

	/* range-partition bindings: CPU rank -> rp part index */
	struct list_head	rp_maps;
	int			nr_rp_maps;

	unsigned long		debug;

	struct list_head	next;
};

/* Iteration */
void gtp_cpu_sched_foreach(int (*fn)(struct gtp_cpu_sched_group *, void *), void *arg);

/* Prototypes */
int gtp_cpu_sched_elect(struct gtp_cpu_sched_group *grp);
struct gtp_range_part *gtp_cpu_sched_get_part(struct gtp_cpu_sched_group *grp,
					      struct gtp_range_partition *rp,
					      int cpu);
struct gtp_cpu_sched_group *gtp_cpu_sched_get(const char *name);
struct gtp_cpu_sched_group *gtp_cpu_sched_alloc(const char *name);
void gtp_cpu_sched_group_destroy(struct gtp_cpu_sched_group *grp);
void gtp_cpu_sched_destroy(void);
void gtp_cpu_sched_wrr_update_gcd(struct gtp_cpu_sched_group *grp);
const char *gtp_cpu_sched_algo_str(int algo);
int gtp_cpu_sched_algo_parse(const char *str);
const char *gtp_cpu_sched_metric_str(int metric);
int gtp_cpu_sched_metric_parse(const char *str);
const char *gtp_cpu_sched_cbs_mode_str(int mode);
int gtp_cpu_sched_cbs_mode_parse(const char *str);
