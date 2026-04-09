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

#include <stdlib.h>
#include <string.h>
#include "cpu.h"
#include "utils.h"
#include "vty_gauge.h"
#include "gtp_cpu.h"
#include "gtp_cpu_sched.h"
#include "logger.h"

/* Local data */
static LIST_HEAD(cpu_sched_list);
static int nr_cpus_possible;


/*
 *	Helpers
 */
static int
gcd(int a, int b)
{
	while (b) {
		int t = b;
		b = a % b;
		a = t;
	}
	return a;
}

void
gtp_cpu_sched_wrr_update_gcd(struct gtp_cpu_sched_group *grp)
{
	int g = 0, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		if (grp->weights[cpu])
			g = g ? gcd(g, grp->weights[cpu]) : grp->weights[cpu];
	}

	grp->wrr_gcd = g ? g : 1;
}

static const char *algo_names[] = {
	[GTP_CPU_SCHED_RR]	= "rr",
	[GTP_CPU_SCHED_WRR]	= "wrr",
	[GTP_CPU_SCHED_LC]	= "lc",
	[GTP_CPU_SCHED_WLC]	= "wlc",
	[GTP_CPU_SCHED_SED]	= "sed",
	[GTP_CPU_SCHED_NQ]	= "nq",
	[GTP_CPU_SCHED_LL]	= "ll",
	[GTP_CPU_SCHED_LBW]	= "lbw",
	[GTP_CPU_SCHED_LPPS]	= "lpps",
	[GTP_CPU_SCHED_LS]	= "ls",
	[GTP_CPU_SCHED_EWMA]	= "ewma",
	[GTP_CPU_SCHED_WSC]	= "wsc",
};

#define NR_ALGOS	(sizeof(algo_names) / sizeof(algo_names[0]))

const char *
gtp_cpu_sched_algo_str(int algo)
{
	if (algo < 0 || algo >= (int) NR_ALGOS)
		return "unknown";
	return algo_names[algo];
}

int
gtp_cpu_sched_algo_parse(const char *str)
{
	int i;

	for (i = 0; i < (int) NR_ALGOS; i++) {
		if (!strcmp(str, algo_names[i]))
			return i;
	}
	return -1;
}


static const char *metric_names[] = {
	[GTP_CPU_SCHED_M_LOAD]		= "load",
	[GTP_CPU_SCHED_M_SESSIONS]	= "sessions",
	[GTP_CPU_SCHED_M_BW]		= "bw",
	[GTP_CPU_SCHED_M_PPS]		= "pps",
};

const char *
gtp_cpu_sched_metric_str(int metric)
{
	if (metric < 0 || metric >= GTP_CPU_SCHED_NR_METRICS)
		return "unknown";
	return metric_names[metric];
}

int
gtp_cpu_sched_metric_parse(const char *str)
{
	int i;

	for (i = 0; i < GTP_CPU_SCHED_NR_METRICS; i++) {
		if (!strcmp(str, metric_names[i]))
			return i;
	}
	return -1;
}


/*
 *	Scheduling algorithms
 */

/* rr: simple rotation across cpumask */
static int
cpu_sched_rr(struct gtp_cpu_sched_group *grp)
{
	int cpu, start = grp->rr_idx;
	int found = -1;

	for (cpu = start + 1; cpu < nr_cpus_possible; cpu++) {
		if (CPU_ISSET(cpu, &grp->cpumask)) {
			found = cpu;
			break;
		}
	}

	if (found >= 0)
		goto end;

	for (cpu = 0; cpu <= start && cpu < nr_cpus_possible; cpu++) {
		if (CPU_ISSET(cpu, &grp->cpumask)) {
			found = cpu;
			break;
		}
	}

end:
	grp->rr_idx = found;
	return found;
}

/* wrr: weighted round-robin with decrementing counter */
static int
cpu_sched_wrr(struct gtp_cpu_sched_group *grp)
{
	int cpu, idx = grp->rr_idx;
	int passes = 0;

	while (passes < grp->nr_cpus * 2) {
		/* advance to next CPU in mask */
		int next = -1;

		for (cpu = idx + 1; cpu < nr_cpus_possible; cpu++) {
			if (CPU_ISSET(cpu, &grp->cpumask) && grp->weights[cpu]) {
				next = cpu;
				break;
			}
		}

		if (next < 0) {
			for (cpu = 0; cpu < nr_cpus_possible; cpu++) {
				if (CPU_ISSET(cpu, &grp->cpumask) && grp->weights[cpu]) {
					next = cpu;
					break;
				}
			}
			/* wrapped around: decrement current weight */
			grp->wrr_cw -= grp->wrr_gcd;
			if (grp->wrr_cw <= 0) {
				/* find max weight */
				int max_w = 0;
				cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
					if (grp->weights[cpu] > max_w)
						max_w = grp->weights[cpu];
				}
				grp->wrr_cw = max_w;
			}
		}

		if (next < 0)
			return 0;

		idx = next;
		if (grp->weights[idx] >= grp->wrr_cw) {
			grp->rr_idx = idx;
			return idx;
		}

		passes++;
	}

	grp->rr_idx = idx;
	return idx;
}

/* lc: least-connection (fewest pfcp_sessions) */
static int
cpu_sched_lc(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	uint32_t min_sessions = UINT32_MAX;
	int best = -1, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;
		if (m->pfcp_sessions < min_sessions) {
			min_sessions = m->pfcp_sessions;
			best = cpu;
		}
	}

	return best >= 0 ? best : 0;
}

/* wlc: weighted least-connection (cross-multiply to avoid fp) */
static int
cpu_sched_wlc(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	uint64_t loh = 0;
	int lw = 0, best = -1, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		if (!grp->weights[cpu])
			continue;
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;

		uint64_t doh = m->pfcp_sessions;
		if (best < 0 || doh * lw < loh * grp->weights[cpu]) {
			best = cpu;
			loh = doh;
			lw = grp->weights[cpu];
		}
	}

	return best >= 0 ? best : 0;
}

/* sed: shortest expected delay — (sessions+1)/weight */
static int
cpu_sched_sed(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	uint64_t loh = 0;
	int lw = 0, best = -1, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		if (!grp->weights[cpu])
			continue;
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;

		uint64_t doh = (uint64_t) m->pfcp_sessions + 1;
		if (best < 0 || doh * lw < loh * grp->weights[cpu]) {
			best = cpu;
			loh = doh;
			lw = grp->weights[cpu];
		}
	}

	return best >= 0 ? best : 0;
}

/* nq: never queue — prefer idle CPUs, fallback to SED */
static int
cpu_sched_nq(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	int best_idle = -1, best_idle_w = 0, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		if (!grp->weights[cpu])
			continue;
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;
		if (m->pfcp_sessions == 0 && grp->weights[cpu] > best_idle_w) {
			best_idle = cpu;
			best_idle_w = grp->weights[cpu];
		}
	}

	return best_idle >= 0 ? best_idle : cpu_sched_sed(grp);
}

/* ll: least-load (lowest CPU utilisation) */
static int
cpu_sched_ll(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	float min_load = 2.0f;
	int best = -1, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m || m->load < 0.0f)
			continue;
		if (m->load < min_load) {
			min_load = m->load;
			best = cpu;
		}
	}

	return best >= 0 ? best : 0;
}

/* lbw: least-bandwidth (lowest total_bw_bps) */
static int
cpu_sched_lbw(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	uint64_t min_bw = UINT64_MAX;
	int best = -1, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;
		if (m->total_bw_bps < min_bw) {
			min_bw = m->total_bw_bps;
			best = cpu;
		}
	}

	return best >= 0 ? best : 0;
}

/* lpps: least-pps (lowest rx_pps + tx_pps) */
static int
cpu_sched_lpps(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	uint64_t min_pps = UINT64_MAX;
	int best = -1, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;
		uint64_t pps = m->rx_pps + m->tx_pps;
		if (pps < min_pps) {
			min_pps = pps;
			best = cpu;
		}
	}

	return best >= 0 ? best : 0;
}

/* ls: least-slope (lowest load trend over window) */
static int
cpu_sched_ls(struct gtp_cpu_sched_group *grp)
{
	struct gtp_percpu_metrics *m;
	float min_slope = 2.0f, oldest, newest, slope;
	int best = -1, cpu, n;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m || m->load < 0.0f || m->load_history.count < 2)
			continue;

		n = min(grp->window, m->load_history.count);
		oldest = gauge_history_get(&m->load_history, m->load_history.count - n);
		newest = gauge_history_get(&m->load_history, m->load_history.count - 1);
		slope = (newest - oldest) / n;

		if (slope < min_slope) {
			min_slope = slope;
			best = cpu;
		}
	}

	return best >= 0 ? best : 0;
}

/* ewma: least EWMA-smoothed load */
static int
cpu_sched_ewma(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	float min_ewma = 2.0f;
	int best = -1, cpu;

	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m || m->load < 0.0f)
			continue;
		if (m->load_ewma < min_ewma) {
			min_ewma = m->load_ewma;
			best = cpu;
		}
	}

	return best >= 0 ? best : 0;
}


/* wsc: weighted-score composite — normalized EWMA metrics */
static int
cpu_sched_wsc(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	double raw[GTP_CPU_SCHED_NR_METRICS];
	double max_v[GTP_CPU_SCHED_NR_METRICS] = {};
	int cpus[CPU_SETSIZE], nr = 0;
	double best_score = 1e18, pps;
	int best = -1, cpu, i;

	/* first round: collect raw EWMA values and track max per metric */
	cpuset_for_each(cpu, grp->cpumask, nr_cpus_possible) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;

		cpus[nr++] = cpu;

		if (m->load_ewma > max_v[GTP_CPU_SCHED_M_LOAD])
			max_v[GTP_CPU_SCHED_M_LOAD] = m->load_ewma;
		if (m->pfcp_sessions > max_v[GTP_CPU_SCHED_M_SESSIONS])
			max_v[GTP_CPU_SCHED_M_SESSIONS] = m->pfcp_sessions;
		if (m->total_bw_bps_ewma > max_v[GTP_CPU_SCHED_M_BW])
			max_v[GTP_CPU_SCHED_M_BW] = m->total_bw_bps_ewma;
		pps = m->rx_pps_ewma + m->tx_pps_ewma;
		if (pps > max_v[GTP_CPU_SCHED_M_PPS])
			max_v[GTP_CPU_SCHED_M_PPS] = pps;
	}

	/* second round: compute composite score and elect lowest */
	for (i = 0; i < nr; i++) {
		m = gtp_percpu_metrics_get(cpus[i]);

		raw[GTP_CPU_SCHED_M_LOAD] = m->load_ewma;
		raw[GTP_CPU_SCHED_M_SESSIONS] = m->pfcp_sessions;
		raw[GTP_CPU_SCHED_M_BW] = m->total_bw_bps_ewma;
		raw[GTP_CPU_SCHED_M_PPS] = m->rx_pps_ewma + m->tx_pps_ewma;

		double score = 0;
		int k;
		for (k = 0; k < GTP_CPU_SCHED_NR_METRICS; k++) {
			if (grp->metric_weights[k] <= 0.0f || max_v[k] <= 0.0)
				continue;
			score += grp->metric_weights[k] * (raw[k] / max_v[k]);
		}

		if (score < best_score) {
			best_score = score;
			best = cpus[i];
		}
	}

	return best >= 0 ? best : 0;
}


/*
 *	Dispatch table and election
 */
typedef int (*cpu_sched_fn)(struct gtp_cpu_sched_group *grp);

static cpu_sched_fn cpu_sched_tab[] = {
	[GTP_CPU_SCHED_RR]	= cpu_sched_rr,
	[GTP_CPU_SCHED_WRR]	= cpu_sched_wrr,
	[GTP_CPU_SCHED_LC]	= cpu_sched_lc,
	[GTP_CPU_SCHED_WLC]	= cpu_sched_wlc,
	[GTP_CPU_SCHED_SED]	= cpu_sched_sed,
	[GTP_CPU_SCHED_NQ]	= cpu_sched_nq,
	[GTP_CPU_SCHED_LL]	= cpu_sched_ll,
	[GTP_CPU_SCHED_LBW]	= cpu_sched_lbw,
	[GTP_CPU_SCHED_LPPS]	= cpu_sched_lpps,
	[GTP_CPU_SCHED_LS]	= cpu_sched_ls,
	[GTP_CPU_SCHED_EWMA]	= cpu_sched_ewma,
	[GTP_CPU_SCHED_WSC]	= cpu_sched_wsc,
};

int
gtp_cpu_sched_elect(struct gtp_cpu_sched_group *grp)
{
	const struct gtp_percpu_metrics *m;
	int cpu;

	if (!grp)
		return 0;

	cpu = cpu_sched_tab[grp->algo](grp);

	if (!grp->debug)
		return cpu;

	m = gtp_percpu_metrics_get(cpu);
	log_message(LOG_INFO, "cpu-sched: group=%s algo=%s elected=cpu%d"
			      " (sessions=%u weight=%d)"
			    , grp->name
			    , gtp_cpu_sched_algo_str(grp->algo)
			    , cpu
			    , m ? m->pfcp_sessions : 0
			    , grp->weights ? grp->weights[cpu] : 0);
	return cpu;
}


/*
 *	Group management
 */
struct gtp_cpu_sched_group *
gtp_cpu_sched_get(const char *name)
{
	struct gtp_cpu_sched_group *grp;

	list_for_each_entry(grp, &cpu_sched_list, next) {
		if (!strcmp(grp->name, name))
			return grp;
	}

	return NULL;
}

struct gtp_cpu_sched_group *
gtp_cpu_sched_alloc(const char *name)
{
	struct gtp_cpu_sched_group *grp;
	int i;

	if (!nr_cpus_possible)
		nr_cpus_possible = cpu_nr_possible();

	grp = calloc(1, sizeof(*grp));
	if (!grp)
		return NULL;

	bsd_strlcpy(grp->name, name, GTP_NAME_MAX_LEN);
	grp->algo = GTP_CPU_SCHED_WLC;
	CPU_ZERO(&grp->cpumask);
	INIT_LIST_HEAD(&grp->next);

	grp->weights = calloc(nr_cpus_possible, sizeof(int));
	if (!grp->weights) {
		free(grp);
		return NULL;
	}

	for (i = 0; i < nr_cpus_possible; i++)
		grp->weights[i] = GTP_CPU_SCHED_DEFAULT_WEIGHT;

	grp->wrr_gcd = GTP_CPU_SCHED_DEFAULT_WEIGHT;
	grp->wrr_cw = GTP_CPU_SCHED_DEFAULT_WEIGHT;
	grp->window = GTP_CPU_SCHED_DEFAULT_WINDOW;
	grp->ewma_alpha = GTP_CPU_SCHED_DEFAULT_EWMA_ALPHA;

	/* WSC: equal weights by default */
	for (i = 0; i < GTP_CPU_SCHED_NR_METRICS; i++)
		grp->metric_weights[i] = 1.0f;

	list_add_tail(&grp->next, &cpu_sched_list);
	return grp;
}

void
gtp_cpu_sched_group_destroy(struct gtp_cpu_sched_group *grp)
{
	list_head_del(&grp->next);
	free(grp->weights);
	free(grp);
}

void
gtp_cpu_sched_foreach(int (*fn)(struct gtp_cpu_sched_group *, void *), void *arg)
{
	struct gtp_cpu_sched_group *grp;

	list_for_each_entry(grp, &cpu_sched_list, next) {
		if (fn(grp, arg))
			break;
	}
}

void
gtp_cpu_sched_destroy(void)
{
	struct gtp_cpu_sched_group *grp, *tmp;

	list_for_each_entry_safe(grp, tmp, &cpu_sched_list, next)
		gtp_cpu_sched_group_destroy(grp);
}
