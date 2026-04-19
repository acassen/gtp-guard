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

#include <inttypes.h>
#include "command.h"
#include "vty.h"
#include "vty_gauge.h"
#include "vty_matrix.h"
#include "cpu.h"
#include "gtp_cpu.h"
#include "gtp_cpu_sched.h"
#include "gtp_range_partition.h"

/* Extern data */
extern struct cpu_load *cpu_load;


/*
 *	CPU scheduling group commands
 */
DEFUN(cpu_sched_group,
      cpu_sched_group_cmd,
      "cpu-sched-group STRING",
      "Configure CPU scheduling group\n"
      "Group name")
{
	struct gtp_cpu_sched_group *grp;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp = gtp_cpu_sched_get(argv[0]);
	grp = grp ? : gtp_cpu_sched_alloc(argv[0]);
	if (!grp) {
		vty_out(vty, "%% Error allocating cpu-sched-group:'%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = CPU_SCHED_NODE;
	vty->index = grp;
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_group,
      no_cpu_sched_group_cmd,
      "no cpu-sched-group STRING",
      "Destroy CPU scheduling group\n"
      "Group name")
{
	struct gtp_cpu_sched_group *grp;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp = gtp_cpu_sched_get(argv[0]);
	if (!grp) {
		vty_out(vty, "%% Unknown cpu-sched-group:'%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_cpu_sched_group_destroy(grp);
	return CMD_SUCCESS;
}

DEFUN(cpu_sched_cpumask,
      cpu_sched_cpumask_cmd,
      "cpumask STRING",
      "Set eligible CPUs\n"
      "CPU list (e.g. 0-3,8-11)")
{
	struct gtp_cpu_sched_group *grp = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	cpulist_to_set(argv[0], &grp->cpumask);
	grp->nr_cpus = CPU_COUNT(&grp->cpumask);
	gtp_cpu_sched_wrr_update_gcd(grp);
	return CMD_SUCCESS;
}

DEFUN(cpu_sched_algorithm,
      cpu_sched_algorithm_cmd,
      "algorithm STRING",
      "Set scheduling algorithm\n"
      "Algorithm (rr|wrr|lc|wlc|sed|nq|ll|lbw|lpps|ls|ewma|wsc|cbs)")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	int algo;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	algo = gtp_cpu_sched_algo_parse(argv[0]);
	if (algo < 0) {
		vty_out(vty, "%% Unknown algorithm '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->algo = algo;
	return CMD_SUCCESS;
}

DEFUN(cpu_sched_weight,
      cpu_sched_weight_cmd,
      "weight cpu <0-4095> <0-65535>",
      "Set per-CPU weight\n"
      "CPU keyword\n"
      "CPU number\n"
      "Weight value (0 = quiesced)")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	int cpu_id, weight;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("CPU number", cpu_id, argv[0], 0, 4095);
	VTY_GET_INTEGER_RANGE("weight", weight, argv[1], 0, 65535);

	if (!grp->weights) {
		vty_out(vty, "%% Internal error%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->weights[cpu_id] = weight;
	gtp_cpu_sched_wrr_update_gcd(grp);
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_weight,
      no_cpu_sched_weight_cmd,
      "no weight cpu <0-4095>",
      "Reset per-CPU weight to default\n"
      "Weight keyword\n"
      "CPU keyword\n"
      "CPU number")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	int cpu_id;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("CPU number", cpu_id, argv[0], 0, 4095);

	if (grp->weights)
		grp->weights[cpu_id] = GTP_CPU_SCHED_DEFAULT_WEIGHT;
	gtp_cpu_sched_wrr_update_gcd(grp);
	return CMD_SUCCESS;
}

DEFUN(cpu_sched_window,
      cpu_sched_window_cmd,
      "window <1-256>",
      "Set history window for ls algorithm\n"
      "Number of 200ms samples")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	int window;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("window", window, argv[0], 1, 256);
	grp->window = window;
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_window,
      no_cpu_sched_window_cmd,
      "no window",
      "Reset history window to default\n"
      "Window keyword")
{
	struct gtp_cpu_sched_group *grp = vty->index;

	grp->window = GTP_CPU_SCHED_DEFAULT_WINDOW;
	return CMD_SUCCESS;
}

DEFUN(cpu_sched_ewma_alpha,
      cpu_sched_ewma_alpha_cmd,
      "ewma-alpha STRING",
      "Set EWMA smoothing factor\n"
      "Alpha value (0.0-1.0)")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	float alpha;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	alpha = strtof(argv[0], NULL);
	if (alpha <= 0.0f || alpha > 1.0f) {
		vty_out(vty, "%% alpha must be in (0.0, 1.0]%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->ewma_alpha = alpha;
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_ewma_alpha,
      no_cpu_sched_ewma_alpha_cmd,
      "no ewma-alpha",
      "Reset EWMA smoothing factor to default\n"
      "EWMA alpha keyword")
{
	struct gtp_cpu_sched_group *grp = vty->index;

	grp->ewma_alpha = GTP_CPU_SCHED_DEFAULT_EWMA_ALPHA;
	return CMD_SUCCESS;
}


DEFUN(cpu_sched_metric_weight,
      cpu_sched_metric_weight_cmd,
      "metric-weight STRING STRING",
      "Set WSC metric weight\n"
      "Metric name (load|sessions|bw|pps)\n"
      "Weight value (0.0-100.0)")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	float w;
	int m;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	m = gtp_cpu_sched_metric_parse(argv[0]);
	if (m < 0) {
		vty_out(vty, "%% Unknown metric '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	w = strtof(argv[1], NULL);
	if (w < 0.0f || w > 100.0f) {
		vty_out(vty, "%% weight must be in [0.0, 100.0]%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->metric_weights[m] = w;
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_metric_weight,
      no_cpu_sched_metric_weight_cmd,
      "no metric-weight STRING",
      "Reset WSC metric weight to default\n"
      "Metric weight keyword\n"
      "Metric name (load|sessions|bw|pps)")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	int m;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	m = gtp_cpu_sched_metric_parse(argv[0]);
	if (m < 0) {
		vty_out(vty, "%% Unknown metric '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->metric_weights[m] = 1.0f;
	return CMD_SUCCESS;
}

DEFUN(cpu_sched_constraint,
      cpu_sched_constraint_cmd,
      "constraint STRING STRING STRING",
      "Add CBS constraint (exclude CPU if metric > threshold)\n"
      "Metric name (load|sessions|bw|pps)\n"
      "Mode (instant|ewma|slope)\n"
      "Threshold value")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	struct gtp_cpu_sched_constraint *c;
	int metric, mode, i, slot = -1;

	if (argc < 3) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	metric = gtp_cpu_sched_metric_parse(argv[0]);
	if (metric < 0) {
		vty_out(vty, "%% Unknown metric '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	mode = gtp_cpu_sched_cbs_mode_parse(argv[1]);
	if (mode < 0) {
		vty_out(vty, "%% Unknown mode '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* sessions only supports instant (no EWMA, no history) */
	if (mode != GTP_CPU_SCHED_CBS_INSTANT && metric == GTP_CPU_SCHED_M_SESSIONS) {
		vty_out(vty, "%% only instant mode available for sessions metric%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* find existing constraint for this metric or a free slot */
	for (i = 0; i < grp->nr_constraints; i++) {
		if (grp->constraints[i].metric == metric) {
			slot = i;
			break;
		}
	}

	if (slot < 0) {
		if (grp->nr_constraints >= GTP_CPU_SCHED_MAX_CONSTRAINTS) {
			vty_out(vty, "%% Maximum constraints reached%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		slot = grp->nr_constraints++;
	}

	c = &grp->constraints[slot];
	c->metric = metric;
	c->mode = mode;
	c->threshold = strtod(argv[2], NULL);
	c->active = 1;
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_constraint,
      no_cpu_sched_constraint_cmd,
      "no constraint STRING",
      "Remove CBS constraint\n"
      "Constraint keyword\n"
      "Metric name (load|sessions|bw|pps)")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	int metric, i;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	metric = gtp_cpu_sched_metric_parse(argv[0]);
	if (metric < 0) {
		vty_out(vty, "%% Unknown metric '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	for (i = 0; i < grp->nr_constraints; i++) {
		if (grp->constraints[i].metric == metric) {
			/* compact array */
			grp->nr_constraints--;
			for (; i < grp->nr_constraints; i++)
				grp->constraints[i] = grp->constraints[i + 1];
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "%% No constraint on metric '%s'%s", argv[0], VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(cpu_sched_fallback,
      cpu_sched_fallback_cmd,
      "fallback-algorithm STRING",
      "Set CBS fallback algorithm for surviving CPUs\n"
      "Algorithm name")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	int algo;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	algo = gtp_cpu_sched_algo_parse(argv[0]);
	if (algo < 0) {
		vty_out(vty, "%% Unknown algorithm '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (algo == GTP_CPU_SCHED_CBS) {
		vty_out(vty, "%% Cannot use cbs as its own fallback%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->fallback_algo = algo;
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_fallback,
      no_cpu_sched_fallback_cmd,
      "no fallback-algorithm",
      "Reset CBS fallback algorithm to default (wlc)\n"
      "Fallback algorithm keyword")
{
	struct gtp_cpu_sched_group *grp = vty->index;

	grp->fallback_algo = GTP_CPU_SCHED_WLC;
	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static void
gtp_cpu_list_gauge(struct vty *vty, const char *list)
{
	const struct gauge_opts defaults = { .style = GAUGE_ASCII };
	struct gauge_opts *opts = vty->priv ? : (void *)&defaults;
	char label[12];
	cpu_set_t set;
	int cpu;

	cpulist_to_set(list, &set);
	cpuset_for_each(cpu, set, cpu_load->nr_cpus) {
		struct gtp_percpu_metrics *m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;
		snprintf(label, sizeof(label), "  cpu%-3d", cpu);
		opts->h = &m->load_history;
		vty_gauge(vty, label, cpu_load_get(cpu_load, cpu), opts);
	}
}

static int
gtp_cpu_list_collect(const char *list, struct matrix_entry *e, int max)
{
	cpu_set_t set;
	int cpu, n = 0;

	cpulist_to_set(list, &set);
	cpuset_for_each(cpu, set, cpu_load->nr_cpus) {
		if (n >= max)
			break;
		snprintf(e[n].label, sizeof(e[n].label), "cpu%-3d", cpu);
		e[n].render = vty_matrix_gauge_render;
		e[n].value  = cpu_load_get(cpu_load, cpu);
		n++;
	}
	return n;
}

static void
gtp_cpu_gauge_cb(int node, const char *cpulist, void *arg)
{
	struct vty *vty = arg;

	vty_out(vty, " NUMA node %d  [cpus: %s]%s", node, cpulist, VTY_NEWLINE);
	gtp_cpu_list_gauge(vty, cpulist);
	vty_out(vty, "%s", VTY_NEWLINE);
}

static void
gtp_cpu_matrix_cb(int node, const char *cpulist, void *arg)
{
	struct matrix_entry entries[cpu_load->nr_cpus];
	struct matrix_opts *mopts = ((struct vty *)arg)->priv;
	struct vty *vty = arg;
	int n;

	vty_out(vty, " NUMA node %d  [cpus: %s]%s", node, cpulist, VTY_NEWLINE);
	n = gtp_cpu_list_collect(cpulist, entries, cpu_load->nr_cpus);
	vty_matrix(vty, NULL, entries, n, mopts);
	vty_out(vty, "%s", VTY_NEWLINE);
}

int
gtp_cpu_show(struct vty *vty)
{
	if (!cpu_load) {
		vty_out(vty, "%% CPU monitoring not available%s", VTY_NEWLINE);
		return -1;
	}
	cpu_foreach_numa_node(gtp_cpu_gauge_cb, vty);
	return 0;
}

int
gtp_cpu_matrix_show(struct vty *vty)
{
	if (!cpu_load) {
		vty_out(vty, "%% CPU monitoring not available%s", VTY_NEWLINE);
		return -1;
	}
	cpu_foreach_numa_node(gtp_cpu_matrix_cb, vty);
	return 0;
}

DEFUN(show_system_cpu,
      show_system_cpu_cmd,
      "show system cpu",
      SHOW_STR
      "System information\n"
      "Per-core CPU utilization\n")
{
	struct gauge_opts *go = gauge_opts_alloc(GAUGE_BRAILLE_GRAPH);
	int ret = CMD_SUCCESS;

	if (!go) {
		vty_out(vty, "%% out of memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->priv = go;
	if (gtp_cpu_show(vty) < 0) {
		ret = CMD_WARNING;
	}

	vty->priv = NULL;
	free(go);
	return ret;
}

static int
show_cpu_sched_group(struct gtp_cpu_sched_group *grp, void *arg)
{
	struct vty *vty = arg;
	const struct gtp_percpu_metrics *m;
	int cpu;

	vty_out(vty, "CPU Scheduling Group: %s (algorithm: %s)%s"
		   , grp->name
		   , gtp_cpu_sched_algo_str(grp->algo)
		   , VTY_NEWLINE);
	vty_out(vty, "  CPU   Weight   Sessions   Load   Load~   BW(Mbps)   BW~(Mbps)       PPS      PPS~%s"
		   , VTY_NEWLINE);

	cpuset_for_each(cpu, grp->cpumask, CPU_SETSIZE) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;
		vty_out(vty, "  %3d   %6d   %8u   %.2f   %5.2f   %8.1f   %9.1f   %7" PRIu64 "   %7.0f%s"
			   , cpu
			   , grp->weights ? grp->weights[cpu] : GTP_CPU_SCHED_DEFAULT_WEIGHT
			   , m->pfcp_sessions
			   , m->load
			   , m->load_ewma
			   , (double)m->total_bw_bps / 125000.0
			   , m->total_bw_bps_ewma / 125000.0
			   , m->rx_pps + m->tx_pps
			   , m->rx_pps_ewma + m->tx_pps_ewma
			   , VTY_NEWLINE);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	return 0;
}

DEFUN(show_cpu_sched,
      show_cpu_sched_cmd,
      "show cpu-sched",
      "Show running system information\n"
      "CPU scheduling groups")
{
	gtp_cpu_sched_foreach(show_cpu_sched_group, vty);
	return CMD_SUCCESS;
}

DEFUN(show_cpu_sched_name,
      show_cpu_sched_name_cmd,
      "show cpu-sched STRING",
      "Show running system information\n"
      "CPU scheduling groups\n"
      "Group name")
{
	struct gtp_cpu_sched_group *grp;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp = gtp_cpu_sched_get(argv[0]);
	if (!grp) {
		vty_out(vty, "%% Unknown cpu-sched-group:'%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	show_cpu_sched_group(grp, vty);
	return CMD_SUCCESS;
}


/*
 *	Debug commands
 */
DEFUN(debug_cpu_sched,
      debug_cpu_sched_cmd,
      "debug cpu-sched STRING",
      "Enable debug\n"
      "CPU scheduling\n"
      "Group name")
{
	struct gtp_cpu_sched_group *grp;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp = gtp_cpu_sched_get(argv[0]);
	if (!grp) {
		vty_out(vty, "%% Unknown cpu-sched-group:'%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->debug = 1;
	return CMD_SUCCESS;
}

DEFUN(no_debug_cpu_sched,
      no_debug_cpu_sched_cmd,
      "no debug cpu-sched STRING",
      "Disable debug\n"
      "CPU scheduling\n"
      "Group name")
{
	struct gtp_cpu_sched_group *grp;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp = gtp_cpu_sched_get(argv[0]);
	if (!grp) {
		vty_out(vty, "%% Unknown cpu-sched-group:'%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	grp->debug = 0;
	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static void
vty_out_cpumask(struct vty *vty, const cpu_set_t *mask)
{
	int cpu, first = 1, range_start = -1, range_end = -1;

	/* iterate one past end so the sentinel flushes the last range */
	for (cpu = 0; cpu <= CPU_SETSIZE; cpu++) {
		if (cpu < CPU_SETSIZE && CPU_ISSET(cpu, mask)) {
			if (range_start < 0)
				range_start = cpu;
			range_end = cpu;
			continue;
		}

		if (range_start < 0)
			continue;

		vty_out(vty, "%s%d", first ? "" : ",", range_start);
		if (range_end > range_start)
			vty_out(vty, "-%d", range_end);
		first = 0;
		range_start = -1;
	}

	vty_out(vty, "%s", VTY_NEWLINE);
}

/*
 *	Range-partition binding commands
 */
DEFUN(cpu_sched_bind_rp,
      cpu_sched_bind_rp_cmd,
      "cpumask bind range-partition WORD",
      "CPU mask operations\n"
      "Bind keyword\n"
      "Range partition keyword\n"
      "Range partition name")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	struct gtp_cpu_sched_rp_map *m;
	struct gtp_range_partition *rp;

	rp = gtp_range_partition_get(argv[0]);
	if (!rp) {
		vty_out(vty, "%% unknown range-partition '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Reject duplicate */
	list_for_each_entry(m, &grp->rp_maps, next) {
		if (m->rp == rp) {
			vty_out(vty, "%% range-partition '%s' already bound%s"
				   , argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (grp->nr_cpus && rp->nr_parts && grp->nr_cpus != rp->nr_parts)
		vty_out(vty, "%% Warning: cpumask has %d CPUs but partition has %d parts, "
			     "only min(%d,%d) mappings active%s"
			   , grp->nr_cpus, rp->nr_parts
			   , grp->nr_cpus, rp->nr_parts
			   , VTY_NEWLINE);

	m = calloc(1, sizeof(*m));
	if (!m) {
		vty_out(vty, "%% Out of memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	m->rp = rp;
	rp->refcnt++;
	list_add_tail(&m->next, &grp->rp_maps);
	grp->nr_rp_maps++;
	return CMD_SUCCESS;
}

DEFUN(no_cpu_sched_bind_rp,
      no_cpu_sched_bind_rp_cmd,
      "no cpumask bind range-partition WORD",
      "Remove binding\n"
      "CPU mask operations\n"
      "Bind keyword\n"
      "Range partition keyword\n"
      "Range partition name")
{
	struct gtp_cpu_sched_group *grp = vty->index;
	struct gtp_cpu_sched_rp_map *m, *tmp;

	list_for_each_entry_safe(m, tmp, &grp->rp_maps, next) {
		if (strncmp(m->rp->name, argv[0], GTP_NAME_MAX_LEN - 1))
			continue;
		m->rp->refcnt--;
		list_del(&m->next);
		free(m);
		grp->nr_rp_maps--;
		return CMD_SUCCESS;
	}

	vty_out(vty, "%% range-partition '%s' not bound%s", argv[0], VTY_NEWLINE);
	return CMD_WARNING;
}


static int
cpu_sched_config_write_group(struct gtp_cpu_sched_group *grp, void *arg)
{
	struct vty *vty = arg;
	int cpu;

	vty_out(vty, "cpu-sched-group %s%s", grp->name, VTY_NEWLINE);
	vty_out(vty, " cpumask ");
	vty_out_cpumask(vty, &grp->cpumask);
	vty_out(vty, " algorithm %s%s"
		   , gtp_cpu_sched_algo_str(grp->algo), VTY_NEWLINE);

	if (grp->window != GTP_CPU_SCHED_DEFAULT_WINDOW)
		vty_out(vty, " window %d%s", grp->window, VTY_NEWLINE);
	if (grp->ewma_alpha != GTP_CPU_SCHED_DEFAULT_EWMA_ALPHA)
		vty_out(vty, " ewma-alpha %.2f%s", grp->ewma_alpha, VTY_NEWLINE);

	for (int i = 0; i < GTP_CPU_SCHED_NR_METRICS; i++) {
		if (grp->metric_weights[i] != 1.0f)
			vty_out(vty, " metric-weight %s %.2f%s"
				   , gtp_cpu_sched_metric_str(i)
				   , grp->metric_weights[i], VTY_NEWLINE);
	}

	for (int i = 0; i < grp->nr_constraints; i++) {
		const struct gtp_cpu_sched_constraint *c = &grp->constraints[i];
		if (!c->active)
			continue;
		vty_out(vty, " constraint %s %s %g%s"
			   , gtp_cpu_sched_metric_str(c->metric)
			   , gtp_cpu_sched_cbs_mode_str(c->mode)
			   , c->threshold, VTY_NEWLINE);
	}

	if (grp->fallback_algo != GTP_CPU_SCHED_WLC)
		vty_out(vty, " fallback-algorithm %s%s"
			   , gtp_cpu_sched_algo_str(grp->fallback_algo), VTY_NEWLINE);

	cpuset_for_each(cpu, grp->cpumask, CPU_SETSIZE) {
		if (grp->weights[cpu] == GTP_CPU_SCHED_DEFAULT_WEIGHT)
			continue;
		vty_out(vty, " weight cpu %d %d%s"
			   , cpu, grp->weights[cpu], VTY_NEWLINE);
	}

	struct gtp_cpu_sched_rp_map *m;
	list_for_each_entry(m, &grp->rp_maps, next)
		vty_out(vty, " cpumask bind range-partition %s%s"
			   , m->rp->name, VTY_NEWLINE);

	vty_out(vty, "!%s", VTY_NEWLINE);
	return 0;
}

static int
cpu_sched_config_write(struct vty *vty)
{
	gtp_cpu_sched_foreach(cpu_sched_config_write_group, vty);
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_cpu_sched_install(void)
{
	/* Config commands */
	install_element(CONFIG_NODE, &cpu_sched_group_cmd);
	install_element(CONFIG_NODE, &no_cpu_sched_group_cmd);

	install_default(CPU_SCHED_NODE);
	install_element(CPU_SCHED_NODE, &cpu_sched_cpumask_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_algorithm_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_weight_cmd);
	install_element(CPU_SCHED_NODE, &no_cpu_sched_weight_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_window_cmd);
	install_element(CPU_SCHED_NODE, &no_cpu_sched_window_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_ewma_alpha_cmd);
	install_element(CPU_SCHED_NODE, &no_cpu_sched_ewma_alpha_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_metric_weight_cmd);
	install_element(CPU_SCHED_NODE, &no_cpu_sched_metric_weight_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_constraint_cmd);
	install_element(CPU_SCHED_NODE, &no_cpu_sched_constraint_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_fallback_cmd);
	install_element(CPU_SCHED_NODE, &no_cpu_sched_fallback_cmd);
	install_element(CPU_SCHED_NODE, &cpu_sched_bind_rp_cmd);
	install_element(CPU_SCHED_NODE, &no_cpu_sched_bind_rp_cmd);

	/* Show commands */
	install_element(VIEW_NODE, &show_system_cpu_cmd);
	install_element(VIEW_NODE, &show_cpu_sched_cmd);
	install_element(VIEW_NODE, &show_cpu_sched_name_cmd);
	install_element(ENABLE_NODE, &show_system_cpu_cmd);
	install_element(ENABLE_NODE, &show_cpu_sched_cmd);
	install_element(ENABLE_NODE, &show_cpu_sched_name_cmd);

	/* Debug commands */
	install_element(ENABLE_NODE, &debug_cpu_sched_cmd);
	install_element(ENABLE_NODE, &no_debug_cpu_sched_cmd);

	return 0;
}

struct cmd_node cpu_sched_node = {
	.node = CPU_SCHED_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(cpu-sched)# ",
	.config_write = cpu_sched_config_write,
};

static struct cmd_ext cmd_ext_cpu_sched = {
	.node = &cpu_sched_node,
	.install = cmd_ext_cpu_sched_install,
};

static void __attribute__((constructor))
gtp_cpu_sched_vty_init(void)
{
	cmd_ext_register(&cmd_ext_cpu_sched);
}
