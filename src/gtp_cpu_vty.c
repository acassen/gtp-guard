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

/* Extern data */
extern struct cpu_load *cpu_load;
extern struct gauge_history *cpu_history;


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
      "Algorithm (rr|wrr|lc|wlc|sed|nq|ll|lbw|lpps)")
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
		snprintf(label, sizeof(label), "  cpu%-3d", cpu);
		opts->h = &cpu_history[cpu];
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
	vty_out(vty, "  CPU   Weight   Sessions   Load    BW(Mbps)     PPS%s"
		   , VTY_NEWLINE);

	cpuset_for_each(cpu, grp->cpumask, CPU_SETSIZE) {
		m = gtp_percpu_metrics_get(cpu);
		if (!m)
			continue;
		vty_out(vty, "  %3d   %5d   %8u   %.2f   %8.1f  %7" PRIu64 "%s"
			   , cpu
			   , grp->weights ? grp->weights[cpu] : GTP_CPU_SCHED_DEFAULT_WEIGHT
			   , m->pfcp_sessions
			   , m->load
			   , (double)m->total_bw_bps / 125000.0
			   , m->rx_pps + m->tx_pps
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

	cpuset_for_each(cpu, grp->cpumask, CPU_SETSIZE) {
		if (grp->weights[cpu] == GTP_CPU_SCHED_DEFAULT_WEIGHT)
			continue;
		vty_out(vty, " weight cpu %d %d%s"
			   , cpu, grp->weights[cpu], VTY_NEWLINE);
	}

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
