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
#include "logger.h"
#include "thread.h"
#include "vty.h"
#include "vty_gauge.h"
#include "vty_matrix.h"
#include "cpu.h"

/* Local data */
static struct cpu_load *cpu_load;
static struct gauge_history *cpu_history;

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Polling thread
 */
static void
gtp_cpu_poll(struct thread *t)
{
	float load;
	int i;

	cpu_load_update(cpu_load);

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		load = cpu_load_get(cpu_load, i);
		if (load < 0.0f)
			continue;	/* offline CPU */
		gauge_history_push(&cpu_history[i], load);
	}

	thread_add_timer(master, gtp_cpu_poll, NULL, TIMER_HZ / 5);
}


/*
 *	VTY show
 */

/* Walk a cpulist string ("0-3,8,16-19") and call vty_gauge for each CPU. */
static void
gtp_cpu_list_gauge(struct vty *vty, const char *list)
{
	const struct gauge_opts defaults = { .style = GAUGE_ASCII };
	struct gauge_opts *opts = vty->priv ? : (void *)&defaults;
	const char *p = list;
	char label[12];
	int a, b;

	while (*p >= '0' && *p <= '9') {
		a = 0;
		while (*p >= '0' && *p <= '9')
			a = a * 10 + (*p++ - '0');
		b = a;
		if (*p == '-') {
			p++;
			b = 0;
			while (*p >= '0' && *p <= '9')
				b = b * 10 + (*p++ - '0');
		}
		for (; a <= b; a++) {
			snprintf(label, sizeof(label), "  cpu%-3d", a);
			opts->h = &cpu_history[a];
			vty_gauge(vty, label, cpu_load_get(cpu_load, a), opts);
		}
		if (*p == ',')
			p++;
	}
}

/* Parse cpulist into matrix_entry[], return count filled. */
static int
gtp_cpu_list_collect(const char *list, struct matrix_entry *e, int max)
{
	const char *p = list;
	int a, b, n = 0;

	while (*p >= '0' && *p <= '9' && n < max) {
		a = 0;
		while (*p >= '0' && *p <= '9')
			a = a * 10 + (*p++ - '0');
		b = a;
		if (*p == '-') {
			p++;
			b = 0;
			while (*p >= '0' && *p <= '9')
				b = b * 10 + (*p++ - '0');
		}
		for (; a <= b && n < max; a++, n++) {
			snprintf(e[n].label, sizeof(e[n].label), "cpu%-3d", a);
			e[n].render = vty_matrix_gauge_render;
			e[n].value = cpu_load_get(cpu_load, a);
		}
		if (*p == ',')
			p++;
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

/*
 *	CPU monitoring init
 */
int
gtp_cpu_init(void)
{
	if (cpu_load_init_tsc(&cpu_load)) {
		log_message(LOG_INFO, "%s(): Error initializing CPU monitoring (%m)"
				    , __FUNCTION__);
		return -1;
	}

	cpu_history = calloc(cpu_load->nr_cpus, sizeof(*cpu_history));
	if (!cpu_history) {
		cpu_load_destroy(cpu_load);
		return -1;
	}

	thread_add_event(master, gtp_cpu_poll, NULL, 0);
	return 0;
}

int
gtp_cpu_destroy(void)
{
	cpu_load_destroy(cpu_load);
	free(cpu_history);
	cpu_history = NULL;
	return 0;
}
