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

#include <stdio.h>
#include <string.h>
#include "logger.h"
#include "thread.h"
#include "vty.h"
#include "cpu.h"

#define CPU_GAUGE_WIDTH	20
#define CPU_NUMA_MAX	8

/* Local data */
static struct cpu_load *cpu_load;

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Polling thread
 */
static void
gtp_cpu_poll(struct thread *t)
{
	int i;

	cpu_load_update(cpu_load);

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		float load = cpu_load_get(cpu_load, i);
	        if (load < 0.0f)
			continue;   /* offline CPU */
#if 0
		printf("CPU #%i : %f\n", i, load*100);
#endif
	}

	thread_add_timer(master, gtp_cpu_poll, NULL, TIMER_HZ / 5);
}


/*
 *	VTY show
 */
static void
gtp_cpu_gauge_show(struct vty *vty, int cpu, float load)
{
	char bar[CPU_GAUGE_WIDTH + 1];
	int filled, i;

	if (load < 0.0f) {
		vty_out(vty, "  cpu%-3d  [%-*s] offline%s",
			cpu, CPU_GAUGE_WIDTH, "", VTY_NEWLINE);
		return;
	}

	filled = (int)(load * CPU_GAUGE_WIDTH);
	if (filled > CPU_GAUGE_WIDTH)
		filled = CPU_GAUGE_WIDTH;
	for (i = 0; i < CPU_GAUGE_WIDTH; i++)
		bar[i] = (i < filled) ? '#' : '.';
	bar[CPU_GAUGE_WIDTH] = '\0';

	vty_out(vty, "  cpu%-3d  [%s] %5.1f%%%s"
		   , cpu, bar, load * 100.0f, VTY_NEWLINE);
}

/* Walk a cpulist string ("0-3,8,16-19") and show a gauge for each CPU. */
static void
gtp_cpu_list_show(struct vty *vty, const char *list)
{
	const char *p = list;
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
		for (; a <= b; a++)
			gtp_cpu_gauge_show(vty, a, cpu_load_get(cpu_load, a));
		if (*p == ',')
			p++;
	}
}

int
gtp_cpu_vty_show(struct vty *vty)
{
	char path[64], cpulist[256];
	FILE *f;
	int i;

	if (!cpu_load) {
		vty_out(vty, "%% CPU monitoring not available%s", VTY_NEWLINE);
		return -1;
	}

	for (i = 0; i < CPU_NUMA_MAX; i++) {
		snprintf(path, sizeof(path)
			     , "/sys/devices/system/node/node%d/cpulist"
			     , i);
		f = fopen(path, "r");
		if (!f)
			break;

		if (!fgets(cpulist, sizeof(cpulist), f)) {
			fclose(f);
			continue;
		}
		fclose(f);
		cpulist[strcspn(cpulist, "\n")] = '\0';

		vty_out(vty, " NUMA node %d  [cpus: %s]%s"
			   , i, cpulist, VTY_NEWLINE);
		gtp_cpu_list_show(vty, cpulist);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

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

	thread_add_event(master, gtp_cpu_poll, NULL, 0);
	return 0;
}

int
gtp_cpu_destroy(void)
{
	cpu_load_destroy(cpu_load);	
	return 0;
}
