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

#ifndef _CPU_H
#define _CPU_H

#include <stdint.h>

struct cpu_perf {
	int		fd;		/* perf_event fd, -1 if unavailable */
	uint64_t	prev_cycles;	/* last sampled ref cycle count */
	uint64_t	prev_time_ns;	/* kernel per-CPU wall ns at last sample */
	float		load;		/* [0.0, 1.0]: fraction of unhalted wall time */
};

struct cpu_load {
	struct cpu_perf	*cpus;
	int		nr_cpus;
	uint64_t	base_freq_hz;	/* calibrated mode: cycles→ns conversion; 0 = TSC mode */
	uint64_t	prev_tsc;	/* TSC mode: TSC at last update */
};

/* Prototypes */
int cpu_load_init(struct cpu_load **ctx);
int cpu_load_init_tsc(struct cpu_load **ctx);
void cpu_load_update(struct cpu_load *ctx);
float cpu_load_get(struct cpu_load *ctx, int cpu);
int cpu_load_nr(struct cpu_load *ctx);
void cpu_load_destroy(struct cpu_load *ctx);

#endif
