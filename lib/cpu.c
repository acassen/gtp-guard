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

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "cpu.h"
#include "logger.h"

/* perf read layout when PERF_FORMAT_TOTAL_TIME_ENABLED is set */
struct perf_read_fmt {
	uint64_t value;
	uint64_t time_enabled; /* kernel per-CPU wall ns; inherently NUMA-local */
};

static long
perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
		int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static inline uint64_t
rdtsc(void)
{
	uint32_t lo, hi;

	asm volatile("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	return ((uint64_t)hi << 32) | lo;
}

/*
 * Calibrate TSC frequency once at init by measuring TSC ticks against
 * CLOCK_MONOTONIC over a short interval. Used only to convert ref-cycles
 * to wall-time fractions when combined with time_enabled.
 */
static uint64_t
tsc_freq_calibrate(void)
{
	struct timespec ts = { .tv_nsec = 20000000 }; /* 20 ms */
	struct timespec t0, t1;
	uint64_t tsc0, tsc1, elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	tsc0 = rdtsc();
	nanosleep(&ts, NULL);
	tsc1 = rdtsc();
	clock_gettime(CLOCK_MONOTONIC, &t1);

	elapsed_ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
		     + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
	return (tsc1 - tsc0) * 1000000000ULL / elapsed_ns;
}


/*
 *	Per-CPU load tracking via hardware reference cycle counter.
 *
 *	PERF_COUNT_HW_REF_CPU_CYCLES increments whenever the CPU is unhalted,
 *	regardless of execution context (tasks, softirq, interrupts). It stops
 *	only during HLT/MWAIT, capturing all work including XDP/NAPI processing
 *	that occurs while the idle task is current.
 *
 *	PERF_FORMAT_TOTAL_TIME_ENABLED provides time_enabled: nanoseconds tracked
 *	by the kernel using per-CPU timekeeping. On multi-socket NUMA systems this
 *	is inherently local to the CPU's own socket, no cross-socket TSC skew.
 *
 *	load = delta(ref_cycles) / (delta(time_enabled_ns) × base_freq_hz / 1e9)
 */
int
cpu_load_init(struct cpu_load **pctx)
{
	struct perf_event_attr attr = {
		.type		= PERF_TYPE_HARDWARE,
		.config		= PERF_COUNT_HW_REF_CPU_CYCLES,
		.size		= sizeof(attr),
		.exclude_idle	= 0,
		.read_format	= PERF_FORMAT_TOTAL_TIME_ENABLED,
	};
	struct perf_read_fmt prf;
	struct cpu_load *ctx;
	int i, nr;

	nr = cpu_nr_possible();
	if (nr <= 0)
		return -1;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	ctx->cpus = calloc(nr, sizeof(*ctx->cpus));
	if (!ctx->cpus) {
		free(ctx);
		return -1;
	}

	ctx->nr_cpus = nr;
	ctx->base_freq_hz = tsc_freq_calibrate();
	if (!ctx->base_freq_hz) {
		log_message(LOG_ERR, "%s(): TSC frequency calibration failed"
				   , __FUNCTION__);
		free(ctx->cpus);
		free(ctx);
		errno = ENODEV;
		return -1;
	}

	for (i = 0; i < nr; i++) {
		ctx->cpus[i].fd = (int)perf_event_open(&attr, -1, i, -1, 0);
		if (ctx->cpus[i].fd < 0) {
			log_message(LOG_ERR, "%s(): perf_event_open cpu%d: (%m)"
					   , __FUNCTION__, i);
			ctx->cpus[i].fd = -1;
			continue;
		}
		if (read(ctx->cpus[i].fd, &prf, sizeof(prf)) != sizeof(prf)) {
			close(ctx->cpus[i].fd);
			ctx->cpus[i].fd = -1;
			continue;
		}
		ctx->cpus[i].prev_cycles = prf.value;
		ctx->cpus[i].prev_time_ns = prf.time_enabled;
	}

	*pctx = ctx;
	return 0;
}

/*
 *	Simplified per-CPU load tracking using the TSC as denominator.
 *
 *	On modern x86 the invariant TSC runs at a fixed crystal-derived rate and
 *	is synchronised across all cores at boot via the QPI/UPI inter-socket
 *	link. Residual cross-socket skew is in the nanosecond range with less than
 *	0.001 % error for the tens-of-milliseconds intervals used by a scheduling
 *	algorithm which can therefore be treated/considered as negligible.
 *
 *	Compared to cpu_load_init(), this variant requires no calibration sleep
 *	and no per-CPU time_enabled field: load = delta(ref_cycles) / delta(tsc) is a
 *	dimensionless ratio that needs no frequency conversion.
 */
int
cpu_load_init_tsc(struct cpu_load **pctx)
{
	struct perf_event_attr attr = {
		.type		= PERF_TYPE_HARDWARE,
		.config		= PERF_COUNT_HW_REF_CPU_CYCLES,
		.size		= sizeof(attr),
		.exclude_idle	= 0,
		/* no read_format: single uint64_t read, no time_enabled */
	};
	struct cpu_load *ctx;
	uint64_t cycles;
	int i, nr;

	nr = cpu_nr_possible();
	if (nr <= 0)
		return -1;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	ctx->cpus = calloc(nr, sizeof(*ctx->cpus));
	if (!ctx->cpus) {
		free(ctx);
		return -1;
	}

	ctx->nr_cpus = nr;

	for (i = 0; i < nr; i++) {
		ctx->cpus[i].fd = (int)perf_event_open(&attr, -1, i, -1, 0);
		if (ctx->cpus[i].fd < 0) {
			log_message(LOG_ERR, "%s(): perf_event_open cpu%d: (%m)"
					   , __FUNCTION__, i);
			ctx->cpus[i].fd = -1;
			continue;
		}
		if (read(ctx->cpus[i].fd, &cycles, sizeof(cycles)) != sizeof(cycles)) {
			close(ctx->cpus[i].fd);
			ctx->cpus[i].fd = -1;
			continue;
		}
		ctx->cpus[i].prev_cycles = cycles;
	}

	ctx->prev_tsc = rdtsc();
	*pctx = ctx;
	return 0;
}

void
cpu_load_update(struct cpu_load *ctx)
{
	struct perf_read_fmt prf;
	uint64_t cycles, delta_cycles, delta_ns, now_tsc, delta_tsc;
	int i;

	/* TSC mode */
	if (!ctx->base_freq_hz) {
		now_tsc = rdtsc();
		delta_tsc = now_tsc - ctx->prev_tsc;
		if (!delta_tsc)
			return;

		for (i = 0; i < ctx->nr_cpus; i++) {
			if (ctx->cpus[i].fd < 0)
				continue;
			if (read(ctx->cpus[i].fd, &cycles, sizeof(cycles)) != sizeof(cycles))
				continue;

			ctx->cpus[i].load = (float)(cycles - ctx->cpus[i].prev_cycles)
					    / (float)delta_tsc;
			if (ctx->cpus[i].load > 1.0f)
				ctx->cpus[i].load = 1.0f;

			ctx->cpus[i].prev_cycles = cycles;
		}

		ctx->prev_tsc = now_tsc;
		return;
	}

	/* calibrated mode */
	for (i = 0; i < ctx->nr_cpus; i++) {
		if (ctx->cpus[i].fd < 0)
			continue;
		if (read(ctx->cpus[i].fd, &prf, sizeof(prf)) != sizeof(prf))
			continue;

		delta_cycles = prf.value - ctx->cpus[i].prev_cycles;
		delta_ns = prf.time_enabled - ctx->cpus[i].prev_time_ns;
		if (!delta_ns)
			continue;

		ctx->cpus[i].load = (float)((double)delta_cycles * 1e9
					    / ((double)delta_ns
					    * (double)ctx->base_freq_hz));
		if (ctx->cpus[i].load > 1.0f)
			ctx->cpus[i].load = 1.0f;

		ctx->cpus[i].prev_cycles = prf.value;
		ctx->cpus[i].prev_time_ns = prf.time_enabled;
	}
}

float
cpu_load_get(struct cpu_load *ctx, int cpu)
{
	if (cpu < 0 || cpu >= ctx->nr_cpus || ctx->cpus[cpu].fd < 0)
		return -1.0f;
	return ctx->cpus[cpu].load;
}

int
cpu_load_nr(struct cpu_load *ctx)
{
	return ctx->nr_cpus;
}

void
cpu_load_destroy(struct cpu_load *ctx)
{
	int i;

	if (!ctx)
		return;

	for (i = 0; i < ctx->nr_cpus; i++) {
		if (ctx->cpus[i].fd >= 0)
			close(ctx->cpus[i].fd);
	}
	free(ctx->cpus);
	free(ctx);
}


/*
 *	Helpers
 */
void
cpu_foreach_numa_node(void (*fn)(int node, const char *cpulist, void *arg),
		      void *arg)
{
	char path[64], cpulist[256];
	ssize_t n;
	int fd, i;

	for (i = 0; i < CPU_NUMA_MAX; i++) {
		snprintf(path, sizeof(path),
			 "/sys/devices/system/node/node%d/cpulist", i);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			break;
		n = read(fd, cpulist, sizeof(cpulist) - 1);
		close(fd);
		if (n <= 0)
			continue;
		cpulist[n] = '\0';
		cpulist[strcspn(cpulist, "\n")] = '\0';
		fn(i, cpulist, arg);
	}
}

static int
cpulist_foreach_range(const char *cpulist,
		      void (*fn)(int lo, int hi, void *arg), void *arg)
{
	const char *p = cpulist;
	int lo, hi;

	while (*p >= '0' && *p <= '9') {
		lo = 0;
		while (*p >= '0' && *p <= '9')
			lo = lo * 10 + (*p++ - '0');
		hi = lo;
		if (*p == '-') {
			p++;
			hi = 0;
			while (*p >= '0' && *p <= '9')
				hi = hi * 10 + (*p++ - '0');
		}
		if (lo > hi)
			return -1;
		fn(lo, hi, arg);
		if (*p == ',')
			p++;
	}

	return 0;
}

static void
cpuset_add_range(int lo, int hi, void *arg)
{
	cpu_set_t *set = arg;
	int i;

	for (i = lo; i <= hi; i++)
		CPU_SET(i, set);
}

void
cpulist_to_set(const char *cpulist, cpu_set_t *set)
{
	CPU_ZERO(set);
	cpulist_foreach_range(cpulist, cpuset_add_range, set);
}

static void
track_max(int lo __attribute__((unused)), int hi, void *arg)
{
	int *max = arg;

	if (hi > *max)
		*max = hi;
}

int
cpu_nr_possible(void)
{
	char buf[128];
	int fd, max = -1;
	ssize_t n;

	fd = open("/sys/devices/system/cpu/possible", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (int)sysconf(_SC_NPROCESSORS_CONF);

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return (int)sysconf(_SC_NPROCESSORS_CONF);
	buf[n] = '\0';

	if (cpulist_foreach_range(buf, track_max, &max) < 0 || max < 0)
		return (int)sysconf(_SC_NPROCESSORS_CONF);

	return max + 1;
}
