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
#include <time.h>
#include "logger.h"
#include "utils.h"
#include "thread.h"
#include "vty_gauge.h"
#include "cpu.h"
#include "ethtool.h"
#include "gtp_interface.h"
#include "gtp_interface_ethtool.h"
#include "gtp_interface_rxq.h"
#include "gtp_cpu.h"

/* Local data */
static int (*pfcp_count_fn)(int cpu);
struct cpu_load *cpu_load;
struct gauge_history *cpu_history;
static struct gtp_percpu_metrics *percpu_metrics;
static int ethtool_tick;
static uint64_t percpu_prev_ts_ns;

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Per-CPU workload aggregation
 */
static void
gtp_percpu_reset_accum(void)
{
	int i;

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		struct gtp_percpu_metrics *m = &percpu_metrics[i];
		memset(&m->q_stats, 0, sizeof(m->q_stats));
	}
}

static int
gtp_percpu_collect(struct gtp_interface *iface, void *arg)
{
	int cpu_per_q[iface->nr_rx_queues ? : 1];
	uint32_t q, nr;
	int cpu;

	if (!iface->queue_stats)
		return 0;

	nr = max(iface->nr_rx_queues, iface->nr_tx_queues);

	memset(cpu_per_q, -1, sizeof(cpu_per_q));
	gtp_interface_rxq_cpu(iface, cpu_per_q, iface->nr_rx_queues);

	for (q = 0; q < nr; q++) {
		struct ethtool_q_stats *s = &iface->queue_stats[q];

		cpu = (q < iface->nr_rx_queues) ? cpu_per_q[q] : -1;
		if (cpu < 0 || cpu >= cpu_load->nr_cpus)
			continue;
		ethtool_q_stats_add(&percpu_metrics[cpu].q_stats, s);
	}

	return 0;
}

struct gtp_percpu_metrics *
gtp_percpu_metrics_get(int cpu)
{
	if (!percpu_metrics || cpu < 0 || cpu >= cpu_load->nr_cpus)
		return NULL;
	return &percpu_metrics[cpu];
}


static void
gtp_percpu_rates_update(uint64_t now_ns)
{
	uint64_t elapsed = now_ns - percpu_prev_ts_ns;
	int i;

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		struct gtp_percpu_metrics *m = &percpu_metrics[i];

		if (elapsed && percpu_prev_ts_ns) {
			m->rx_bw_bps = (m->q_stats.rx_bytes - m->prev_q_stats.rx_bytes)
				       * 1000000000ULL / elapsed;
			m->tx_bw_bps = (m->q_stats.tx_bytes - m->prev_q_stats.tx_bytes)
				       * 1000000000ULL / elapsed;
			m->total_bw_bps = m->rx_bw_bps + m->tx_bw_bps;
			m->rx_pps = (m->q_stats.rx_packets - m->prev_q_stats.rx_packets)
				    * 1000000000ULL / elapsed;
			m->tx_pps = (m->q_stats.tx_packets - m->prev_q_stats.tx_packets)
				    * 1000000000ULL / elapsed;
			m->rx_buff_alloc_err_rate = (m->q_stats.rx_buff_alloc_err - m->prev_q_stats.rx_buff_alloc_err)
						    * 1000000000ULL / elapsed;
		}
		m->prev_q_stats = m->q_stats;
	}
	percpu_prev_ts_ns = now_ns;
}


/*
 *	Polling thread
 */
static void
gtp_cpu_poll(struct thread *t)
{
	struct timespec ts;
	uint64_t now_ns;
	float load;
	int i;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now_ns = timespec_to_ns(&ts);

	cpu_load_update(cpu_load);
	gtp_percpu_reset_accum();

	/* collect ethtool stats every 3s */
	if (++ethtool_tick >= ETHTOOL_POLL_TICKS) {
		ethtool_tick = 0;
		gtp_interface_foreach(gtp_interface_collect, &now_ns);
		gtp_interface_foreach(gtp_percpu_collect, NULL);

		/* Avoid syscall latency */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		now_ns = timespec_to_ns(&ts);
		gtp_percpu_rates_update(now_ns);
	}

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		load = cpu_load_get(cpu_load, i);
		if (load < 0.0f)
			continue;	/* offline CPU */
		gauge_history_push(&cpu_history[i], load);
		percpu_metrics[i].load = load;
		percpu_metrics[i].pfcp_sessions = pfcp_count_fn ? pfcp_count_fn(i) : 0;
	}

	thread_add_timer(master, gtp_cpu_poll, NULL, TIMER_HZ / 5);
}


/*
 *	CPU monitoring init
 */
void
gtp_cpu_register_pfcp_count(int (*fn)(int cpu))
{
	pfcp_count_fn = fn;
}

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

	percpu_metrics = calloc(cpu_load->nr_cpus, sizeof(*percpu_metrics));
	if (!percpu_metrics) {
		free(cpu_history);
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
	free(percpu_metrics);
	percpu_metrics = NULL;
	return 0;
}
