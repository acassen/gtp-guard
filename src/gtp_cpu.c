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
#include "thread.h"
#include "vty.h"
#include "vty_gauge.h"
#include "vty_matrix.h"
#include "cpu.h"
#include "ethtool.h"
#include "gtp_interface.h"
#include "gtp_interface_rxq.h"
#include "gtp_bpf_ifrules.h"
#include "gtp_cpu.h"

/* Local data */
static struct cpu_load *cpu_load;
static struct gauge_history *cpu_history;
static struct gtp_percpu_metrics *percpu_metrics;

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Interface stats collection
 */
#define STAT_NAME_LEN    32

/* same order as gtp_if_phy_stats fields */
static const char * const phy_stat_names[N_PHY_STATS] = {
	"tx_packets_phy", "rx_packets_phy",
	"tx_bytes_phy", "rx_bytes_phy",
	"rx_discards_phy", "tx_discards_phy",
	"tx_errors_phy",
	"rx_64_bytes_phy", "rx_65_to_127_bytes_phy",
	"rx_128_to_255_bytes_phy", "rx_256_to_511_bytes_phy",
	"rx_512_to_1023_bytes_phy", "rx_1024_to_1518_bytes_phy",
	"rx_1519_to_2047_bytes_phy", "rx_2048_to_4095_bytes_phy",
	"rx_4096_to_8191_bytes_phy", "rx_8192_to_10239_bytes_phy",
};

/* format strings for per-queue names; queue index substituted with %d */
static const char rx_queue_stat_fmt[N_QUEUE_RX_STATS][STAT_NAME_LEN] = {
	"rx%d_packets", "rx%d_bytes",
	"rx%d_xdp_drop", "rx%d_xdp_redirect",
	"rx%d_xdp_tx_xmit", "rx%d_xdp_tx_mpwqe",
	"rx%d_xdp_tx_inlnw", "rx%d_xdp_tx_nops",
	"rx%d_xdp_tx_full", "rx%d_xdp_tx_err",
	"rx%d_xdp_tx_cqes",
};

static const char tx_queue_stat_fmt[N_QUEUE_TX_STATS][STAT_NAME_LEN] = {
	"tx%d_packets", "tx%d_bytes",
	"tx%d_stopped", "tx%d_dropped", "tx%d_xmit_more",
	"tx%d_xdp_xmit", "tx%d_xdp_mpwqe", "tx%d_xdp_inlnw",
	"tx%d_xdp_nops", "tx%d_xdp_full", "tx%d_xdp_err",
	"tx%d_xdp_cqes",
};

static void
gtp_interface_collect_phy(struct gtp_interface *iface)
{
	uint64_t v[N_PHY_STATS];
	struct gtp_if_phy_stats *s = &iface->phy_stats;

	if (ethtool_gstats_get(iface->ifname, phy_stat_names, v, N_PHY_STATS) < 0)
		return;

	s->tx_packets    = v[0];  s->rx_packets    = v[1];
	s->tx_bytes      = v[2];  s->rx_bytes      = v[3];
	s->rx_discards   = v[4];  s->tx_discards   = v[5];
	s->tx_errors     = v[6];
	s->rx_64         = v[7];  s->rx_65_127     = v[8];
	s->rx_128_255    = v[9];  s->rx_256_511    = v[10];
	s->rx_512_1023   = v[11]; s->rx_1024_1518  = v[12];
	s->rx_1519_2047  = v[13]; s->rx_2048_4095  = v[14];
	s->rx_4096_8191  = v[15]; s->rx_8192_10239 = v[16];
}

static void
gtp_interface_collect_queue(struct gtp_interface *iface, int q)
{
	char gen[N_QUEUE_STATS][STAT_NAME_LEN];
	const char *ptrs[N_QUEUE_STATS];
	uint64_t v[N_QUEUE_STATS];
	struct gtp_if_queue_stats *s = &iface->queue_stats[q];
	int i;

	for (i = 0; i < N_QUEUE_RX_STATS; i++) {
		snprintf(gen[i], STAT_NAME_LEN, rx_queue_stat_fmt[i], q);
		ptrs[i] = gen[i];
	}
	for (i = 0; i < N_QUEUE_TX_STATS; i++) {
		snprintf(gen[N_QUEUE_RX_STATS + i], STAT_NAME_LEN,
			 tx_queue_stat_fmt[i], q);
		ptrs[N_QUEUE_RX_STATS + i] = gen[N_QUEUE_RX_STATS + i];
	}

	if (ethtool_gstats_get(iface->ifname, ptrs, v, N_QUEUE_STATS) < 0)
		return;

	s->rx_packets      = v[0];  s->rx_bytes        = v[1];
	s->rx_xdp_drop     = v[2];  s->rx_xdp_redirect = v[3];
	s->rx_xdp_tx_xmit  = v[4];  s->rx_xdp_tx_mpwqe = v[5];
	s->rx_xdp_tx_inlnw = v[6];  s->rx_xdp_tx_nops  = v[7];
	s->rx_xdp_tx_full  = v[8];  s->rx_xdp_tx_err   = v[9];
	s->rx_xdp_tx_cqes  = v[10];
	s->tx_packets      = v[11]; s->tx_bytes        = v[12];
	s->tx_stopped      = v[13]; s->tx_dropped      = v[14];
	s->tx_xmit_more    = v[15];
	s->tx_xdp_xmit     = v[16]; s->tx_xdp_mpwqe    = v[17];
	s->tx_xdp_inlnw    = v[18]; s->tx_xdp_nops     = v[19];
	s->tx_xdp_full     = v[20]; s->tx_xdp_err      = v[21];
	s->tx_xdp_cqes     = v[22];
}

static int
gtp_interface_collect(struct gtp_interface *iface, void *arg)
{
	uint64_t now_ns = *(uint64_t *)arg;
	uint64_t elapsed;
	uint32_t q, nr;

	gtp_interface_collect_phy(iface);

	if (iface->queue_stats) {
		nr = iface->nr_rx_queues > iface->nr_tx_queues ?
		     iface->nr_rx_queues : iface->nr_tx_queues;
		for (q = 0; q < nr; q++)
			gtp_interface_collect_queue(iface, q);
	}

	/* bandwidth from PHY byte counters */
	if (iface->prev_ts_ns) {
		elapsed = now_ns - iface->prev_ts_ns;
		if (elapsed) {
			iface->rx_bw_bps = (iface->phy_stats.rx_bytes -
					    iface->prev_rx_bytes)
					   * 1000000000ULL / elapsed;
			iface->tx_bw_bps = (iface->phy_stats.tx_bytes -
					    iface->prev_tx_bytes)
					   * 1000000000ULL / elapsed;
		}
	}
	iface->prev_rx_bytes = iface->phy_stats.rx_bytes;
	iface->prev_tx_bytes = iface->phy_stats.tx_bytes;
	iface->prev_ts_ns = now_ns;

	return 0;
}


/*
 *	Per-CPU workload aggregation
 */
static int
gtp_percpu_collect(struct gtp_interface *iface, void *arg)
{
	struct gtp_bpf_ifrule_metrics bpf_m[cpu_load->nr_cpus];
	int cpu_per_q[iface->nr_rx_queues ? : 1];
	uint32_t q, nr;
	int cpu;

	if (!iface->queue_stats)
		return 0;

	nr = iface->nr_rx_queues > iface->nr_tx_queues ?
	     iface->nr_rx_queues : iface->nr_tx_queues;

	memset(cpu_per_q, -1, sizeof(cpu_per_q));
	gtp_interface_rxq_cpu(iface, cpu_per_q, iface->nr_rx_queues);

	for (q = 0; q < nr; q++) {
		struct gtp_if_queue_stats *s = &iface->queue_stats[q];

		cpu = (q < iface->nr_rx_queues) ? cpu_per_q[q] : -1;
		if (cpu < 0 || cpu >= cpu_load->nr_cpus)
			continue;
		percpu_metrics[cpu].rx_packets      += s->rx_packets;
		percpu_metrics[cpu].rx_bytes        += s->rx_bytes;
		percpu_metrics[cpu].rx_xdp_drop     += s->rx_xdp_drop;
		percpu_metrics[cpu].rx_xdp_redirect += s->rx_xdp_redirect;
		percpu_metrics[cpu].rx_xdp_tx_xmit  += s->rx_xdp_tx_xmit;
		percpu_metrics[cpu].rx_xdp_tx_mpwqe += s->rx_xdp_tx_mpwqe;
		percpu_metrics[cpu].rx_xdp_tx_inlnw += s->rx_xdp_tx_inlnw;
		percpu_metrics[cpu].rx_xdp_tx_nops  += s->rx_xdp_tx_nops;
		percpu_metrics[cpu].rx_xdp_tx_full  += s->rx_xdp_tx_full;
		percpu_metrics[cpu].rx_xdp_tx_err   += s->rx_xdp_tx_err;
		percpu_metrics[cpu].rx_xdp_tx_cqes  += s->rx_xdp_tx_cqes;
		percpu_metrics[cpu].tx_packets      += s->tx_packets;
		percpu_metrics[cpu].tx_bytes        += s->tx_bytes;
		percpu_metrics[cpu].tx_stopped      += s->tx_stopped;
		percpu_metrics[cpu].tx_dropped      += s->tx_dropped;
		percpu_metrics[cpu].tx_xmit_more    += s->tx_xmit_more;
		percpu_metrics[cpu].tx_xdp_xmit     += s->tx_xdp_xmit;
		percpu_metrics[cpu].tx_xdp_mpwqe    += s->tx_xdp_mpwqe;
		percpu_metrics[cpu].tx_xdp_inlnw    += s->tx_xdp_inlnw;
		percpu_metrics[cpu].tx_xdp_nops     += s->tx_xdp_nops;
		percpu_metrics[cpu].tx_xdp_full     += s->tx_xdp_full;
		percpu_metrics[cpu].tx_xdp_err      += s->tx_xdp_err;
		percpu_metrics[cpu].tx_xdp_cqes     += s->tx_xdp_cqes;
	}

	if (!gtp_bpf_ifrules_all_cpu_metrics(iface, bpf_m, cpu_load->nr_cpus)) {
		for (cpu = 0; cpu < cpu_load->nr_cpus; cpu++) {
			percpu_metrics[cpu].bpf_pkt_in   += bpf_m[cpu].pkt_in;
			percpu_metrics[cpu].bpf_bytes_in += bpf_m[cpu].bytes_in;
			percpu_metrics[cpu].bpf_pkt_fwd  += bpf_m[cpu].pkt_fwd;
		}
	}

	return 0;
}

const struct gtp_percpu_metrics *
gtp_percpu_metrics_get(int cpu)
{
	if (!percpu_metrics || cpu < 0 || cpu >= cpu_load->nr_cpus)
		return NULL;
	return &percpu_metrics[cpu];
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
	now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	cpu_load_update(cpu_load);

	if (percpu_metrics)
		memset(percpu_metrics, 0, cpu_load->nr_cpus * sizeof(*percpu_metrics));

	gtp_interface_foreach(gtp_interface_collect, &now_ns);
	gtp_interface_foreach(gtp_percpu_collect, NULL);

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		load = cpu_load_get(cpu_load, i);
		if (load < 0.0f)
			continue;	/* offline CPU */
		gauge_history_push(&cpu_history[i], load);
		if (percpu_metrics) {
			percpu_metrics[i].load = load;
			percpu_metrics[i].sys_rx_pkts = percpu_metrics[i].rx_packets -
						        percpu_metrics[i].bpf_pkt_in;
		}
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
