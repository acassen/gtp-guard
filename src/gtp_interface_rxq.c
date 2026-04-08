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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vty.h"
#include "gtp_data.h"
#include "gtp_interface.h"
#include "ethtool.h"
#include "cpu.h"

/* Extern data */
extern struct data *daemon_data;

/* Local stuff */
#define RXQUEUE_MAX		64
#define RXQUEUE_NUMA_MAX	8

struct rxq_numa {
	char cpulist[RXQUEUE_NUMA_MAX][256];
	int cpu_count[RXQUEUE_NUMA_MAX];
	int nr;
};


/* Read /proc/irq/{irq}/effective_affinity_list, fall back to smp_affinity_list. */
static int
rxq_irq_get_affinity(int irq, char *buf, size_t size)
{
	char path[64];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/irq/%d/effective_affinity_list", irq);
	f = fopen(path, "r");
	if (!f) {
		snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity_list", irq);
		f = fopen(path, "r");
	}
	if (!f)
		return -1;
	if (!fgets(buf, size, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	buf[strcspn(buf, "\n")] = '\0';
	return 0;
}

/* Return the first CPU pinned to irq, or -1. */
static int
rxq_irq_get_cpu(int irq)
{
	char cpulist[64];

	if (rxq_irq_get_affinity(irq, cpulist, sizeof(cpulist)) < 0)
		return -1;
	return cpulist_first_cpu(cpulist);
}

/* Resolve PCI BDF for ifname via /sys/class/net/{ifname}/device symlink. */
static int
rxq_iface_get_bdf(const char *ifname, char *bdf, size_t size)
{
	char path[128], link[256];
	char *p;
	int len;

	snprintf(path, sizeof(path), "/sys/class/net/%s/device", ifname);
	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0)
		return -1;
	link[len] = '\0';
	p = strrchr(link, '/');
	p = p ? p + 1 : link;
	len = strnlen(p, size - 1);
	memcpy(bdf, p, len);
	bdf[len] = '\0';
	return 0;
}


/* Get rx_queue from BDF formated buffer */
static int
rxq_get_id_from_bdf(const char *bdf, int bdf_len, const char *end, const char *ns)
{
	int token_len = end - ns;
	int at_off = token_len - bdf_len- 5; /* "@pci:" */
	const char *c, *comp = NULL;

	if (at_off <= 0)
		return -1;
	if (memcmp(ns + at_off, "@pci:", 5) != 0)
		return -1;
	if (memcmp(ns + at_off + 5, bdf, bdf_len) != 0)
		return -1;

	/* looking for _compN in the prefix portion */
	for (c = ns; at_off > 5 && c < ns + at_off - 5; c++) {
		if (memcmp(c, "_comp", 5) == 0 &&
		    c[5] >= '0' && c[5] <= '9') {
			comp = c + 5;
			break;
		}
	}

	return comp ? atoi(comp) : -1;
}

/*
 * Parse /proc/interrupts and fill irqs[] (indexed by queue number) for rx
 * queues of ifname.
 *
 * Strategy 1 - ifname-based: matches {ifname}-rx-{n}, {ifname}-TxRx-{n},
 *   {ifname}-{n} (i40e, ice, ixgbe, igb, bnxt, ...).
 *
 * Strategy 2 - BDF-based: matches *_compN@pci:{bdf}, used by mlx5 which
 *   names interrupts after the PCI device, not the netdev.
 *
 * Returns the highest queue index found + 1, or -1 on error.
 */
static int
rxq_iface_get_irqs(const char *ifname, int *irqs, int max_q)
{
	char bdf[32];
	char line[4096];
	char *p, *end, *ns;
	int ifname_len = strlen(ifname);
	int bdf_len = 0;
	int irq, q, found = 0;
	FILE *f;

	if (rxq_iface_get_bdf(ifname, bdf, sizeof(bdf)) == 0)
		bdf_len = strlen(bdf);

	f = fopen("/proc/interrupts", "r");
	if (!f)
		return -1;

	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return 0;
	}

	while (fgets(line, sizeof(line), f)) {
		p = line;
		while (*p == ' ')
			p++;
		if (*p < '0' || *p > '9')
			continue;
		irq = 0;
		while (*p >= '0' && *p <= '9')
			irq = irq * 10 + (*p++ - '0');
		if (*p != ':')
			continue;

		/* Extract last whitespace-delimited token (interrupt name). */
		line[strcspn(line, "\n\r")] = '\0';
		end = line + strlen(line);
		while (end > line && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
		ns = end;
		while (ns > line && ns[-1] != ' ' && ns[-1] != '\t')
			ns--;
		if (ns == end)
			continue;
		*end = '\0';

		/* Strategy 1: interrupt named after interface */
		q = -1;
		if (strncmp(ns, ifname, ifname_len) == 0 && ns[ifname_len] == '-') {
			p = ns + ifname_len + 1;
			if (strncmp(p, "rx-", 3) == 0)
				q = atoi(p + 3);
			else if (strncmp(p, "TxRx-", 5) == 0)
				q = atoi(p + 5);
			else if (*p >= '0' && *p <= '9')
				q = atoi(p);
		} else if (bdf_len) {
			/* Strategy 2: _compN@pci:{bdf} (mlx5 and similar) */
			q = rxq_get_id_from_bdf(bdf, bdf_len, end, ns);
		}

		if (q >= 0 && q < max_q) {
			irqs[q] = irq;
			if (q + 1 > found)
				found = q + 1;
		}
	}
	fclose(f);
	return found;
}

/* Infer NUMA node from the first IRQ pinned to a NIC queue. */
static int
rxq_iface_numa_from_irq(const char *ifname, const struct rxq_numa *numa)
{
	int irqs[RXQUEUE_MAX];
	int i, cpu, n, nr;

	memset(irqs, -1, sizeof(irqs));
	nr = rxq_iface_get_irqs(ifname, irqs, RXQUEUE_MAX);
	if (nr <= 0)
		return -1;

	for (i = 0; i < nr; i++) {
		if (irqs[i] < 0)
			continue;
		cpu = rxq_irq_get_cpu(irqs[i]);
		if (cpu < 0)
			continue;
		for (n = 0; n < numa->nr; n++) {
			if (cpulist_contains(numa->cpulist[n], cpu))
				return n;
		}
	}
	return -1;
}

/* Return NUMA node for iface using IRQ affinity, physical parent if available. */
static int
rxq_iface_numa(const struct gtp_interface *iface, const struct rxq_numa *numa)
{
	const char *pif = iface->link_iface ? iface->link_iface->ifname
					    : iface->ifname;
	return rxq_iface_numa_from_irq(pif, numa);
}

/* Callback for cpu_foreach_numa_node() to populate rxq_numa. */
static void
rxq_numa_add_node(int node, const char *cpulist, void *arg)
{
	struct rxq_numa *numa = arg;

	if (node >= RXQUEUE_NUMA_MAX)
		return;
	strncpy(numa->cpulist[node], cpulist, sizeof(numa->cpulist[node]) - 1);
	numa->cpulist[node][sizeof(numa->cpulist[node]) - 1] = '\0';
	numa->cpu_count[node] = cpulist_count(cpulist);
	numa->nr = node + 1;
}

/* Load NUMA node cpulists from sysfs. */
static void
rxq_numa_load(struct rxq_numa *numa)
{
	numa->nr = 0;
	cpu_foreach_numa_node(rxq_numa_add_node, numa);
}

/* Display RX queue details for one interface. */
static void
rxq_show_iface_queues(struct vty *vty, struct gtp_interface *iface)
{
	char cpulist[64];
	int irqs[RXQUEUE_MAX];
	uint32_t nr_rx = 0, nr_tx = 0;
	int q;

	ethtool_get_nr_queues(iface->ifname, &nr_rx, &nr_tx);
	if (nr_rx > RXQUEUE_MAX)
		nr_rx = RXQUEUE_MAX;
	memset(irqs, -1, sizeof(irqs));
	rxq_iface_get_irqs(iface->ifname, irqs, RXQUEUE_MAX);

	vty_out(vty, "   %s  rx_queues:%u%s", iface->ifname, nr_rx, VTY_NEWLINE);
	for (q = 0; q < (int)nr_rx; q++) {
		if (irqs[q] < 0) {
			vty_out(vty, "     rx-%-2d  irq:n/a    cpu:n/a%s",
				q, VTY_NEWLINE);
			continue;
		}
		cpulist[0] = '\0';
		rxq_irq_get_affinity(irqs[q], cpulist, sizeof(cpulist));
		vty_out(vty, "     rx-%-2d  irq:%-5d  cpu:%s%s",
			q, irqs[q], cpulist[0] ? cpulist : "?",
			VTY_NEWLINE);
	}
}

/* Display interfaces grouped by NUMA node. */
static void
rxq_show_by_numa(struct vty *vty, struct list_head *l, struct rxq_numa *numa)
{
	struct gtp_interface *iface;
	bool header_printed;
	int n;

	for (n = 0; n < numa->nr; n++) {
		header_printed = false;
		list_for_each_entry(iface, l, next) {
			if (rxq_iface_numa(iface, numa) != n)
				continue;
			if (!header_printed) {
				vty_out(vty, " NUMA node %d  [cpus: %s  %d CPUs]%s",
					n, numa->cpulist[n], numa->cpu_count[n],
					VTY_NEWLINE);
				header_printed = true;
			}
			rxq_show_iface_queues(vty, iface);
		}
		if (header_printed)
			vty_out(vty, "%s", VTY_NEWLINE);
	}
}

/* Display interfaces whose NUMA node could not be determined. */
static void
rxq_show_unknown_numa(struct vty *vty, struct list_head *l, struct rxq_numa *numa)
{
	struct gtp_interface *iface;
	bool header_printed = false;

	list_for_each_entry(iface, l, next) {
		if (rxq_iface_numa(iface, numa) != -1)
			continue;
		if (!header_printed) {
			vty_out(vty, " NUMA node: unknown%s", VTY_NEWLINE);
			header_printed = true;
		}
		rxq_show_iface_queues(vty, iface);
	}
	if (header_printed)
		vty_out(vty, "%s", VTY_NEWLINE);
}

/* Diagnostic Phase 1: capacity, single-CPU pinning, and NUMA locality for one interface. */
static bool
rxq_diag_iface(struct vty *vty, struct gtp_interface *iface, struct rxq_numa *numa)
{
	char cpulist[64];
	int irqs[RXQUEUE_MAX];
	uint32_t nr_rx = 0, nr_tx = 0;
	int iface_numa, q, cpu;
	bool ok = true;

	iface_numa = rxq_iface_numa(iface, numa);
	ethtool_get_nr_queues(iface->ifname, &nr_rx, &nr_tx);
	if (!nr_rx)
		return true;
	if (nr_rx > RXQUEUE_MAX)
		nr_rx = RXQUEUE_MAX;

	memset(irqs, -1, sizeof(irqs));
	rxq_iface_get_irqs(iface->ifname, irqs, RXQUEUE_MAX);

	if (iface_numa >= 0 && iface_numa < numa->nr &&
	    (int)nr_rx > numa->cpu_count[iface_numa]) {
		vty_out(vty, "  [WARN] %s: rx_queue count (%u) exceeds "
			     "NUMA node %d CPU count (%d)%s"
			   , iface->ifname, nr_rx, iface_numa
			   , numa->cpu_count[iface_numa], VTY_NEWLINE);
		ok = false;
	}

	for (q = 0; q < (int)nr_rx; q++) {
		if (irqs[q] < 0)
			continue;
		cpulist[0] = '\0';
		if (rxq_irq_get_affinity(irqs[q], cpulist, sizeof(cpulist)) < 0)
			continue;

		if (cpulist_count(cpulist) != 1) {
			vty_out(vty, "  [WARN] %s: rx-%d irq:%d not pinned to "
				     "single CPU (affinity: %s)%s"
				   , iface->ifname, q, irqs[q], cpulist, VTY_NEWLINE);
			ok = false;
			continue;
		}

		cpu = cpulist_first_cpu(cpulist);
		if (cpu < 0)
			continue;

		if (iface_numa >= 0 && iface_numa < numa->nr &&
		    !cpulist_contains(numa->cpulist[iface_numa], cpu)) {
			vty_out(vty, "  [WARN] %s: rx-%d irq:%d bound to cpu %d "
				     "(not on NUMA node %d)%s"
				   , iface->ifname, q, irqs[q]
				   , cpu, iface_numa, VTY_NEWLINE);
			ok = false;
		}
	}

	if (ok)
		vty_out(vty, "  [ OK ] %s: pinning and NUMA locality correct%s",
			iface->ifname, VTY_NEWLINE);
	return ok;
}

/*
 * Diagnostic Phase 2: each CPU must serve at most one rx queue IRQ
 * system-wide.
 */
static bool
rxq_diag_cpu_uniqueness(struct vty *vty, struct list_head *l)
{
	int assign_cpu[RXQUEUE_MAX * 4];
	int assign_irq[RXQUEUE_MAX * 4];
	int assign_q[RXQUEUE_MAX * 4];
	const char *assign_iface[RXQUEUE_MAX * 4];
	int irqs[RXQUEUE_MAX];
	char cpulist[64];
	struct gtp_interface *iface;
	uint32_t nr_rx, nr_tx;
	int nassigns = 0;
	int k, m, q, cpu;
	bool ok = true;

	list_for_each_entry(iface, l, next) {
		nr_rx = 0;
		nr_tx = 0;
		ethtool_get_nr_queues(iface->ifname, &nr_rx, &nr_tx);
		if (!nr_rx)
			continue;
		if (nr_rx > RXQUEUE_MAX)
			nr_rx = RXQUEUE_MAX;
		memset(irqs, -1, sizeof(irqs));
		rxq_iface_get_irqs(iface->ifname, irqs, RXQUEUE_MAX);

		for (q = 0; q < (int)nr_rx && nassigns < RXQUEUE_MAX * 4; q++) {
			if (irqs[q] < 0)
				continue;
			cpulist[0] = '\0';
			if (rxq_irq_get_affinity(irqs[q], cpulist, sizeof(cpulist)) < 0)
				continue;
			if (cpulist_count(cpulist) != 1)
				continue;
			cpu = cpulist_first_cpu(cpulist);
			if (cpu < 0)
				continue;
			assign_cpu[nassigns] = cpu;
			assign_irq[nassigns] = irqs[q];
			assign_q[nassigns] = q;
			assign_iface[nassigns] = iface->ifname;
			nassigns++;
		}
	}

	for (k = 0; k < nassigns; k++) {
		for (m = k + 1; m < nassigns; m++) {
			if (assign_cpu[k] != assign_cpu[m])
				continue;
			vty_out(vty, "  [WARN] cpu %d shared: %s/rx-%d (irq:%d)"
				     " and %s/rx-%d (irq:%d)%s"
				   , assign_cpu[k]
				   , assign_iface[k], assign_q[k], assign_irq[k]
				   , assign_iface[m], assign_q[m], assign_irq[m]
				   , VTY_NEWLINE);
			ok = false;
		}
	}
	if (ok)
		vty_out(vty, "  [ OK ] all rx queue IRQs use distinct CPUs%s",
			VTY_NEWLINE);
	return ok;
}

/*
 * Fill cpu_per_queue[q] with the primary CPU for each rx queue of iface.
 * Uses the physical parent interface when iface is a VLAN/sub-interface.
 * Entries for queues where affinity cannot be resolved are left as -1.
 * Returns the number of rx queues found, or negative on error.
 */
int
gtp_interface_rxq_cpu(const struct gtp_interface *iface,
		      int *cpu_per_queue, int max_q)
{
	const char *ifname = iface->link_iface ? iface->link_iface->ifname :
						 iface->ifname;
	int irqs[RXQUEUE_MAX];
	int q, n, cpu;

	if (max_q > RXQUEUE_MAX)
		max_q = RXQUEUE_MAX;

	memset(cpu_per_queue, -1, max_q * sizeof(*cpu_per_queue));
	memset(irqs, -1, sizeof(irqs));

	n = rxq_iface_get_irqs(ifname, irqs, max_q);
	if (n <= 0)
		return n;

	for (q = 0; q < n; q++) {
		if (irqs[q] < 0)
			continue;
		cpu = rxq_irq_get_cpu(irqs[q]);
		if (cpu >= 0)
			cpu_per_queue[q] = cpu;
	}

	return n;
}


int
gtp_interface_rxq_show(struct vty *vty)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;
	struct rxq_numa numa;
	bool ok;

	rxq_numa_load(&numa);
	rxq_show_by_numa(vty, l, &numa);
	rxq_show_unknown_numa(vty, l, &numa);

	vty_out(vty, "Diagnostic:%s", VTY_NEWLINE);

	ok = true;
	list_for_each_entry(iface, l, next)
		ok &= rxq_diag_iface(vty, iface, &numa);
	ok &= rxq_diag_cpu_uniqueness(vty, l);

	vty_out(vty, "%s", VTY_NEWLINE);
	if (ok)
		vty_out(vty, "  Overall: rx queue affinity configuration is optimal%s"
			   , VTY_NEWLINE);
	else
		vty_out(vty, "  Overall: rx queue affinity has issues, review warnings above%s"
			   , VTY_NEWLINE);

	return 0;
}
