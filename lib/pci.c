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

#include <stdbool.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "pci.h"
#include "utils.h"
#include "command.h"

#define SYSFS_PCI_DEVICES	"/sys/bus/pci/devices"
#define PCI_CLASS_ETH		0x020000
#define PCI_CLASS_ETH_MASK	0xffff00
#define PCI_PATH_MAX		768

/* Tree drawing */
#define T_MID	"├── "
#define T_END	"└── "
#define T_CONT	"│   "
#define T_SKIP	"    "

static const char * const pci_ids_paths[] = {
	"/usr/share/misc/pci.ids",
	"/usr/share/hwdata/pci.ids",
	NULL
};


/*
 *	Helpers
 */
static int
sysfs_read(const char *path, char *buf, size_t size)
{
	int fd, len;

	if (size < 2)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, size - 1);
	close(fd);
	if (len <= 0)
		return -1;

	if (buf[len - 1] == '\n')
		len--;
	buf[len] = '\0';
	return 0;
}

static void
pci_collect_netifs(const char *dev_path, char *buf, size_t size)
{
	char net_path[PCI_PATH_MAX];
	struct dirent *de;
	size_t off = 0;
	DIR *dir;

	buf[0] = '\0';
	snprintf(net_path, sizeof(net_path), "%s/net", dev_path);
	dir = opendir(net_path);
	if (!dir)
		return;

	while ((de = readdir(dir)) && off < size - 1) {
		if (de->d_name[0] == '.')
			continue;
		if (off != 0)
			off += scnprintf(buf + off, size - off, ",");
		off += scnprintf(buf + off, size - off, "%s", de->d_name);
	}
	closedir(dir);
}

static void
pci_read_driver(const char *dev_path, char *buf, size_t size)
{
	char drv_path[PCI_PATH_MAX], link[PCI_PATH_MAX];
	size_t n;
	char *p;
	int len;

	buf[0] = '\0';
	snprintf(drv_path, sizeof(drv_path), "%s/driver", dev_path);
	len = readlink(drv_path, link, sizeof(link) - 1);
	if (len < 0)
		return;

	link[len] = '\0';
	p = strrchr(link, '/');
	p = p ? p + 1 : link;
	n = strnlen(p, size - 1);
	memcpy(buf, p, n);
	buf[n] = '\0';
}

static void
pci_ids_lookup(FILE *f, unsigned long vid, unsigned long did,
	       char *vname, size_t vsz, char *dname, size_t dsz)
{
	bool in_vendor = false;
	unsigned long id;
	char line[256];
	char *p, *end;

	vname[0] = dname[0] = '\0';
	rewind(f);

	while (fgets(line, sizeof(line), f)) {
		if (line[0] == '#' || line[0] == '\n')
			continue;

		if (line[0] != '\t') {
			id = strtoul(line, &end, 16);
			if (end - line == 4 && *end == ' ' && id == vid) {
				p = end;
				while (*p == ' ') p++;
				p[strcspn(p, "\n")] = '\0';
				strncpy(vname, p, vsz - 1);
				vname[vsz - 1] = '\0';
				in_vendor = true;
			} else if (in_vendor) {
				break;
			}
		} else if (in_vendor && line[1] != '\t') {
			id = strtoul(line + 1, &end, 16);
			if (end - (line + 1) == 4 && *end == ' ' && id == did) {
				p = end;
				while (*p == ' ') p++;
				p[strcspn(p, "\n")] = '\0';
				strncpy(dname, p, dsz - 1);
				dname[dsz - 1] = '\0';
				break;
			}
		}
	}
}

static int
pci_dev_cmp(const void *a, const void *b)
{
	const struct pci_eth_dev *da = a, *db = b;
	int na = da->numa_node < 0 ? INT_MAX : da->numa_node;
	int nb = db->numa_node < 0 ? INT_MAX : db->numa_node;

	if (na != nb)
		return na - nb;
	return strcmp(da->bdf, db->bdf);
}


/*
 *	Enumerate ethernet PCI devices enriched with pci.ids names and
 *	sorted by NUMA node.
 */
int
pci_eth_dev_fetch(struct pci_eth_dev *devs, int max_devs)
{
	char dev_path[512], path[PCI_PATH_MAX], buf[64];
	unsigned long class_val;
	struct dirent *de;
	FILE *pci_ids = NULL;
	int ndevs = 0;
	size_t n;
	DIR *dir;
	int i;

	dir = opendir(SYSFS_PCI_DEVICES);
	if (!dir)
		return -1;

	while ((de = readdir(dir)) && ndevs < max_devs) {
		if (de->d_name[0] == '.')
			continue;

		snprintf(dev_path, sizeof(dev_path),
			 SYSFS_PCI_DEVICES "/%s", de->d_name);

		snprintf(path, sizeof(path), "%s/class", dev_path);
		if (sysfs_read(path, buf, sizeof(buf)) < 0)
			continue;

		class_val = strtoul(buf, NULL, 16);
		if ((class_val & PCI_CLASS_ETH_MASK) != PCI_CLASS_ETH)
			continue;

		memset(&devs[ndevs], 0, sizeof(devs[ndevs]));

		n = strnlen(de->d_name, sizeof(devs[ndevs].bdf) - 1);
		memcpy(devs[ndevs].bdf, de->d_name, n);
		devs[ndevs].bdf[n] = '\0';

		devs[ndevs].numa_node = -1;
		snprintf(path, sizeof(path), "%s/numa_node", dev_path);
		if (sysfs_read(path, buf, sizeof(buf)) == 0)
			devs[ndevs].numa_node = atoi(buf);

		snprintf(path, sizeof(path), "%s/vendor", dev_path);
		if (sysfs_read(path, buf, sizeof(buf)) == 0)
			devs[ndevs].vendor_id = strtoul(buf, NULL, 16);

		snprintf(path, sizeof(path), "%s/device", dev_path);
		if (sysfs_read(path, buf, sizeof(buf)) == 0)
			devs[ndevs].device_id = strtoul(buf, NULL, 16);

		pci_read_driver(dev_path, devs[ndevs].driver, sizeof(devs[ndevs].driver));
		pci_collect_netifs(dev_path, devs[ndevs].netifs, sizeof(devs[ndevs].netifs));
		ndevs++;
	}
	closedir(dir);

	for (i = 0; pci_ids_paths[i]; i++) {
		pci_ids = fopen(pci_ids_paths[i], "r");
		if (pci_ids)
			break;
	}
	if (pci_ids) {
		for (i = 0; i < ndevs; i++)
			pci_ids_lookup(pci_ids,
				       devs[i].vendor_id, devs[i].device_id,
				       devs[i].vendor_name, sizeof(devs[i].vendor_name),
				       devs[i].device_name, sizeof(devs[i].device_name));
		fclose(pci_ids);
	}

	qsort(devs, ndevs, sizeof(*devs), pci_dev_cmp);
	return ndevs;
}

/* Format one device's detail lines into buffer at offset pos. */
static size_t
pci_dev_format(const struct pci_eth_dev *dev, const char *l1, const char *l2,
	       char *buffer, size_t size)
{
	size_t pos = 0;

	pos += scnprintf(buffer + pos, size - pos, "%s%s" T_MID "vendor: %s [%04lx]\n",
			 l1, l2,
			 dev->vendor_name[0] ? dev->vendor_name : "unknown",
			 dev->vendor_id);

	pos += scnprintf(buffer + pos, size - pos, "%s%s%smodel:  %s [%04lx]\n",
			 l1, l2,
			 (dev->driver[0] || dev->netifs[0]) ? T_MID : T_END,
			 dev->device_name[0] ? dev->device_name : "unknown",
			 dev->device_id);

	if (dev->driver[0])
		pos += scnprintf(buffer + pos, size - pos, "%s%s%sdriver: %s\n",
				 l1, l2, dev->netifs[0] ? T_MID : T_END, dev->driver);

	if (dev->netifs[0])
		pos += scnprintf(buffer + pos, size - pos, "%s%s" T_END "net:    %s\n",
				 l1, l2, dev->netifs);

	return pos;
}

void
pci_eth_dev_vty(struct vty *vty, struct pci_eth_dev *devs, int ndevs)
{
	int numa_nodes[PCI_MAX_ETH_DEVS], n_numa;
	char buffer[512];
	int i, j, k;

	/* Collect unique NUMA nodes (devs sorted by NUMA then BDF) */
	for (i = 0, n_numa = 0; i < ndevs; i++) {
		if (i == 0 || devs[i].numa_node != devs[i-1].numa_node)
			numa_nodes[n_numa++] = devs[i].numa_node;
	}

	vty_out(vty, "PCI ethernet topology\n");

	for (i = 0, j = 0; i < n_numa; i++) {
		bool last_numa = (i == n_numa - 1);
		int numa = numa_nodes[i];
		int start = j;

		if (numa < 0)
			vty_out(vty, "%sNUMA node: none\n",
				last_numa ? T_END : T_MID);
		else
			vty_out(vty, "%sNUMA node %d\n",
				last_numa ? T_END : T_MID, numa);

		while (j < ndevs && devs[j].numa_node == numa)
			j++;

		for (k = start; k < j; k++) {
			bool last_dev = (k == j - 1);
			const char *l1 = last_numa ? T_SKIP : T_CONT;
			const char *l2 = last_dev  ? T_SKIP : T_CONT;

			vty_out(vty, "%s%s%s\n",
				l1, last_dev ? T_END : T_MID, devs[k].bdf);
			pci_dev_format(&devs[k], l1, l2, buffer, sizeof(buffer));
			vty_out(vty, "%s", buffer);
		}
	}
}
