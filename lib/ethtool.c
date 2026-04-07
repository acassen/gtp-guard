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
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/netlink.h>

#include "utils.h"
#include "logger.h"

#define MAX_DEV_QUEUE_PATH_LEN 64


/*
 *	sysfs helpers
 */
int
sysfs_set_iface_forwarding(const char *ifname, bool ipv4, bool ipv6)
{
	const char *protos[] = { "ipv4", "ipv6" };
	const bool enabled[] = { ipv4, ipv6 };
	const char on[3] = "1\n";
	ssize_t nbytes = 0;
	char path[256];
	int fd, i;

	for (i = 0; i < 2; i++) {
		if (!enabled[i])
			continue;

		snprintf(path, sizeof(path), "/proc/sys/net/%s/conf/%s/forwarding",
			 protos[i], ifname);

		fd = open(path, O_WRONLY);
		if (fd < 0) {
			log_message(LOG_ERR, "%s: %m", path);
			return -1;
		}

		nbytes = write(fd, on, sizeof(on));
		close(fd);
		if (nbytes < 0) {
			log_message(LOG_ERR, "%s: %m", path);
			return -1;
		}
	}

	return 0;
}

static void
sysfs_get_queues_from_sysfs(const char* ifname, uint32_t *rx, uint32_t *tx)
{
	char buf[MAX_DEV_QUEUE_PATH_LEN];
	struct dirent *entry;
	DIR *dir;

	snprintf(buf, MAX_DEV_QUEUE_PATH_LEN, "/sys/class/net/%s/queues/",
		 ifname);

	dir = opendir(buf);
	if (dir == NULL)
		return;

	while ((entry = readdir(dir))) {
		if (!strncmp(entry->d_name, "rx", 2))
			++*rx;

		if (!strncmp(entry->d_name, "tx", 2))
			++*tx;
	}

	closedir(dir);
}


/*
 *	ethtool helpers
 */
static int
ethtool_open(void)
{
	int fd;

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	return fd;
}

static int
ethtool_send(int fd, const char *ifname, void *cmd)
{
	struct ifreq ifr = {};

	bsd_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = cmd;
	return ioctl(fd, SIOCETHTOOL, &ifr);
}


/*
 * get configured number of rx/tx queues for requested iface,
 * from kernel ethtool
 */
int
ethtool_get_nr_queues(const char *ifname, uint32_t *rx, uint32_t *tx)
{
	struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct ifreq ifr = {};
	int fd, err;

	fd = ethtool_open();
	if (fd < 0)
		return -errno;

	*rx = 0;
	*tx = 0;

	err = ethtool_send(fd, ifname, &channels);
	if (err && errno != EOPNOTSUPP) {
		close(fd);
		return -errno;
	}

	if (err) {
		/* If the device says it has no channels, try to get rx tx
		 * from sysfs */
		sysfs_get_queues_from_sysfs(ifr.ifr_name, rx, tx);
		goto end;
	}

	/* Take the max of rx, tx, combined. Drivers return
	 * the number of channels in different ways.
	 */
	*rx = channels.rx_count;
	if (!*rx)
		*rx = channels.combined_count;
	*tx = channels.tx_count;
	if (!*tx)
		*tx = channels.combined_count;

end:
	close(fd);

	return *rx > 0 && *tx > 0 ? 0 : -1;
}


/*
 * Fetch named ethtool stats for ifname.
 * names is an array of n stat name strings (ETH_GSTRING_LEN max each).
 * out is filled with the corresponding value if found.
 */
int
ethtool_gstats_get(const char *ifname, const char * const *names,
		   uint64_t *out, int n)
{
	struct ethtool_drvinfo drvinfo = { .cmd = ETHTOOL_GDRVINFO };
	struct ethtool_gstrings *gstrings = NULL;
	struct ethtool_stats *stats = NULL;
	uint32_t nstats;
	int fd, i, j, ret = 0;

	fd = ethtool_open();
	if (fd < 0)
		return -errno;

	if (ethtool_send(fd, ifname, &drvinfo) < 0) {
		close(fd);
		return -errno;
	}
	nstats = drvinfo.n_stats;

	if (!nstats) {
		close(fd);
		return -ENODATA;
	}

	memset(out, 0, n * sizeof(*out));

	gstrings = calloc(1, sizeof(*gstrings) + nstats * ETH_GSTRING_LEN);
	if (!gstrings)
		goto end;

	gstrings->cmd = ETHTOOL_GSTRINGS;
	gstrings->string_set = ETH_SS_STATS;
	gstrings->len = nstats;
	if (ethtool_send(fd, ifname, gstrings) < 0) {
		ret = -errno;
		goto end;
	}

	stats = calloc(1, sizeof(*stats) + nstats * sizeof(uint64_t));
	if (!stats)
		goto end;

	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = nstats;
	if (ethtool_send(fd, ifname, stats) < 0) {
		ret = -errno;
		goto end;
	}

	for (i = 0; i < n; i++) {
		for (j = 0; j < (int)nstats; j++) {
			const char *s = (char *)gstrings->data + j * ETH_GSTRING_LEN;
			if (!strncmp(names[i], s, ETH_GSTRING_LEN)) {
				out[i] = stats->data[j];
				break;
			}
		}
	}

end:
	free(gstrings);
	free(stats);
	close(fd);
	return ret;
}
