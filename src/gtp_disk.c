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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/un.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;

/*
 *      Restart counter file handling
 */
int
gtp_disk_write_restart_counter(void)
{
        FILE *fcounter;

        fcounter = fopen(daemon_data->restart_counter_filename, "w");
        if (!fcounter)
                return -1;

        fprintf(fcounter, "%hhx\n", daemon_data->restart_counter);
        fclose(fcounter);
        return 0;
}

int
gtp_disk_read_restart_counter(void)
{
	FILE *fcounter;
	int ret;

        fcounter = fopen(daemon_data->restart_counter_filename, "r");
        if (!fcounter)
                return -1;

        ret = fscanf(fcounter, "%hhx\n", &daemon_data->restart_counter);
        if (ret != 1) {
                fclose(fcounter);
                return -1;
        }

        fclose(fcounter);
        return daemon_data->restart_counter;
}

char *
gtp_disk_fd2filename(int fd, char *buffer, size_t bufsize)
{
	struct stat statbuf;
#define RETERROR(s) { \
	snprintf(buffer, bufsize, s); \
	return s; \
}

	if (fd < 0 || buffer == NULL || bufsize == 0)
		RETERROR("invalid");

	/* what is fd ? socket, regular file name, etc... (could be used to get pipe, etc.) */
	if (fstat(fd, &statbuf) == -1) {
		snprintf(buffer, bufsize, "error: %s", strerror(errno));
		return buffer;
	}

	/* fd is a regular file, get its pathname */
	if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode)) {
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
		ssize_t len = readlink(path, buffer, bufsize - 1);
		if (len == -1) {
			snprintf(buffer, bufsize, "error: %s", strerror(errno));
			return buffer;
		}
		buffer[len] = '\0';
		return buffer;
	}

	/* fd is a socket, check for IPv4, IPv6, or Unix socket */
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) == 0) {
		if (addr.ss_family == AF_INET) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
			char local_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ipv4->sin_addr, local_ip, sizeof(local_ip));
			snprintf(buffer, bufsize, "IPv4: %s:%d", local_ip, ntohs(ipv4->sin_port));
		} else if (addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
			char local_ip[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &ipv6->sin6_addr, local_ip, sizeof(local_ip));
			snprintf(buffer, bufsize, "IPv6: [%s]:%d", local_ip, ntohs(ipv6->sin6_port));
		} else if (addr.ss_family == AF_UNIX) {
			struct sockaddr_un *un = (struct sockaddr_un *)&addr;
			snprintf(buffer, bufsize, "Unix Socket: %s", *un->sun_path ? un->sun_path : "(abstract)");
		} else {
			RETERROR("Unknown socket type");
		}

		if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) == 0) {
			char remote_info[PATH_MAX];
			if (addr.ss_family == AF_INET) {
				struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
				char remote_ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &ipv4->sin_addr, remote_ip, sizeof(remote_ip));
				snprintf(remote_info, sizeof(remote_info), " -> Remote: %s:%d", remote_ip, ntohs(ipv4->sin_port));
			} else if (addr.ss_family == AF_INET6) {
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
				char remote_ip[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &ipv6->sin6_addr, remote_ip, sizeof(remote_ip));
				snprintf(remote_info, sizeof(remote_info), " -> Remote: [%s]:%d", remote_ip, ntohs(ipv6->sin6_port));
			} else if (addr.ss_family == AF_UNIX) {
				struct sockaddr_un *un = (struct sockaddr_un *)&addr;
				snprintf(remote_info, sizeof(remote_info), " -> Remote Unix Socket: %s", *un->sun_path ? un->sun_path : "(abstract)");
			}
			strncat(buffer, remote_info, bufsize - strlen(buffer) - 1);
		}
		return buffer;
	}

	RETERROR("Unknown");
#undef RETERROR
}
