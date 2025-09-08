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

#include <stdio.h>
#include <signal.h>
#include <syslog.h>

#include "pidfile.h"

/* Create the runnnig daemon pidfile */
int
pidfile_write(char *pathname, int pid)
{
	FILE *pidfile = fopen(pathname, "w");

	if (!pidfile) {
		syslog(LOG_INFO, "pidfile_write : Can not open %s pidfile",
		       pathname);
		return 0;
	}
	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);
	return 1;
}

/* Remove the running daemon pidfile */
void
pidfile_rm(char *pathname)
{
	unlink(pathname);
}

/* return the daemon running state */
int
process_running(char *pathname)
{
	FILE *pidfile = fopen(pathname, "r");
	pid_t pid;
	int ret;

	/* No pidfile */
	if (!pidfile)
		return 0;

	ret = fscanf(pidfile, "%d", &pid);
	if (ret == EOF)
		syslog(LOG_INFO, "Error reading pid file %s (%d)", pathname, ferror(pidfile));
	fclose(pidfile);

	/* If no process is attached to pidfile, remove it */
	if (kill(pid, 0)) {
		syslog(LOG_INFO, "Remove a zombie pid file %s", pathname);
		pidfile_rm(pathname);
		return 0;
	}

	return 1;
}
