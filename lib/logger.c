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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

/* Boolean flag - send messages to console instead of syslog */
static bool log_console = false;

void
enable_console_log(void)
{
	log_console = true;
}

void
log_message(const int priority, const char *fmt, ...)
{
	va_list args;
	char buf[512];
	int n;

	va_start(args, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (log_console) {
		char *p = NULL;

		/* output was truncated, we want full output on stderr */
		if (n >= sizeof (buf)) {
			p = malloc(n + 2);
			if (!p)
				return;
			va_start(args, fmt);
			n = vsnprintf(p, n + 1, fmt, args);
			va_end(args);
		} else {
			p = buf;
		}
		/* add trailing '\n' if there is none */
		if (n > 0 && p[n - 1] == '\n')
			p[n - 1] = 0;
		fprintf(stderr, "%s\n", p);
		if (p != buf)
			free(p);
	} else {
		syslog(priority, "%s", buf);
	}
}

void
conf_write(FILE *fp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (fp) {
		vfprintf(fp, fmt, args);
		fprintf(fp, "\n");
	} else
		log_message(LOG_INFO, fmt, args);

	va_end(args);
}
