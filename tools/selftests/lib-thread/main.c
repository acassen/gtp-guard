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
 * Authors:     Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#define _XOPEN_SOURCE
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>

#include "gtp_guard.h"

/* Local data */
data_t *daemon_data;
thread_master_t *master = NULL;
const char *apn_str;
const char *plmn_str;
const char *nameserver;
const char *service_selection;

/*
 *      Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -h, --help                   Display this help message\n");
}


/*
 *	Command line parser
 */
static int
parse_cmdline(int argc, char **argv)
{
	int c, longindex;

	struct option long_options[] = {
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	while (longindex = -1, (c = getopt_long(argc, argv, ":ha:p:s:S:"
						, long_options, &longindex)) != -1) {
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument &&
		    optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
			exit(1);
			break;
		}
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		return -1;
	}

	return 0;
}

static thread_master_t *m;
static int sigint;
static thread_t *t1, *t2, *t3;

static void
sigint_hdl(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	if (++sigint > 2) {
		fprintf(stderr, "ctrl-C pressed too much, dying hard\n");
		exit(1);
	}

	if (sigint == 1) {
		fprintf(stderr, "shutting down\n");
		thread_add_terminate_event(m);
	}
}

/* t1 or t2 fired */
static void
timer_func(thread_t *t)
{
	thread_t *ot = t == t1 ? t2 : t1;

	printf("t%ld fired\n", (size_t)t->arg);

	/* cancel thread that did not yet fire */
	assert(t3->type == THREAD_TIMER);
	thread_del(t3);

	/* cancel thread that fired, in ready list, but not this callback */
	assert(ot->type == THREAD_READY_TIMER);
	thread_del(ot);

	/* cancel thread that fired (in ready list), and this callback (no-op) */
	assert(t->type == THREAD_READY_TIMER);
	thread_del(t);

	printf("timer test ok\n");
	thread_add_terminate_event(m);
}

int main(int argc, char **argv)
{
	int err;

	m = thread_make_master(false);

	/* Command line parsing */
	err = parse_cmdline(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	if (isatty(STDIN_FILENO))
		signal_set(SIGINT, sigint_hdl, NULL);

	t1 = thread_add_timer(m, timer_func, (void *)1, TIMER_HZ);
	t2 = thread_add_timer(m, timer_func, (void *)2, TIMER_HZ);
	t3 = thread_add_timer(m, timer_func, (void *)3, TIMER_HZ + 10000);

	launch_thread_scheduler(m);

	thread_destroy_master(m);

	return 0;
}
