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

#include <getopt.h>

#include "gtp_data.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_session.h"
#include "gtp_sched.h"
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "inet_utils.h"

/* XXX: defined in gtp_bpf_rt.c */
struct gtp_bpf_prog;
int
gtp_bpf_rt_lladdr_update(void *p)
{
	return 0;
}
int
gtp_bpf_rt_metrics_init(struct gtp_bpf_prog *p, int a, int b)
{
	return 0;
}


/* Local data */
struct data *daemon_data;
struct thread_master *master = NULL;
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
	fprintf(stderr, "  -a, --apn                    Access-Point-Name\n");
	fprintf(stderr, "  -p, --plmn                   PLMN\n");
	fprintf(stderr, "  -s, --name-server            Nameserver IP Address\n");
	fprintf(stderr, "  -S, --service-selection      Service selection string\n");
	fprintf(stderr, "  -h, --help                   Display this help message\n");
}


/*
 *	Command line parser
 */
static int
parse_cmdline(int argc, char **argv)
{
	int c, longindex, curind;
	int bad_option = 0;

	struct option long_options[] = {
		{"apn",			required_argument,	NULL, 'a'},
		{"plmn",		required_argument,	NULL, 'p'},
		{"name-server",		required_argument,	NULL, 's'},
		{"service-selection",	required_argument,	NULL, 'S'},
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	if (argc < 5)
		return -1;

	curind = optind;
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
		case 'a':
			apn_str = optarg;
			break;
		case 'p':
			plmn_str = optarg;
			break;
		case 's':
			nameserver = optarg;
			break;
		case 'S':
			service_selection = optarg;
			break;
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option --%s\n", argv[curind]);
			bad_option = 1;
			break;
		case ':':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Missing parameter for option -%c\n", optopt);
			else
				fprintf(stderr, "Missing parameter for option --%s\n", long_options[longindex].name);
			bad_option = 1;
			break;
		default:
			exit(1);
			break;
		}
		curind = optind;
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		return -1;
	}

	if (bad_option)
		return -1;

	return 0;
}



int main(int argc, char **argv)
{
	struct sockaddr_in pgw, sgw;
	struct gtp_apn *apn;
	struct gtp_service *svc;
	unsigned long flags = 0;
	int err;

	/* Command line parsing */
	err = parse_cmdline(argc, argv);
	if (err) {
		usage(argv[0]);
		exit(-1);
	}

	PMALLOC(apn);
	INIT_LIST_HEAD(&apn->service_selection);
	bsd_strlcpy(apn->name, "*", GTP_APN_MAX_LEN);
	inet_stosockaddr(nameserver, 53, &apn->nameserver);
	if (service_selection) {
		PMALLOC(svc);
		INIT_LIST_HEAD(&svc->next);
		svc->prio = 10;
		bsd_strlcpy(svc->str, service_selection, GTP_APN_MAX_LEN);
		list_add_tail(&svc->next, &apn->service_selection);
	}
	__set_bit(GTP_SESSION_FL_ROAMING_OUT, &flags);

	memset(&pgw, 0, sizeof(struct sockaddr_in));
	memset(&sgw, 0, sizeof(struct sockaddr_in));
	err = gtp_sched_dynamic(apn, apn_str, plmn_str, &pgw, &sgw, &flags);
	if (err) {
		fprintf(stderr, " Unable to schedule pGW for apn:'%s.apn.epc.%s.3gppnetwork.org.'"
			      , apn_str, plmn_str);
		exit(-1);
	}

	printf("Scheduled pGW : %u.%u.%u.%u\n", NIPQUAD(pgw.sin_addr.s_addr));

	exit(0);
}
