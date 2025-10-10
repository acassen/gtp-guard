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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <bpf.h>
#include <libbpf.h>

struct data *daemon_data;
struct thread_master *master = NULL;


static int test_id;
static const char *bpf_prog_name = "cgn_test";

/*
 *      Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -h, --help                   Display this help message\n");
	fprintf(stderr, "  -t, --test-id                Run this test\n");
	fprintf(stderr, "  -p, --bpf-prog               Run this bpf-program\n");
}


/*
 *	Command line parser
 */
static void
parse_cmdline(int argc, char **argv)
{
	int c, longindex;

	struct option long_options[] = {
		{"help",                no_argument,		NULL, 'h'},
		{"test-id",             required_argument,	NULL, 't'},
		{"bpf-prog",            required_argument,	NULL, 'p'},
		{NULL,                  0,			NULL,  0 }
	};

	while (longindex = -1, (c = getopt_long(argc, argv, "ht:p:"
						, long_options, &longindex)) != -1) {

		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 't':
			test_id = atoi(optarg);
			break;
		case 'p':
			bpf_prog_name = optarg;
			break;
		default:
			exit(1);
			break;
		}
	}
}

/*
 * loop through *all* loaded bpf in kernel, and stop at the one we want
 */
static int
retrieve_prog_fd(const char *prog_name, int type)
{
	struct bpf_prog_info info;
	uint32_t len = sizeof(info);
	uint32_t id = 0;
	int fd, err;

	while (true) {
		err = bpf_prog_get_next_id(id, &id);
		if (err < 0)
			return -1;

		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0)
			return -1;

		memset(&info, 0x00, sizeof (info));
		err = bpf_prog_get_info_by_fd(fd, &info, &len);
		if (err)
			return -1;

		if (type == info.type && !strcmp(prog_name, info.name))
			return fd;

		close(fd);
	}
	return -1;
}

/*
 * run bpf function src/bpf/test_cgn.c:test_block_log()
 */
static void
run_block_log_event_test(void)
{
	int prg_fd = retrieve_prog_fd("test_block_log", BPF_PROG_TYPE_XDP);
	if (prg_fd < 0) {
		printf("did not find %s. maybe you forgot to launch it\n",
		       bpf_prog_name);
		return;
	}

	uint8_t buf[1000];
	struct xdp_md ctx_in = {
		.data_end = sizeof (buf),
	};

	LIBBPF_OPTS(bpf_test_run_opts, rcfg,
		    .data_in = buf,
		    .data_size_in = sizeof (buf),
		    .ctx_in = &ctx_in,
		    .ctx_size_in = sizeof (ctx_in),
		    .repeat = 1);

	errno = 0;
	int ret = bpf_prog_test_run_opts(prg_fd, &rcfg);

	printf("test 1 run ret=%d %m\n", ret);
	close(prg_fd);
}


int main(int argc, char **argv)
{
	parse_cmdline(argc, argv);

	switch (test_id) {
	case 1:
		run_block_log_event_test();
	}

	return 0;
}
