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
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <errno.h>
#include <bpf.h>
#include <libbpf.h>

#include "gtp_data.h"
#include "logger.h"
#include "jhash.h"
#include "inet_utils.h"
#include "cgn-priv.h"
#include "gtp_bpf_xsk.h"
#include "bpf/lib/cgn-def.h"
#include "bpf/lib/xsk-def.h"

struct data *daemon_data;
struct thread_master *master = NULL;


static int test_id;
static const char *bpf_prog_name = "cgn_test";
static int iface_idx;


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
		{"iface",               required_argument,	NULL, 'i'},
		{NULL,                  0,			NULL,  0 }
	};

	while (longindex = -1, (c = getopt_long(argc, argv, "ht:p:i:"
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
		case 'i':
			iface_idx = if_nametoindex(optarg);
			if (iface_idx <= 0)
				printf("cannot find iface %s\n", optarg);
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
 *
 * this test is not used anymore
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


/*
 * run bpf function src/bpf/test_cgn.c:xdp_tx_pkt_gen()
 */
static void
run_xdp_pkt_gen_test(void)
{
	struct timespec ts;
	int i, ret;

	int prg_fd = retrieve_prog_fd("xdp_tx_pkt_gen", BPF_PROG_TYPE_XDP);
	if (prg_fd < 0) {
		printf("did not find %s. maybe you forgot to launch it\n",
		       "xdp_tx_pkt_gen");
		return;
	}

	uint8_t buf[600];
	struct xdp_md ctx_in = {
		.data_end = sizeof (buf),
		.ingress_ifindex = iface_idx
	};

	struct ethhdr *ethh = (struct ethhdr *)buf;
	struct iphdr *iph = (struct iphdr *)(ethh + 1);
	struct udphdr *udph = (struct udphdr *)(iph + 1);

	memset(ethh, 0x00, sizeof (*ethh));
	ethh->h_proto = htons(ETH_P_IP);

	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = (uint16_t)(sizeof(struct iphdr) + sizeof(struct udphdr));
	iph->tot_len = htons(iph->tot_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = htonl(0x0a000001);
	iph->daddr = htonl(0x08080404);
	iph->check = 0;
	iph->check = in_csum((uint16_t *)iph, sizeof(struct iphdr), 0);

	udph->source = htons(2000);
	udph->dest = htons(53);
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0;

	LIBBPF_OPTS(bpf_test_run_opts, rcfg,
		    .data_in = buf,
		    .data_size_in = sizeof (buf),
		    .ctx_in = &ctx_in,
		    .ctx_size_in = sizeof (ctx_in),
		    .repeat = 2000,
		    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		    /* .cpu = 1, */
		    );

	for (i = 0; i < 625 * 8; i++) { /* 10M packets */
		iph->saddr = htonl(0x0a000001 + i / 10);

		errno = 0;
		ret = bpf_prog_test_run_opts(prg_fd, &rcfg);

		clock_gettime(CLOCK_MONOTONIC, &ts);
		printf("%ld.%.3ld test 3 run[%d] pkt=%d/%d ret=%d %m\n",
		       ts.tv_sec % 1000, ts.tv_nsec / 1000000,
		       i, i * rcfg.repeat, 625 * 8 * rcfg.repeat, ret);
	}

	close(prg_fd);
}


/*************************************************************************/
/* test cgn flow */

static int
update_priv_last_use(struct cgn_ctx *c, const struct cgn_v4_flow_priv_key *pk,
		     int timeout)
{
	struct cgn_v4_flow_priv priv_d;
	int ret;

	ret = bpf_map__lookup_elem(c->bpf_data->v4_priv_flows, pk, sizeof (*pk),
				   &priv_d, sizeof (priv_d), 0);
	if (ret) {
		printf("(test) map lookup{v4_priv_flows}: %m\n");
		printf(" lookup was: %x:%d %x:%d %d\n",
		       ntohl(pk->priv_addr), ntohs(pk->priv_port),
		       ntohl(pk->pub_addr), ntohs(pk->pub_port), pk->proto);
		return -1;
	}

	priv_d.last_use = c->now_ns + timeout * NSEC_PER_SEC;

	ret = bpf_map__update_elem(c->bpf_data->v4_priv_flows, pk, sizeof (*pk),
				   &priv_d, sizeof (priv_d), 0);
	if (ret) {
		printf("map update{v4_priv_flows}: %m\n");
		return -1;
	}

	return 0;
}

static void
test_cgn_flow_1(struct cgn_ctx *c)
{
	uint8_t data[400];
	struct gtp_xsk_metadata *md = (struct gtp_xsk_metadata *)data;
	struct cgn_v4_flow_priv_key *pk = (void *)md->data;
	struct cgn_user *u;
	struct gtp_xsk_desc desc;
	char buf[600000];
	int i, j, ret;

	desc.len = 10;

	pk->_pad[0] = 0;
	pk->_pad[1] = 0;
	pk->_pad[2] = 0;

#if 0
	/* flows from multiple protocols */
	pk->priv_addr = htonl(0x0a00000b);
	pk->priv_port = htons(20000);
	pk->pub_addr = htonl(0x08080404);
	pk->pub_port = htons(80);
	pk->proto = IPPROTO_UDP;
	desc.data = pk + 1;
	assert(cgn_flow_read_pkt(c, &desc) == GTP_XSK_TX);

	pk->priv_addr = htonl(0x0a00000b);
	pk->priv_port = htons(20000);
	pk->pub_addr = htonl(0x08080404);
	pk->pub_port = htons(80);
	pk->proto = IPPROTO_TCP;
	desc.data = pk + 1;
	assert(cgn_flow_read_pkt(c, &desc) == GTP_XSK_TX);

	pk->priv_addr = htonl(0x0a00000b);
	pk->priv_port = htons(20000);
	pk->pub_addr = htonl(0x08080404);
	pk->pub_port = htons(80);
	pk->proto = IPPROTO_ICMP;
	desc.data = pk + 1;
	assert(cgn_flow_read_pkt(c, &desc) == GTP_XSK_TX);

	assert(c->user_n == 1);
	u = list_first_entry(&c->user_list, struct cgn_user, list);
	assert(u->flow_n == 3);

	cgn_flow_dump_user_full(c, ntohl(pk->priv_addr), buf, sizeof (buf));
	printf("%s\n", buf);

	c->now_ns += 200ULL * NSEC_PER_SEC;
	cgn_flow_gc(c);
#endif

	pk->proto = IPPROTO_UDP;

#if 1
	/* first loop will alloc flow, second loop use created flows */
	for (j = 0; j < 2; j++) {
		/* alloc 4*100=400 flows, more will fails (cgn port cannot
		 * be reused) */
		for (i = 0; i < 504; i++) {
			pk->priv_addr = htonl(0x0a000001);
			pk->priv_port = htons(40000 + i);
			pk->pub_addr = htonl(0x08080404);
			pk->pub_port = htons(80);

			desc.data = pk + 1;
			ret = cgn_flow_read_pkt(c, &desc);
			if (ret == GTP_XSK_TX)
				assert(i < 400);
			else
				assert(i >= 400);
		}

		/* alloc remaining 100 flows */
		for (i = 0; i < 106; i++) {
			pk->priv_addr = htonl(0x0a000001);
			pk->priv_port = htons(20000 + i);
			pk->pub_addr = htonl(0x01010101);
			pk->pub_port = htons(53);

			desc.data = pk + 1;
			ret = cgn_flow_read_pkt(c, &desc);
			if (ret == GTP_XSK_TX)
				assert(i < 100);
			else
				assert(i >= 100);
		}
	}

	assert(c->user_n == 1);
	u = list_first_entry(&c->user_list, struct cgn_user, list);
	assert(u->flow_n == 500);

	/* gc pass */
	c->now_ns += 200ULL * NSEC_PER_SEC;
	cgn_flow_gc(c);
	assert(c->user_n == 0);

	/* cgn_flow_dump_user_full(c, ntohl(pk->priv_addr), buf, sizeof (buf)); */
	/* printf("%s\n", buf); */
#endif

#if 1
	/* port reuse, with pub change (test stun).
	 * user's flows is limited to 500 anyway */
	for (i = 0; i < 600; i++) {
		pk->priv_addr = htonl(0x0a000002);
		pk->pub_addr = htonl(0x08080404 + (i / 100));
		pk->priv_port = htons(40000 + (i % 20));
		pk->pub_port = htons(80 + ((i % 100) / 20));

		desc.data = pk + 1;
		ret = cgn_flow_read_pkt(c, &desc);
		assert((i < 500 && ret == GTP_XSK_TX) || ret == GTP_XSK_DROP);
	}

	/* clean everything */
	c->now_ns += 200ULL * NSEC_PER_SEC;
	cgn_flow_gc(c);
	assert(c->user_n == 0);

	cgn_flow_dump_user_full(c, ntohl(pk->priv_addr), buf, sizeof (buf));
	printf("%s\n", buf);
#endif

#if 1
	uint64_t start_ns = c->now_ns;
	/* random allocation/free */
	for (i = 0; i < 2 * 1000 * 1000; i++) {
		int user_r = (i / 1000000) % 2 ? 1000: 10050;
		pk->priv_addr = htonl(0x0a000000 + (random() % user_r));
		pk->pub_addr = htonl(0x08080404);
		pk->priv_port = htons(30000 + (random() % 1000));
		pk->pub_port = htons(100 + random() % 20);

		desc.data = pk + 1;
		ret = cgn_flow_read_pkt(c, &desc);
		if (ret != GTP_XSK_TX) {
			if (!(c->user_n == c->max_user || c->flow_n == c->max_flow)) {
				uint32_t h = jhash_1word(ntohl(pk->priv_addr), 0) &
					(c->huser_size - 1);
				hlist_for_each_entry(u, &c->huser[h], hlist) {
					if (u->addr == ntohl(pk->priv_addr)) {
						assert(u->flow_n == c->flow_per_user);
						break;
					}
				}
			}
		} else {
			/* will expire in [1-500] seconds */
			if (update_priv_last_use(c, pk, 1 + (random() % 500))) {
				cgn_flow_dump_user_full(c, ntohl(pk->priv_addr),
							buf, sizeof (buf));
				printf("%s\n", buf);
				break;
			}
		}

		/* 1 second and 1 gc step every 2000 packets... */
		if (((i + 1) % 2000) == 0) {
			c->now_ns += NSEC_PER_SEC;
			cgn_flow_gc(c);
		}

		if (((i + 1) % 10000) == 0)
			printf("%d0k: %d/%d %d/%d\n", i / 10000,
			       c->user_n, c->max_user,
			       c->flow_n, c->max_flow);
	}

	printf("doing last GC, virtually %ld seconds elapsed\n",
	       (c->now_ns - start_ns) / NSEC_PER_SEC);
	c->now_ns += 600ULL * NSEC_PER_SEC;
	c->user_gc_cur = NULL;
	while (cgn_flow_gc(c))
		;

	/* list_for_each_entry(u, &c->user_list, list) { */
	/* 	cgn_flow_dump_user_full(c, u->addr, buf, sizeof (buf)); */
	/* 	printf("%s\n", buf); */
	/* } */

	cgn_flow_dump_block_alloc(c, buf, sizeof (buf));
	printf("%s\n", buf);

	assert(c->user_n == 0);
#endif
}


static void
setup_cgn_flow(void)
{
	const char *bpf_filename = "bin/cgn.bpf";
	struct bpf_object *obj;
	struct cgn_bpf_ctx *bc;
	struct cgn_ctx *c;
	int i;

	/* load bpf program, only to access its map (program won't be run) */
	obj = bpf_object__open_file(bpf_filename, NULL);
	if (obj == NULL) {
		printf("%s: %m\n", bpf_filename);
		return;
	}

	/* alloc a cgn context, add ip-pool */
	c = cgn_ctx_alloc("cgn-t");
	c->flow_per_user = 500;
	c->block_size = 100;
	c->max_user = 10000;
	c->max_flow = 320000;
	c->block_count = (c->port_end - c->port_start) / c->block_size;
	c->port_end = c->port_start + c->block_size * c->block_count;
	c->cgn_addr = realloc(c->cgn_addr, 16 * sizeof (uint32_t));
	for (i = 0; i < 16; i++)
		c->cgn_addr[i] = 0x258D0000 + i;
	c->cgn_addr_n = 16;

	/* attach a fake cgn bpf template */
	bc = calloc(1, sizeof (*bc));
	INIT_LIST_HEAD(&bc->cgn_list);
	bc->v4_priv_flows = bpf_object__find_map_by_name(obj, "v4_priv_flows");
	bc->v4_pub_flows = bpf_object__find_map_by_name(obj, "v4_pub_flows");
	assert(bc->v4_priv_flows && bc->v4_pub_flows);
	c->bpf_data = bc;
	list_add(&c->bpf_list, &bc->cgn_list);
	assert(!bpf_map__set_max_entries(bc->v4_priv_flows, c->max_flow));
	assert(!bpf_map__set_max_entries(bc->v4_pub_flows, c->max_flow));
	if (bpf_object__load(obj) < 0) {
		printf("%s: %m\n", bpf_filename);
		goto exit;
	}

	/* initialize flows */
	assert(cgn_flow_init(c) == 0);
	c->initialized = true;

	/* treat fake packets */
	test_cgn_flow_1(c);

 exit:
	/* now release everything */
	cgn_flow_release(c);
	cgn_ctx_release(c);
	free(bc);
	bpf_object__close(obj);
}

int
main(int argc, char **argv)
{
	parse_cmdline(argc, argv);

	srandom(time(NULL) + (getpid() << 16));

	/* global initializations */
	daemon_data = malloc(sizeof (*daemon_data));
	INIT_LIST_HEAD(&daemon_data->cgn);
	enable_console_log();

	switch (test_id) {
	case 1:
		run_block_log_event_test();
		break;
	case 2:
		setup_cgn_flow();
		break;
	case 3:
		run_xdp_pkt_gen_test();
		break;

	default:
		return 10;
	}

	free(daemon_data);

	return 0;
}
