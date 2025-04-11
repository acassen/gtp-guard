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
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#define _XOPEN_SOURCE
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "gtp_guard.h"


/* Local data */
data_t *daemon_data;
thread_master_t *master = NULL;

/* Local var */
static const char *gtp_pcap_file;
static bool verbose = false;


/*
 *	Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -p, --pcap-file		PCAP file\n");
	fprintf(stderr, "  -v, --verbose		verbose mode\n");
	fprintf(stderr, "  -h, --help			Display this help message\n");
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
		{"pcap-file",		required_argument,	NULL, 'p'},
		{"verbose",		no_argument,		NULL, 'v'},
		{"help",		no_argument,		NULL, 'h'},
		{NULL,			0,			NULL,  0 }
	};

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}


	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":hvp:"
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
		case 'v':
			verbose = true;
			break;
		case 'p':
			gtp_pcap_file = optarg;
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
	}

	if (bad_option || !gtp_pcap_file) {
		usage(argv[0]);
		exit(1);
	}

	return 0;
}


/*
 *	PCAP related
 */
static int
gtp_pcap_process(const char *path)
{
	char errbuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *data;
	int packetCount = 0;
	int err, offset, payload_len;
	pcap_t *pcap;
	struct iphdr *iph;
	struct udphdr *udph;
	pkt_buffer_t *pkt;
	gtp_msg_t *msg;
	gtp_cdr_t *cdr;

	pcap = pcap_open_offline(path, errbuff);
	if (!pcap) {
		fprintf(stderr, "Error opening pcap file:%s (%s)\n", path, errbuff);
		return -1;
	}

	pkt = pkt_buffer_alloc(8192);
	cdr = gtp_cdr_alloc();

	offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	while ((err = pcap_next_ex(pcap, &header, &data)) >= 0) {
		if (verbose)
			printf("* Packet # %i - size: %d Bytes (epoch: %ld:%ld secs)\n",
				++packetCount, header->len, header->ts.tv_sec, header->ts.tv_usec);
 
		if (header->len != header->caplen)
			printf("Warning! Capture size different than packet size: %d bytes\n", header->len);
 
		iph = (struct iphdr *) (data + sizeof(struct ethhdr));
		if (iph->protocol != IPPROTO_UDP)
			continue;

		udph = (struct udphdr *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
		payload_len = ntohs(udph->len) - sizeof(struct udphdr);

		memcpy(pkt->head, data + offset, payload_len);
		pkt_buffer_set_end_pointer(pkt, payload_len);
		pkt_buffer_set_data_pointer(pkt, payload_len);

		msg = gtp_msg_alloc(pkt);
		if (!msg)
			continue;

		if (verbose) {
			printf("  ---[ GTP packet ]---\n");
			dump_buffer("  ", (char *) pkt->head, pkt_buffer_len(pkt));
			gtp_msg_dump("  ", msg);
		}

		gtp_cdr_update(pkt, msg, cdr);
	
		gtp_msg_destroy(msg);
	}

	pcap_close(pcap);
	pkt_buffer_free(pkt);
	return 0;
}


int main(int argc, char **argv)
{
	/* Command line parsing */
	parse_cmdline(argc, argv);

	/* dummy data */
	PMALLOC(daemon_data);
	INIT_LIST_HEAD(&daemon_data->gtp_apn);

	gtp_pcap_process(gtp_pcap_file);


#if 0
	unsigned char cdr[512];
	const unsigned char *cdr_end = cdr + 512;
	unsigned char *cp;



	memset(cdr, 0, 512);

	cp = asn1_encode_tag(cdr, cdr_end, ASN1_CONT, ASN1_CONS, 79, NULL, -1);
	if (!cp)
		printf("Error...\n");



	printf("----[ Generated CDR ]----\n");
	dump_buffer("", cdr, 16);
#endif

	FREE(daemon_data);
	exit(0);
}
