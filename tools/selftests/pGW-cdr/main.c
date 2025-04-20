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
static const char *gtp_cdr_file;
static const char *document_root;
static const char *archive_root;
static bool verbose = false;


/*
 *	Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -p, --pcap-file              PCAP file\n");
	fprintf(stderr, "  -c, --cdr-file               CDR file\n");
	fprintf(stderr, "  -d, --document-root          CDR File Document Root\n");
	fprintf(stderr, "  -a, --archive-root           CDR File Archive Root\n");
	fprintf(stderr, "  -v, --verbose                verbose mode\n");
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
		{"pcap-file",		required_argument,	NULL, 'p'},
		{"cdr-file",		required_argument,	NULL, 'c'},
		{"dpcument-root",	required_argument,	NULL, 'd'},
		{"archive-root",	required_argument,	NULL, 'a'},
		{"verbose",		no_argument,		NULL, 'v'},
		{"help",		no_argument,		NULL, 'h'},
		{NULL,			0,			NULL,  0 }
	};

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":hvp:c:d:a:"
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
		case 'c':
			gtp_cdr_file = optarg;
			break;
		case 'd':
			document_root = optarg;
			break;
		case 'a':
			archive_root = optarg;
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
static gtp_cdr_t *
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
		return NULL;
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
	return cdr;
}


/*
 * I/O operations
 */
static int
write_cdr(const void *buf, size_t bsize)
{
	map_file_t *map_file;
	off_t offset = 0;
	int err, i;

	PMALLOC(map_file);
	bsd_strlcpy(map_file->path, gtp_cdr_file, GTP_PATH_MAX_LEN);

	err = gtp_disk_open(map_file, GTP_CDR_DEFAULT_FSIZE);
	if (err) {
		fprintf(stderr, "error creating file:%s (%m)\n", gtp_cdr_file);
		return -1;
	}

	/* writing */
	for (i = 0, offset = 0; i < 1000; i++, offset += bsize) {
		err = gtp_disk_write_sync(map_file, offset, buf, bsize);
		if (err) {
			fprintf(stderr, "\n#%d error writing (%m)\n", i);
			goto end;
		}

		printf(".%s", ((i + 1) % 64) ? "" : "\n");
	}
	printf("\n");

	/* vrfy */
	for (i = 0, offset = 0; i < 1000; i++, offset += bsize) {
		if (!memcmp((char *) map_file->map + offset, buf, bsize))
			continue;

		fprintf(stderr, "\n#%d buffer miss-match :\n", i);
		dump_buffer("Error buffer ", (char *)map_file->map + offset, bsize);
		goto end;
	}
	printf("Success vrfy file content integrity\n");

end:
	gtp_disk_close(map_file);
	FREE(map_file);
	return 0;
}

static int
write_cdr_file(const void *buf, size_t bsize)
{
	gtp_cdr_spool_t *s;
	gtp_cdr_file_t *f;
	int err, i;

	/* Init context */
	s = gtp_cdr_spool_alloc("cdr-test");
	bsd_strlcpy(s->document_root, document_root, GTP_PATH_MAX_LEN);
	if (archive_root)
		bsd_strlcpy(s->archive_root, archive_root, GTP_PATH_MAX_LEN);
	bsd_strlcpy(s->prefix, "pGW-test_", GTP_PATH_MAX_LEN);
	s->roll_period = 60;
	s->cdr_file_size = 1*1024*1024; /* 1MB test file */
	f = s->cdr_file;
	__set_bit(GTP_CDR_SPOOL_FL_ASYNC_BIT, &s->flags);

	err = gtp_cdr_file_create(f);
	if (err) {
		fprintf(stderr, "error creating cdr file:%s (%m)\n", document_root);
		goto end;
	}

	/* writing */
	for (i = 0; i < 100000; i++) {
		err = gtp_cdr_file_write(f, buf, bsize);
		if (err) {
			fprintf(stderr, "\n#%d error writing cdr file:%s (%m)\n"
				      , i, f->file->path);
			goto end;
		}

		printf(".%s", ((i + 1) % 64) ? "" : "\n");
	}
	printf("\n");

end:
	gtp_cdr_spool_destroy(s);
	return 0;
}


/*
 * Input pcap file contains GTP-C message with a full protocol
 * sequence :
 *  . create-session-reguest
 *  . create-session-response
 *  . delete-session-request
 *  . delete-session-response
 * gtp_cdr_update(...) is called for each GTP-C protocol msg in
 * order to simulate full protocol stack insertion and debugging
 * on the side. It incrementally update internal CDR represenation
 * with GTP-C IE cherry picking.
 * Displayed output is a C source code ARRAY, which can be later used
 * as an input into any ASN.1 decoder for encoding validation.
 *
 * usage: ./pGW-cdr -p gtp-c-capture.pcapng
 */
int main(int argc, char **argv)
{
	uint8_t data[512];
	int len;
	gtp_cdr_t *cdr;

	/* Command line parsing */
	parse_cmdline(argc, argv);
	host.name = "test-node";

	/* dummy data */
	PMALLOC(daemon_data);
	INIT_LIST_HEAD(&daemon_data->gtp_cdr);
	INIT_LIST_HEAD(&daemon_data->gtp_apn);

	cdr = gtp_pcap_process(gtp_pcap_file);
	if (!cdr)
		goto end;
	gtp_cdr_volumes_update(cdr, 12345, 12345);

	memset(data, 0, 512);
	len = gtp_cdr_asn1_pgw_record_encode(cdr, data, 512);
	gtp_cdr_destroy(cdr);

	printf("----[ Generated CDR (%d) ]----\n", len);
	dump_buffer("", (char *) data, len);

	/* Generate c array to be injected into third party
	 * ASN.1 decoder to validate our ASN.1 encoder output.
	 */
	buffer_to_c_array("cdr_3gpp", (char *) data, len);

	/* I/O operations */
	if (gtp_cdr_file)
		write_cdr(data, len);

	if (document_root)
		write_cdr_file(data, len);

  end:
	FREE(daemon_data);
	exit(0);
}
