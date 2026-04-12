/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        Split an IPv4 or IPv6 prefix over N queues (N MUST be a power of 2).
 *              Usage: ./ip-pfx-split [-v] <prefix/len> <num-queues>
 *
 *              The next log2(N) bits after the prefix length select the queue.
 *              Example: 10.0.0.0/8  4   ->  4 x /10 sub-prefixes
 *                       2001:db8::/46 8 ->  8 x /49 sub-prefixes
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
split4(const char *prefix_arg, int num_queues, int verbose)
{
	char addr_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];
	struct in_addr base, addr, mask;
	int len, bits, new_len;
	char buf[64];
	char *slash;

	strncpy(buf, prefix_arg, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	slash = strchr(buf, '/');
	if (!slash) {
		fprintf(stderr, "Error: missing prefix length\n");
		return 1;
	}

	*slash = '\0';
	len = atoi(slash + 1);
	if (len < 0 || len > 32 || inet_pton(AF_INET, buf, &base) != 1) {
		fprintf(stderr, "Error: invalid IPv4 prefix\n");
		return 1;
	}

	for (bits = 0; (1 << bits) < num_queues; bits++);
	new_len = len + bits;
	if (new_len > 32) {
		fprintf(stderr, "Error: not enough bits for %d queues in /%d\n",
			num_queues, len);
		return 1;
	}

	mask.s_addr = new_len ? htonl(~((1u << (32 - new_len)) - 1)) : 0;
	inet_ntop(AF_INET, &mask, mask_str, sizeof(mask_str));

	for (int q = 0; q < num_queues; q++) {
		uint32_t a = ntohl(base.s_addr);
		a |= (uint32_t)q << (32 - new_len);
		addr.s_addr = htonl(a);
		inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
		if (verbose)
			printf("q%-3d %s/%s  (%u addresses)\n",
			       q, addr_str, mask_str, 1u << (32 - new_len));
		else
			printf("q%-3d %s/%s\n", q, addr_str, mask_str);
	}

	return 0;
}

static int
split6(const char *prefix_arg, int num_queues, int verbose)
{
	char addr_str[INET6_ADDRSTRLEN], mask_str[INET6_ADDRSTRLEN];
	struct in6_addr base, addr, mask;
	int len, bits, new_len;
	char buf[64];
	char *slash;

	strncpy(buf, prefix_arg, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	slash = strchr(buf, '/');
	if (!slash) {
		fprintf(stderr, "Error: missing prefix length\n");
		return 1;
	}

	*slash = '\0';
	len = atoi(slash + 1);
	if (len < 0 || len > 128 || inet_pton(AF_INET6, buf, &base) != 1) {
		fprintf(stderr, "Error: invalid IPv6 prefix\n");
		return 1;
	}

	for (bits = 0; (1 << bits) < num_queues; bits++);
	new_len = len + bits;
	if (new_len > 128) {
		fprintf(stderr, "Error: not enough bits for %d queues in /%d\n",
			num_queues, len);
		return 1;
	}

	for (int i = 0; i < 16; i++) {
		int n = new_len - i * 8;
		mask.s6_addr[i] = n >= 8 ? 0xff : n <= 0 ? 0x00 : (uint8_t)(0xff << (8 - n));
	}
	inet_ntop(AF_INET6, &mask, mask_str, sizeof(mask_str));

	for (int q = 0; q < num_queues; q++) {
		addr = base;
		for (int b = 0; b < bits; b++) {
			int pos = len + b;
			if (q & (1 << (bits - 1 - b)))
				addr.s6_addr[pos / 8] |= 0x80 >> (pos % 8);
		}
		inet_ntop(AF_INET6, &addr, addr_str, sizeof(addr_str));
		if (verbose)
			printf("q%-3d %s/%s  (2^%d addresses)\n",
			       q, addr_str, mask_str, 128 - new_len);
		else
			printf("q%-3d %s/%s\n", q, addr_str, mask_str);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int num_queues, verbose = 0, opt;

	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
		case 'v':
			verbose = 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [-v] <prefix/len> <num-queues>\n",
				argv[0]);
			return 1;
		}
	}

	if (argc - optind != 2) {
		fprintf(stderr, "Usage: %s [-v] <prefix/len> <num-queues>\n", argv[0]);
		return 1;
	}

	num_queues = atoi(argv[optind + 1]);
	if (num_queues <= 0 || (num_queues & (num_queues - 1))) {
		fprintf(stderr, "Error: num-queues must be a power of 2\n");
		return 1;
	}

	if (strchr(argv[optind], ':'))
		return split6(argv[optind], num_queues, verbose);
	return split4(argv[optind], num_queues, verbose);
}
