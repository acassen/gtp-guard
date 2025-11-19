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
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ip_pool.h"
#include "addr.h"
#include "utils.h"

#define NR_ALLOC	4096

struct thread_master *master;


int main(int argc, char **argv)
{
	const char *ip6_pfx_str = "1234:abcd:1330::/44";
	const char *ip4_pfx_str = "10.0.0.0/12";
	char addr_str[INET6_ADDRSTRLEN];
	union addr pfx, pfx6;
	uint32_t pfx_len, pfx6_len;
	struct ip_pool *p4, *p6;
	struct in_addr *addr4;
	struct in6_addr *addr6;
	int err, i;

	/* IPv6 playground */
	err = addr_parse_ip(ip6_pfx_str, &pfx6, &pfx6_len, NULL, false);
	if (err) {
		fprintf(stderr, "Error allocating ip6_pfx\n");
		exit(-1);
	}
	
	printf("IPv6 pfx Str : %s\n", inet_ntop(AF_INET6, &pfx6.sin6.sin6_addr, addr_str,
						INET6_ADDRSTRLEN));
	hexdump("IPv6 pfx : ", (unsigned char *) &pfx6.sin6.sin6_addr
			     , sizeof(struct in6_addr));
	printf("pfx6_len : %d\n", pfx6_len);

	p6 = ip_pool_alloc(ip6_pfx_str);
	if (!p6) {
		fprintf(stderr, "error while allocating ip_pool for IPv6\n");
		exit(-1);
	}
	printf("IPv6 ip_pool->size: %d\n", p6->size);
	addr6 = calloc(NR_ALLOC, sizeof(struct in6_addr));
	for (i = 0; i < NR_ALLOC; i++) {
		ip_pool_get(p6, &addr6[i]);
		printf("Allocated pfx6 : %s\n",
		       inet_ntop(AF_INET6, &addr6[i], addr_str, INET6_ADDRSTRLEN));
	}
	for (i = 0; i < NR_ALLOC; i++) {
		ip_pool_put(p6, &addr6[i]);
		printf("Releasing pfx6 : %s\n",
		       inet_ntop(AF_INET6, &addr6[i], addr_str, INET6_ADDRSTRLEN));
	}
	printf("IPv6 ip_pool->used: %d\n", p6->used);
	ip_pool_destroy(p6);

	/* IPv4 playground */
	err = addr_parse_ip(ip4_pfx_str, &pfx, &pfx_len, NULL, false);
	if (err) {
		fprintf(stderr, "Error allocating ip6_pfx\n");
		exit(-1);
	}

	printf("IPv4 pfx Str : %s\n", inet_ntop(AF_INET, &pfx.sin.sin_addr, addr_str,
						INET6_ADDRSTRLEN));
	hexdump("IPv4 pfx : ", (unsigned char *) &pfx.sin.sin_addr
			     , sizeof(struct in_addr));
	printf("pfx_len : %d\n", pfx_len);

	p4 = ip_pool_alloc(ip4_pfx_str);
	if (!p4) {
		fprintf(stderr, "error while allocating ip_pool for IPv4\n");
		exit(-1);
	}
	printf("IPv4 ip_pool->size: %d\n", p4->size);
	addr4 = calloc(NR_ALLOC, sizeof(struct in_addr));
	for (i = 0; i < NR_ALLOC; i++) {
		ip_pool_get(p4, &addr4[i]);
		printf("Allocated pfx4 : %s\n",
		       inet_ntop(AF_INET, &addr4[i], addr_str, INET6_ADDRSTRLEN));
	}
	for (i = 0; i < NR_ALLOC; i++) {
		ip_pool_put(p4, &addr4[i]);
		printf("Releasing pfx4 : %s\n",
		       inet_ntop(AF_INET, &addr4[i], addr_str, INET6_ADDRSTRLEN));
	}
	printf("IPv6 ip_pool->used: %d\n", p4->used);
	ip_pool_destroy(p4);

	exit(0);
}
