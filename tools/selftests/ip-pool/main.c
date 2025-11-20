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
#include <sys/time.h>
#include <string.h>

#include "ip_pool.h"
#include "addr.h"
#include "utils.h"

#define NR_ALLOC	((1 << 20) - 1)

struct thread_master *master;

/* Performance measurement helpers */
static inline uint64_t
get_usec(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Fragmentation test statistics */
struct frag_stats {
	uint64_t alloc_time_usec;
	uint64_t free_time_usec;
	uint64_t realloc_time_usec;
	uint32_t operations;
	const char *test_name;
};

static void
print_stats(struct frag_stats *stats)
{
	printf("\n=== %s ===\n", stats->test_name);
	printf("Operations:        %u\n", stats->operations);
	printf("Total alloc time:  %lu usec (%.2f usec/op)\n",
	       stats->alloc_time_usec,
	       (double)stats->alloc_time_usec / stats->operations);
	printf("Total free time:   %lu usec (%.2f usec/op)\n",
	       stats->free_time_usec,
	       (double)stats->free_time_usec / stats->operations);
	if (stats->realloc_time_usec > 0) {
		printf("Total realloc time: %lu usec (%.2f usec/op)\n",
		       stats->realloc_time_usec,
		       (double)stats->realloc_time_usec / stats->operations);
	}
	printf("========================================\n");
}

/*
 * Test 1: Sequential allocation/deallocation (best case - no fragmentation)
 */
static void
test_sequential(struct ip_pool *pool, int num_ops)
{
	struct frag_stats stats = {0};
	struct in_addr *addrs;
	uint64_t start, end;
	int i;

	stats.test_name = "Sequential Allocation (No Fragmentation)";
	stats.operations = num_ops;

	addrs = calloc(num_ops, sizeof(struct in_addr));
	if (!addrs) {
		fprintf(stderr, "Failed to allocate test memory\n");
		return;
	}

	/* Allocate sequentially */
	start = get_usec();
	for (i = 0; i < num_ops; i++) {
		if (ip_pool_get(pool, &addrs[i]) < 0) {
			fprintf(stderr, "Allocation failed at %d\n", i);
			break;
		}
	}
	end = get_usec();
	stats.alloc_time_usec = end - start;

	/* Free sequentially */
	start = get_usec();
	for (i = 0; i < num_ops; i++) {
		ip_pool_put(pool, &addrs[i]);
	}
	end = get_usec();
	stats.free_time_usec = end - start;

	print_stats(&stats);
	free(addrs);
}

/*
 * Test 2: Every-other deallocation (creates maximum fragmentation)
 */
static void
test_fragmented(struct ip_pool *pool, int num_ops)
{
	struct frag_stats stats = {0};
	struct in_addr *addrs;
	uint64_t start, end;
	int i;

	stats.test_name = "Maximum Fragmentation (Every-Other Pattern)";
	stats.operations = num_ops;

	addrs = calloc(num_ops, sizeof(struct in_addr));
	if (!addrs) {
		fprintf(stderr, "Failed to allocate test memory\n");
		return;
	}

	/* Allocate all */
	start = get_usec();
	for (i = 0; i < num_ops; i++) {
		if (ip_pool_get(pool, &addrs[i]) < 0) {
			fprintf(stderr, "Allocation failed at %d\n", i);
			num_ops = i;
			break;
		}
	}
	end = get_usec();
	stats.alloc_time_usec = end - start;

	/* Free every other entry to create fragmentation */
	start = get_usec();
	for (i = 0; i < num_ops; i += 2) {
		ip_pool_put(pool, &addrs[i]);
	}
	end = get_usec();
	stats.free_time_usec = end - start;

	printf("Pool after fragmentation: %u used / %u total (%.1f%% full)\n",
	       pool->used, pool->size, (pool->used * 100.0) / pool->size);
	printf("Fragmentation metric: %.1f%%\n", ip_pool_frag_ratio(pool));

	/* Reallocate to measure fragmented performance */
	start = get_usec();
	for (i = 0; i < num_ops / 2; i++) {
		if (ip_pool_get(pool, &addrs[i]) < 0) {
			fprintf(stderr, "Reallocation failed at %d\n", i);
			break;
		}
	}
	end = get_usec();
	stats.realloc_time_usec = end - start;

	/* Clean up */
	for (i = 0; i < num_ops; i++) {
		ip_pool_put(pool, &addrs[i]);
	}

	print_stats(&stats);
	free(addrs);
}

/*
 * Test 3: Random allocation/deallocation (realistic scenario)
 */
static void
test_random_churn(struct ip_pool *pool, int num_ops)
{
	struct frag_stats stats = {0};
	struct in_addr *addrs;
	uint64_t start, end;
	int i, active_count;

	stats.test_name = "Random Churn (Realistic Fragmentation)";
	stats.operations = num_ops;

	addrs = calloc(num_ops, sizeof(struct in_addr));
	if (!addrs) {
		fprintf(stderr, "Failed to allocate test memory\n");
		return;
	}

	/* Fill pool to 70% */
	active_count = (num_ops * 7) / 10;
	start = get_usec();
	for (i = 0; i < active_count; i++) {
		if (ip_pool_get(pool, &addrs[i]) < 0) {
			fprintf(stderr, "Initial allocation failed at %d\n", i);
			active_count = i;
			break;
		}
	}
	end = get_usec();
	stats.alloc_time_usec = end - start;

	printf("Pool at 70%% capacity: %u used / %u total\n",
	       pool->used, pool->size);
	printf("Fragmentation before churn: %.1f%%\n", ip_pool_frag_ratio(pool));

	/* Randomly free 30% and reallocate to simulate churn */
	start = get_usec();
	for (i = 0; i < active_count; i += 3) {
		ip_pool_put(pool, &addrs[i]);
	}
	end = get_usec();
	stats.free_time_usec = end - start;

	printf("After partial free: %u used / %u total (%.1f%% full)\n",
	       pool->used, pool->size, (pool->used * 100.0) / pool->size);
	printf("Fragmentation after churn: %.1f%%\n", ip_pool_frag_ratio(pool));

	/* Reallocate freed slots */
	start = get_usec();
	for (i = 0; i < active_count; i += 3) {
		if (ip_pool_get(pool, &addrs[i]) < 0) {
			fprintf(stderr, "Reallocation failed at %d\n", i);
			break;
		}
	}
	end = get_usec();
	stats.realloc_time_usec = end - start;

	/* Clean up */
	for (i = 0; i < num_ops; i++) {
		if (addrs[i].s_addr != 0)
			ip_pool_put(pool, &addrs[i]);
	}

	print_stats(&stats);
	free(addrs);
}

/*
 * Test 4: Hot reuse test (tests last_freed_idx optimization)
 */
static void
test_hot_reuse(struct ip_pool *pool, int num_ops)
{
	struct frag_stats stats = {0};
	struct in_addr addr;
	uint64_t start, end;
	int i;

	stats.test_name = "Hot Reuse (Last-Freed Optimization)";
	stats.operations = num_ops;

	/* Allocate and immediately free in a loop */
	start = get_usec();
	for (i = 0; i < num_ops; i++) {
		if (ip_pool_get(pool, &addr) < 0) {
			fprintf(stderr, "Hot reuse allocation failed at %d\n", i);
			break;
		}
		ip_pool_put(pool, &addr);
	}
	end = get_usec();
	stats.alloc_time_usec = end - start;
	stats.free_time_usec = 0;  /* Included in alloc time */

	printf("Hot reuse pattern: alloc+free %d times on same slot\n", num_ops);
	print_stats(&stats);
}

/*
 * Test 5: Chunk skipping efficiency (tests chunk_free optimization)
 */
static void
test_chunk_skipping(struct ip_pool *pool, int num_ops)
{
	struct frag_stats stats = {0};
	struct in_addr *addrs;
	uint64_t start, end;
	int i, allocated;

	stats.test_name = "Chunk Skipping (Full-Chunk Optimization)";
	stats.operations = num_ops;

	addrs = calloc(num_ops, sizeof(struct in_addr));
	if (!addrs) {
		fprintf(stderr, "Failed to allocate test memory\n");
		return;
	}

	/* Fill pool to 95% */
	allocated = (num_ops * 95) / 100;
	start = get_usec();
	for (i = 0; i < allocated; i++) {
		if (ip_pool_get(pool, &addrs[i]) < 0) {
			fprintf(stderr, "Allocation failed at %d\n", i);
			allocated = i;
			break;
		}
	}
	end = get_usec();
	stats.alloc_time_usec = end - start;

	printf("Pool at 95%% capacity: %u used / %u total\n",
	       pool->used, pool->size);
	printf("Number of chunks: %u\n", pool->num_chunks);

	/* Count full chunks */
	int full_chunks = 0;
	for (i = 0; i < pool->num_chunks; i++) {
		if (pool->chunk_free[i] == 0)
			full_chunks++;
	}
	printf("Full chunks (will be skipped): %d / %u (%.1f%%)\n",
	       full_chunks, pool->num_chunks,
	       (full_chunks * 100.0) / pool->num_chunks);

	/* Allocate remaining addresses (exercises chunk skipping) */
	start = get_usec();
	for (i = allocated; i < num_ops && pool->used < pool->size; i++) {
		if (ip_pool_get(pool, &addrs[i]) < 0)
			break;
	}
	end = get_usec();
	stats.realloc_time_usec = end - start;

	printf("Allocated remaining %d addresses\n", i - allocated);

	/* Clean up */
	for (i = 0; i < num_ops; i++) {
		if (addrs[i].s_addr != 0)
			ip_pool_put(pool, &addrs[i]);
	}

	print_stats(&stats);
	free(addrs);
}


int main(int argc, char **argv)
{
	const char *ip6_pfx_str = "1234:abcd:1330::/44";
	const char *ip4_pfx_str = "10.0.0.0/12";
	char addr_str[INET6_ADDRSTRLEN];
	union addr pfx, pfx6;
	uint32_t pfx_len, pfx6_len;
	struct ip_pool *p4, *p6, *ptest;
	struct in_addr *addr4;
	struct in6_addr *addr6;
	int err, i, verbose = 0;

	/* Parse command line options */
	if (argc > 1) {
		if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0) {
			verbose = 1;
		} else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
			printf("Usage: %s [OPTIONS]\n", argv[0]);
			printf("Options:\n");
			printf("  -v, --verbose    Show detailed allocation logs\n");
			printf("  -h, --help       Show this help message\n");
			exit(0);
		}
	}

	printf("╔═══════════════════════════════════════════════════════════╗\n");
	printf("║         Basic IP POOL ALLOCATION TEST SUITE               ║\n");
	printf("╚═══════════════════════════════════════════════════════════╝\n");

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
		if (verbose)
			printf("Allocated pfx6 : %s\n",
			       inet_ntop(AF_INET6, &addr6[i], addr_str, INET6_ADDRSTRLEN));
	}
	for (i = 0; i < NR_ALLOC; i++) {
		ip_pool_put(p6, &addr6[i]);
		if (verbose)
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

	printf("\nIPv4 pfx Str : %s\n", inet_ntop(AF_INET, &pfx.sin.sin_addr, addr_str,
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
		if (verbose)
			printf("Allocated pfx4 : %s\n",
			       inet_ntop(AF_INET, &addr4[i], addr_str, INET6_ADDRSTRLEN));
	}
	for (i = 0; i < NR_ALLOC; i++) {
		ip_pool_put(p4, &addr4[i]);
		if (verbose)
			printf("Releasing pfx4 : %s\n",
			       inet_ntop(AF_INET, &addr4[i], addr_str, INET6_ADDRSTRLEN));
	}
	printf("IPv4 ip_pool->used: %d\n", p4->used);
	ip_pool_destroy(p4);

	printf("\n\n");
	printf("╔═══════════════════════════════════════════════════════════╗\n");
	printf("║         IP POOL FRAGMENTATION TEST SUITE                  ║\n");
	printf("╚═══════════════════════════════════════════════════════════╝\n");

	/* Create test pool */
	ptest = ip_pool_alloc(ip4_pfx_str);
	if (!ptest) {
		fprintf(stderr, "Failed to allocate test pool\n");
		exit(1);
	}

	printf("\nTest Pool Configuration:\n");
	printf("  Prefix: %s\n", ip4_pfx_str);
	printf("  Total addresses: %u\n", ptest->size);
	printf("  Chunks: %u (chunk size: %d)\n",
	       ptest->num_chunks, IP_POOL_CHUNK_SIZE);
	printf("  Memory overhead: %lu bytes (%.2f%%)\n",
	       ptest->num_chunks * sizeof(uint32_t),
	       (ptest->num_chunks * sizeof(uint32_t) * 100.0) /
	       (ptest->size * sizeof(bool)));

	printf("\n───────────── Test 1: Sequential (baseline) ─────────────────\n");
	test_sequential(ptest, NR_ALLOC);
	ip_pool_destroy(ptest);

	printf("\n───────────── Test 2: Maximum fragmentation ─────────────────\n");
	ptest = ip_pool_alloc(ip4_pfx_str);
	if (!ptest) {
		fprintf(stderr, "Failed to allocate test pool\n");
		exit(1);
	}
	test_fragmented(ptest, NR_ALLOC);
	ip_pool_destroy(ptest);

	printf("\n───────────── Test 3: Random churn ──────────────────────────\n");
	ptest = ip_pool_alloc(ip4_pfx_str);
	if (!ptest) {
		fprintf(stderr, "Failed to allocate test pool\n");
		exit(1);
	}
	test_random_churn(ptest, NR_ALLOC);
	ip_pool_destroy(ptest);

	printf("\n───────────── Test 4: Hot Reuse ────────────────────────────\n");
	ptest = ip_pool_alloc(ip4_pfx_str);
	if (!ptest) {
		fprintf(stderr, "Failed to allocate test pool\n");
		exit(1);
	}
	test_hot_reuse(ptest, NR_ALLOC * 10);
	ip_pool_destroy(ptest);

	printf("\n───────────── Test 5: Chunk skipping ───────────────────────\n");
	ptest = ip_pool_alloc(ip4_pfx_str);
	if (!ptest) {
		fprintf(stderr, "Failed to allocate test pool\n");
		exit(1);
	}
	test_chunk_skipping(ptest, NR_ALLOC);
	ip_pool_destroy(ptest);

	exit(0);
}
