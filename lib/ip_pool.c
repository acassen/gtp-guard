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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "ip_pool.h"
#include "utils.h"


/*
 * IP Pool Management with Anti-Fragmentation Design
 * ==================================================
 *
 * This implementation uses a multi-layered strategy to minimize the performance
 * impact of pool fragmentation in high-churn environments (e.g., mobile networks).
 *
 * FRAGMENTATION PROBLEM:
 * ----------------------
 * In traditional linear scanning, as sessions come and go, freed addresses become
 * scattered throughout the pool. Finding a free address requires O(N) scanning,
 * which degrades performance significantly when the pool is 70%+ utilized with
 * fragmentation.
 *
 * SOLUTION - PURE LRU ALLOCATION STRATEGY:
 * -----------------------------------------
 *
 * LRU Ring (O(1) - Optimal for Temporal Locality)
 * - Circular buffer with size equal to pool size (full FIFO tracking)
 * - Allocates OLDEST freed address first (only when ring is FULL)
 * - Ensures maximum "cool down" period before reuse
 * - On first allocation: uses sequential allocation to fill pool
 * - On steady-state: pure LRU allocation from ring
 * - Allows CPU caches to naturally evict stale entries
 * - Optimal for high-churn environments (mobile networks)
 *
 * PERFORMANCE CHARACTERISTICS:
 * ----------------------------
 * - Empty pool: O(1) - Sequential allocation
 * - Filling pool: O(1) - Sequential allocation
 * - Steady state: O(1) - LRU ring (after pool has been fully allocated once)
 * - All operations: O(1) constant time
 *
 * MEMORY OVERHEAD:
 * ----------------
 * - Per address: 1 byte (lease bitmap)
 * - LRU ring: pool_size × 4 bytes (full tracking)
 * - Example /24: 254 bytes + 1016 bytes = 1270 bytes total
 * - Example /20: 4094 bytes + 16376 bytes = 20470 bytes total
 * - Example /12: 1048575 bytes + 4194300 bytes = ~5.0 MB total
 * - Overhead: ~400% but provides perfect LRU behavior
 *
 */


/* LRU ring buffer - full pool size FIFO queue */
static int
ip_pool_lru_init(struct ip_pool_lru *lru, uint32_t pool_size)
{
	lru->ring = calloc(pool_size, sizeof(int));
	if (!lru->ring)
		return -1;

	lru->head = 0;
	lru->tail = 0;
	lru->count = 0;
	lru->size = pool_size;
	return 0;
}

static void
ip_pool_lru_push(struct ip_pool_lru *lru, int idx)
{
	/* If ring is full, overwrite oldest entry (move tail forward) */
	if (lru->count == lru->size) {
		lru->tail = (lru->tail + 1) % lru->size;
	} else {
		lru->count++;
	}

	lru->ring[lru->head] = idx;
	lru->head = (lru->head + 1) % lru->size;
}

static int
ip_pool_lru_pop(struct ip_pool_lru *lru, int *idx)
{
	/* Only use LRU when ring is full to ensure maximum cool-down period */
	if (lru->count < lru->size)
		return -1;

	/* Get oldest entry from tail */
	*idx = lru->ring[lru->tail];
	lru->tail = (lru->tail + 1) % lru->size;
	lru->count--;
	return 0;
}

static void
ip_pool_lru_destroy(struct ip_pool_lru *lru)
{
	if (!lru || !lru->ring)
		return;

	free(lru->ring);
	lru->ring = NULL;
	lru->count = 0;
	lru->size = 0;
}


/*
 * Pure LRU allocation strategy:
 * 0. Try LRU ring - allocate OLDEST freed address (true LRU/FIFO)
 *    Only when ring is FULL (pool_size entries) to ensure maximum cool-down period
 *    Ensures addresses "cool down" before reuse, optimal for cache efficiency
 * 1. Try next sequential allocation (used only during initial pool fill-up)
 *
 * This provides O(1) performance in all cases.
 */
static int
ip_pool_alloc_lease(struct ip_pool *p, int *idx)
{
	int lru_idx;

	/* Quick check: pool exhausted? */
	if (__sync_add_and_fetch(&p->used, 0) >= p->size)
		return -1;

	/* Path 0: Try LRU ring (optimal temporal locality) */
	if (ip_pool_lru_pop(&p->lru, &lru_idx) == 0) {
		if (lru_idx >= 0 && lru_idx < p->size && !p->lease[lru_idx]) {
			*idx = lru_idx;
			return 0;
		}
	}

	/* Path 1: Sequential allocation (only during initial fill-up) */
	if (p->next_lease_idx < p->size && !p->lease[p->next_lease_idx]) {
		*idx = p->next_lease_idx;
		return 0;
	}

	/* Should not reach here if used < size */
	return -1;
}

/* Generic helper to mark lease as allocated */
static void
ip_pool_mark_allocated(struct ip_pool *p, int idx)
{
	p->lease[idx] = true;
	p->next_lease_idx = idx + 1;
	__sync_add_and_fetch(&p->used, 1);
}

/* Generic helper to release lease */
static int
ip_pool_release_lease(struct ip_pool *p, int idx)
{
	if (idx < 0 || idx >= p->size) {
		errno = EINVAL;
		return -1;
	}

	p->lease[idx] = false;
	__sync_sub_and_fetch(&p->used, 1);

	/* Add to LRU ring for optimal reuse */
	ip_pool_lru_push(&p->lru, idx);

	return 0;
}

/* IPv6 helper to add offset to an IPv6 address */
static void
ipv6_addr_add_offset(struct in6_addr *result, const struct in6_addr *base,
		     size_t offset, uint64_t *seed)
{
	uint64_t *upper, *lower;

	memcpy(result, base, sizeof(struct in6_addr));
	upper = (uint64_t *) &result->s6_addr[0];
	*upper = htobe64(be64toh(*upper) + offset);

	lower = (uint64_t *) &result->s6_addr[8];
	*lower = xorshift_prng(seed);
}

/* IPv6 helper to calculate offset from base address */
static int
ipv6_addr_offset(const struct in6_addr *base, const struct in6_addr *addr, int *idx)
{
	uint64_t base_upper, addr_upper;

	base_upper = be64toh(*((uint64_t *) &base->s6_addr[0]));
	addr_upper = be64toh(*((uint64_t *) &addr->s6_addr[0]));

	/* Calculate the offset */
	if (addr_upper < base_upper) {
		/* Address is not within this pool */
		return -1;
	}

	*idx = addr_upper - base_upper;
	return 0;
}

int
ip_pool_get(struct ip_pool *p, void *addr)
{
	struct in6_addr *addr6;
	int idx;

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	if (ip_pool_alloc_lease(p, &idx) < 0) {
		errno = ENOSPC;
		return -1;
	}

	ip_pool_mark_allocated(p, idx);

	if (p->prefix.family == AF_INET) {
		struct in_addr *addr4 = (struct in_addr *) addr;
		addr4->s_addr = htonl(ntohl(p->prefix.sin.sin_addr.s_addr) + idx);
		return 0;
	}

	addr6 = (struct in6_addr *) addr;
	ipv6_addr_add_offset(addr6, &p->prefix.sin6.sin6_addr, idx, &p->seed);
	return 0;
}

int
ip_pool_put(struct ip_pool *p, void *addr)
{
	struct in6_addr *addr6;
	int idx, err;

	if (!p || !addr) {
		errno = EINVAL;
		return -1;
	}

	if (p->prefix.family == AF_INET) {
		struct in_addr *addr4 = (struct in_addr *) addr;
		idx = ntohl(addr4->s_addr & ~p->prefix.sin.sin_addr.s_addr);
		goto release;
	}

	addr6 = (struct in6_addr *) addr;
	err = ipv6_addr_offset(&p->prefix.sin6.sin6_addr, addr6, &idx);
	if (err) {
		errno = EINVAL;
		return -1;
	}

release:
	return ip_pool_release_lease(p, idx);
}

struct ip_pool *
ip_pool_alloc(const char *ip_pool_str)
{
	struct ip_pool *new;
	uint32_t size;
	int err;

	new = calloc(1, sizeof(*new));
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}

	err = addr_parse_ip(ip_pool_str, &new->prefix, &new->prefix_bits,
			    NULL, false);
	if (err)
		goto inval;

	new->seed = time(NULL);
	size = ((1U << (32 - new->prefix_bits)) - 1);

	/* For IPv6, allocate /64 subnets */
	if (new->prefix.family == AF_INET6) {
		if (new->prefix_bits >= 64)
			goto inval;
		size = ((1U << (64 - new->prefix_bits)) - 1);
	}

	new->size = size;

	/* Allocate lease bitmap */
	new->lease = calloc(new->size, sizeof(bool));
	if (!new->lease) {
		errno = ENOMEM;
		free(new);
		return NULL;
	}

	/* Initialize LRU ring buffer with full pool size */
	err = ip_pool_lru_init(&new->lru, new->size);
	if (err) {
		errno = ENOMEM;
		free(new->lease);
		free(new);
		return NULL;
	}

	return new;

inval:
	errno = EINVAL;
	free(new);
	return NULL;
}

void
ip_pool_destroy(struct ip_pool *p)
{
	if (!p)
		return;

	ip_pool_lru_destroy(&p->lru);
	free(p->lease);
	free(p);
}
