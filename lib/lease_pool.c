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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/random.h>

#include "lease_pool.h"


/*
 * Generic Lease Pool - O(1) Index Allocation Engine
 * ==================================================
 *
 * Shared allocation engine used by ip_pool (IP address ranges) and id_pool
 * (uint32 ID ranges). Manages a bitmap of leases with an LRU ring to
 * guarantee O(1) allocation and release in all cases.
 *
 * Phase 0 (initial fill): sequential allocation until all slots used once.
 * Phase 1 (steady state): LRU ring — allocate from tail (oldest freed slot),
 *   release to head. Ensures a natural cool-down before reuse, which reduces
 *   collision probability in high-churn environments (mobile networks).
 *
 * Memory: 1 bit per slot (lease bitmap) + 4 bytes per slot (LRU ring).
 * Shuffle mode uses a Feistel permutation (zero extra memory) instead of
 * a materialized permutation array.
 */


/*
 *	LRU ring
 */
static int
lease_lru_init(struct lease_lru *lru, uint32_t size)
{
	lru->ring = calloc(size, sizeof(int));
	if (!lru->ring)
		return -1;

	lru->head = 0;
	lru->tail = 0;
	lru->count = 0;
	lru->size = size;
	return 0;
}

static void
lease_lru_push(struct lease_lru *lru, int idx)
{
	/* Ring full: advance tail to overwrite oldest entry */
	if (lru->count == lru->size)
		lru->tail = (lru->tail + 1) % lru->size;
	else
		lru->count++;

	lru->ring[lru->head] = idx;
	lru->head = (lru->head + 1) % lru->size;
}

static int
lease_lru_pop(struct lease_lru *lru, int *idx)
{
	if (lru->count == 0)
		return -1;

	*idx = lru->ring[lru->tail];
	lru->tail = (lru->tail + 1) % lru->size;
	lru->count--;
	return 0;
}

static void
lease_lru_destroy(struct lease_lru *lru)
{
	if (!lru->ring)
		return;

	free(lru->ring);
	lru->ring = NULL;
	lru->count = 0;
	lru->size = 0;
}


/*
 *	Lease bitmap helpers
 */
static inline bool
lease_bit_test(const uint8_t *bitmap, uint32_t idx)
{
	return bitmap[idx >> 3] & (1U << (idx & 7));
}

static inline void
lease_bit_set(uint8_t *bitmap, uint32_t idx)
{
	bitmap[idx >> 3] |= (1U << (idx & 7));
}

static inline void
lease_bit_clear(uint8_t *bitmap, uint32_t idx)
{
	bitmap[idx >> 3] &= ~(1U << (idx & 7));
}


/*
 *	Feistel permutation
 *
 *	Bijective mapping [0, size) -> [0, size) using a 4-round Feistel
 *	network. Replaces the materialized order[] array with O(1) per-index
 *	computation and zero memory overhead. Cycle-walking handles non
 *	power-of-two domains.
 */
#define FEISTEL_ROUNDS	4

static uint32_t
ceil_log2(uint32_t n)
{
	if (n <= 1)
		return 1;
	return 32 - __builtin_clz(n - 1);
}

static inline uint32_t
feistel_round_fn(uint32_t val, uint32_t key)
{
	val ^= key;
	val *= 0x9e3779b9U;
	val ^= val >> 16;
	val *= 0x45d9f3bU;
	val ^= val >> 16;
	return val;
}

static uint32_t
feistel_permute(uint32_t idx, uint32_t bits, uint32_t size, uint64_t seed)
{
	uint32_t half = (bits + 1) / 2;
	uint32_t mask = (1U << half) - 1;
	uint32_t keys[FEISTEL_ROUNDS];
	uint32_t i, l, r, f, tmp;

	for (i = 0; i < FEISTEL_ROUNDS; i++) {
		uint64_t k = seed + (uint64_t)i * 0x517cc1b727220a95ULL;
		k ^= k >> 30;
		k *= 0xbf58476d1ce4e5b9ULL;
		k ^= k >> 27;
		keys[i] = (uint32_t)k;
	}

	do {
		l = (idx >> half) & mask;
		r = idx & mask;

		for (i = 0; i < FEISTEL_ROUNDS; i++) {
			f = feistel_round_fn(r, keys[i]) & mask;
			tmp = r;
			r = l ^ f;
			l = tmp;
		}

		idx = (l << half) | r;
	} while (idx >= size);

	return idx;
}


/*
 *	Lease helpers
 */
int
lease_pool_init(struct lease_pool *lp, uint32_t size, bool shuffle)
{
	uint64_t seed;

	lp->lease = calloc((size + 7) / 8, 1);
	if (!lp->lease)
		return -1;

	if (lease_lru_init(&lp->lru, size) < 0) {
		free(lp->lease);
		lp->lease = NULL;
		return -1;
	}

	if (shuffle) {
		if (getrandom(&seed, sizeof(seed), 0) < 0)
			seed = (uint64_t)(uintptr_t)lp;
		lp->shuffle_seed = seed;
		lp->shuffle_bits = ceil_log2(size);
	}

	lp->size = size;
	return 0;
}

/* Return the permuted index for position idx (Feistel or identity) */
int
lease_pool_permute(struct lease_pool *lp, uint32_t idx)
{
	if (!lp->shuffle_seed || idx >= lp->size)
		return (int)idx;
	return (int)feistel_permute(idx, lp->shuffle_bits, lp->size, lp->shuffle_seed);
}

/* Find a free slot index. Caller must call lease_pool_mark() after use. */
int
lease_pool_get(struct lease_pool *lp, int *idx)
{
	int lru_idx, slot;

	if (__sync_add_and_fetch(&lp->used, 0) >= lp->size)
		return -1;

	/* Phase 0: initial fill (linear or Feistel permutation) */
	if (lp->next_lease_idx < lp->size) {
		slot = lp->shuffle_seed
		     ? (int)feistel_permute(lp->next_lease_idx, lp->shuffle_bits,
					    lp->size, lp->shuffle_seed)
		     : lp->next_lease_idx;
		if (!lease_bit_test(lp->lease, slot)) {
			*idx = slot;
			return 0;
		}
	}

	/* Phase 1: pure LRU — oldest freed slot */
	if (lease_lru_pop(&lp->lru, &lru_idx) == 0) {
		if (lru_idx >= 0 && lru_idx < lp->size &&
		    !lease_bit_test(lp->lease, lru_idx)) {
			*idx = lru_idx;
			return 0;
		}
	}

	return -1;
}

void
lease_pool_mark(struct lease_pool *lp, int idx)
{
	lease_bit_set(lp->lease, idx);
	if (lp->next_lease_idx < lp->size)
		lp->next_lease_idx++;
	__sync_add_and_fetch(&lp->used, 1);
}

int
lease_pool_release(struct lease_pool *lp, int idx)
{
	if (idx < 0 || idx >= lp->size) {
		errno = EINVAL;
		return -1;
	}

	lease_bit_clear(lp->lease, idx);
	__sync_sub_and_fetch(&lp->used, 1);
	lease_lru_push(&lp->lru, idx);
	return 0;
}

void
lease_pool_destroy(struct lease_pool *lp)
{
	lease_lru_destroy(&lp->lru);
	free(lp->lease);
	lp->lease = NULL;
}
