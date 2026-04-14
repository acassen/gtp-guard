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
#include "utils.h"


/*
 * Generic Lease Pool - O(1) Index Allocation Engine
 * ==================================================
 *
 * Shared allocation engine used by ip_pool (IP address ranges) and id_pool
 * (uint32 ID ranges). Manages a flat array of boolean leases with an LRU
 * ring to guarantee O(1) allocation and release in all cases.
 *
 * Phase 0 (initial fill): sequential allocation until all slots used once.
 * Phase 1 (steady state): LRU ring — allocate from tail (oldest freed slot),
 *   release to head. Ensures a natural cool-down before reuse, which reduces
 *   collision probability in high-churn environments (mobile networks).
 *
 * Memory: 1 byte per slot (lease bitmap) + 4 bytes per slot (LRU ring).
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
 *	'Inside-out' Fisher-Yates
 *
 *	builds a shuffled permutation in one pass. Classic 'Knuth shuffle'
 *	shuffles an already-initialized array in a backward pass. Our
 *	Inside-Out version runs the same logic to init and shuffle in
 *	a single pass.
 */
static void
lease_pool_shuffle(int *order, uint32_t size, uint64_t seed)
{
	uint32_t i, j;

	for (i = 1; i < size; i++) {
		j = (uint32_t)(xorshift_prng(&seed) % (i + 1));
		order[i] = order[j];
		order[j] = i;
	}
}


/*
 *	Lease helpers
 */
int
lease_pool_init(struct lease_pool *lp, uint32_t size, bool shuffle)
{
	uint64_t seed;

	lp->lease = calloc(size, sizeof(bool));
	if (!lp->lease)
		return -1;

	if (lease_lru_init(&lp->lru, size) < 0) {
		free(lp->lease);
		lp->lease = NULL;
		return -1;
	}

	if (shuffle) {
		lp->order = calloc(size, sizeof(int));
		if (!lp->order) {
			lease_lru_destroy(&lp->lru);
			free(lp->lease);
			lp->lease = NULL;
			return -1;
		}
		if (getrandom(&seed, sizeof(seed), 0) < 0)
			seed = (uint64_t)(uintptr_t)lp;
		lease_pool_shuffle(lp->order, size, seed);
	}

	lp->size = size;
	return 0;
}

/* Find a free slot index. Caller must call lease_pool_mark() after use. */
int
lease_pool_get(struct lease_pool *lp, int *idx)
{
	int lru_idx, slot;

	if (__sync_add_and_fetch(&lp->used, 0) >= lp->size)
		return -1;

	/* Phase 0: initial fill (linear or shuffled permutation) */
	if (lp->next_lease_idx < lp->size) {
		slot = lp->order ? lp->order[lp->next_lease_idx] : lp->next_lease_idx;
		if (!lp->lease[slot]) {
			*idx = slot;
			return 0;
		}
	}

	/* Phase 1: pure LRU — oldest freed slot */
	if (lease_lru_pop(&lp->lru, &lru_idx) == 0) {
		if (lru_idx >= 0 && lru_idx < lp->size && !lp->lease[lru_idx]) {
			*idx = lru_idx;
			return 0;
		}
	}

	return -1;
}

void
lease_pool_mark(struct lease_pool *lp, int idx)
{
	lp->lease[idx] = true;
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

	lp->lease[idx] = false;
	__sync_sub_and_fetch(&lp->used, 1);
	lease_lru_push(&lp->lru, idx);
	return 0;
}

void
lease_pool_destroy(struct lease_pool *lp)
{
	lease_lru_destroy(&lp->lru);
	free(lp->order);
	lp->order = NULL;
	free(lp->lease);
	lp->lease = NULL;
}
