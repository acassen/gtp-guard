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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "lease_pool.h"
#include "thread.h"

struct thread_master *master;

#define POOL_SIZE	(1 << 24)

#define PASS	"PASS"
#define FAIL	"FAIL"

/*
 * Verify order[] is a valid permutation of [0..N-1] and is not the
 * identity (i.e. the shuffle actually ran). Also report the number of
 * sequential adjacent pairs as a basic randomness indicator.
 */
static int
test_shuffle_permutation(void)
{
	struct lease_pool lp = {0};
	bool *seen;
	int i, val, prev, sequential = 0;
	int ret = 0;

	seen = calloc(POOL_SIZE, sizeof(bool));
	if (!seen)
		return -1;

	if (lease_pool_init(&lp, POOL_SIZE, true) < 0) {
		fprintf(stderr, "  lease_pool_init failed\n");
		free(seen);
		return -1;
	}

	for (i = 0; i < POOL_SIZE; i++) {
		val = lease_pool_permute(&lp, i);
		if (val < 0 || val >= POOL_SIZE) {
			fprintf(stderr, "  permute(%d)=%d out of range\n", i, val);
			ret = -1;
			goto out;
		}
		if (seen[val]) {
			fprintf(stderr, "  duplicate value %d at position %d\n", val, i);
			ret = -1;
			goto out;
		}
		seen[val] = true;
	}

	prev = lease_pool_permute(&lp, 0);
	for (i = 1; i < POOL_SIZE; i++) {
		val = lease_pool_permute(&lp, i);
		if (val == prev + 1)
			sequential++;
		prev = val;
	}

	/* Identity permutation would have POOL_SIZE-1 sequential pairs */
	if (sequential == POOL_SIZE - 1) {
		fprintf(stderr, "  permutation is identity — shuffle did not run\n");
		ret = -1;
		goto out;
	}

	printf("  valid permutation, sequential adjacent pairs: %d/%d (~1 expected by chance)\n",
	       sequential, POOL_SIZE - 1);
	printf("  first 50 entries:");
	for (i = 0; i < 50; i++)
		printf(" %d", lease_pool_permute(&lp, i));
	printf("\n");
out:
	lease_pool_destroy(&lp);
	free(seen);
	return ret;
}

/*
 * Allocate every slot in Phase 0 and verify each returned index matches
 * the corresponding position in order[]. Then verify all slots are marked.
 */
static int
test_allocation_follows_order(void)
{
	struct lease_pool lp = {0};
	int idx, i, expected;
	int ret = 0;

	if (lease_pool_init(&lp, POOL_SIZE, true) < 0) {
		fprintf(stderr, "  lease_pool_init failed\n");
		return -1;
	}

	for (i = 0; i < POOL_SIZE; i++) {
		if (lease_pool_get(&lp, &idx) < 0) {
			fprintf(stderr, "  lease_pool_get failed at position %d\n", i);
			ret = -1;
			goto out;
		}
		expected = lease_pool_permute(&lp, i);
		if (idx != expected) {
			fprintf(stderr, "  position %d: got idx=%d, expected permute(%d)=%d\n",
				i, idx, i, expected);
			ret = -1;
			goto out;
		}
		lease_pool_mark(&lp, idx);
	}

	if (lp.used != POOL_SIZE) {
		fprintf(stderr, "  expected %d used slots, got %d\n", POOL_SIZE, lp.used);
		ret = -1;
		goto out;
	}

	printf("  all %d allocations matched shuffled order\n", POOL_SIZE);
out:
	lease_pool_destroy(&lp);
	return ret;
}

/*
 * Exhaust Phase 0, release a few slots, then reallocate via LRU. Verifies
 * that the LRU path is unaffected by the shuffle.
 */
static int
test_lru_after_shuffle(void)
{
	struct lease_pool lp = {0};
	int *slots;
	int idx, i;
	int ret = 0;

	slots = malloc(POOL_SIZE * sizeof(int));
	if (!slots)
		return -1;

	if (lease_pool_init(&lp, POOL_SIZE, true) < 0) {
		fprintf(stderr, "  lease_pool_init failed\n");
		free(slots);
		return -1;
	}

	/* Exhaust Phase 0 */
	for (i = 0; i < POOL_SIZE; i++) {
		if (lease_pool_get(&lp, &slots[i]) < 0) {
			fprintf(stderr, "  Phase 0 get failed at %d\n", i);
			ret = -1;
			goto out;
		}
		lease_pool_mark(&lp, slots[i]);
	}

	/* Release 8 slots into the LRU ring */
	for (i = 0; i < 8; i++) {
		if (lease_pool_release(&lp, slots[i]) < 0) {
			fprintf(stderr, "  release failed for slot %d\n", slots[i]);
			ret = -1;
			goto out;
		}
	}

	/* Reallocate from LRU */
	for (i = 0; i < 8; i++) {
		if (lease_pool_get(&lp, &idx) < 0) {
			fprintf(stderr, "  LRU get failed at %d\n", i);
			ret = -1;
			goto out;
		}
		lease_pool_mark(&lp, idx);
	}

	if (lp.used != POOL_SIZE) {
		fprintf(stderr, "  expected %d used after LRU cycle, got %d\n", POOL_SIZE, lp.used);
		ret = -1;
		goto out;
	}

	printf("  LRU path: 8 slots released and reallocated, pool full again\n");
out:
	lease_pool_destroy(&lp);
	free(slots);
	return ret;
}


int
main(void)
{
	struct {
		const char *name;
		int (*fn)(void);
	} tests[] = {
		{ "shuffle produces valid permutation",      test_shuffle_permutation      },
		{ "allocations follow shuffled order",       test_allocation_follows_order },
		{ "LRU path works after Phase 0 exhausted",  test_lru_after_shuffle        },
	};
	int i, result, failed = 0;

	printf("lease_pool shuffle selftest\n");
	printf("pool size: %d slots\n\n", POOL_SIZE);

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		result = tests[i].fn();
		printf("[%s] %s\n\n", result == 0 ? PASS : FAIL, tests[i].name);
		if (result < 0)
			failed++;
	}

	printf("%d/%d tests passed\n", (int)(sizeof(tests) / sizeof(tests[0])) - failed,
	       (int)(sizeof(tests) / sizeof(tests[0])));
	return failed ? 1 : 0;
}
