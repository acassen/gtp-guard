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
#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Circular buffer of freed indices for O(1) reuse */
struct lease_lru {
	int		*ring;
	uint32_t	head;
	uint32_t	tail;
	uint32_t	count;
	uint32_t	size;
};

/* Generic index-based lease pool: allocate/release integer slots in O(1) */
struct lease_pool {
	uint8_t		*lease;		/* bitmap: 1 bit per slot */
	uint64_t	shuffle_seed;	/* Feistel permutation seed, 0 if linear */
	uint32_t	shuffle_bits;	/* ceil(log2(size)) for Feistel domain */
	struct lease_lru lru;
	int		next_lease_idx;
	uint32_t	size;
	uint32_t	used;
};

/* Prototypes */
int lease_pool_init(struct lease_pool *lp, uint32_t size, bool shuffle);
int lease_pool_get(struct lease_pool *lp, int *idx);
void lease_pool_mark(struct lease_pool *lp, int idx);
int lease_pool_release(struct lease_pool *lp, int idx);
void lease_pool_destroy(struct lease_pool *lp);
int lease_pool_permute(struct lease_pool *lp, uint32_t idx);
