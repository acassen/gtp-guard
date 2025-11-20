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
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "addr.h"

/* Chunk size for scanning optimization (64 entries per chunk) */
#define IP_POOL_CHUNK_SHIFT	6
#define IP_POOL_CHUNK_SIZE	(1 << IP_POOL_CHUNK_SHIFT)
#define IP_POOL_CHUNK_MASK	(IP_POOL_CHUNK_SIZE - 1)

#define IP_POOL_LRU_SIZE	256	/* Track last 256 freed addresses */

struct ip_pool_lru {
	int		*ring;		/* Circular buffer of recently freed indices */
	uint32_t	head;		/* Write position */
	uint32_t	tail;		/* Read position */
	uint32_t	count;		/* Number of entries */
};

struct ip_pool {
	union addr	prefix;
	uint32_t	prefix_bits;
	bool		*lease;
	struct ip_pool_lru lru;		/* LRU tracking structure */
	uint32_t	*chunk_free;	/* Free count per chunk for fast scanning */
	uint32_t	num_chunks;	/* Number of chunks */
	int		next_lease_idx;	/* Hint for next allocation */
	uint32_t	size;
	uint32_t	used;
	uint64_t	seed;
};

/* Prototypes */
int ip_pool_get(struct ip_pool *p, void *addr);
int ip_pool_put(struct ip_pool *p, void *addr);
float ip_pool_frag_ratio(struct ip_pool *p);
struct ip_pool *ip_pool_alloc(const char *ip_pool_str);
void ip_pool_destroy(struct ip_pool *p);
