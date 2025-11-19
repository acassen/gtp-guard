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

#include <asm-generic/errno-base.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "ip_pool.h"
#include "utils.h"


/* Generic helper to find and allocate a lease */
static int
ip_pool_alloc_lease(struct ip_pool *p, int *idx)
{
	if (__sync_add_and_fetch(&p->used, 0) >= p->size)
		return -1;

	/* fast-path */
	*idx = p->next_lease_idx;
	if (!p->lease[*idx])
		return 0;

	/* slow-path */
	for (*idx = 0; *idx < p->size; (*idx)++) {
		if (!p->lease[*idx])
			return 0;
	}

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
	p->next_lease_idx = idx;
	__sync_sub_and_fetch(&p->used, 1);
	return 0;
}

/* IPv6 helper to add offset to an IPv6 address */
static void
ipv6_addr_add_offset(struct in6_addr *result, const struct in6_addr *base, size_t offset,
		     uint64_t *seed)
{
	uint64_t *upper, *lower;

	memcpy(result, base, sizeof(struct in6_addr));
	upper = (uint64_t *) &result->s6_addr[0];
	*upper = be64toh(*upper) + offset;
	*upper = htobe64(*upper);

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
	new->lease = calloc(new->size, sizeof(bool));
	if (!new->lease) {
		errno = ENOMEM;
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

	free(p->lease);
	free(p);
}
