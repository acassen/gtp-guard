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
#include <string.h>
#include <time.h>
#include <errno.h>

#include "ip_pool.h"
#include "lease_pool.h"
#include "utils.h"


/* IPv6 helper: add integer offset to upper 64 bits, roll the dices on lower 64 bits */
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

/* IPv6 helper: compute slot index from address offset relative to base */
static int
ipv6_addr_offset(const struct in6_addr *base, const struct in6_addr *addr,
		 int *idx)
{
	uint64_t base_upper, addr_upper;

	base_upper = be64toh(*((uint64_t *) &base->s6_addr[0]));
	addr_upper = be64toh(*((uint64_t *) &addr->s6_addr[0]));

	if (addr_upper < base_upper)
		return -1;

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

	if (lease_pool_get(&p->pool, &idx) < 0) {
		errno = ENOSPC;
		return -1;
	}

	lease_pool_mark(&p->pool, idx);

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
	return lease_pool_release(&p->pool, idx);
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

	if (new->prefix.family == AF_INET6) {
		if (new->prefix_bits >= 64)
			goto inval;
		size = ((1U << (64 - new->prefix_bits)) - 1);
	}

	if (lease_pool_init(&new->pool, size) < 0) {
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

	lease_pool_destroy(&p->pool);
	free(p);
}
