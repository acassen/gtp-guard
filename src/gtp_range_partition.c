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
#include <stdio.h>
#include <arpa/inet.h>

#include "gtp_data.h"
#include "gtp_range_partition.h"
#include "addr.h"
#include "utils.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Part helpers
 */
static const char *rp_strs[] = {
	[GTP_RANGE_PARTITION_TEID] = "TEID",
	[GTP_RANGE_PARTITION_IPV4] = "IPv4",
	[GTP_RANGE_PARTITION_IPV6] = "IPv6",
};

const char *
range_partition_type2str(int type)
{
	if (type >= GTP_RANGE_PARTITION_TYPE_MAX)
		return "unknown";
	return rp_strs[type];
}

static void
part_pool_destroy(struct gtp_range_partition *rp, struct gtp_range_part *p)
{
	if (rp->type == GTP_RANGE_PARTITION_TEID) {
		id_pool_destroy(p->id_pool);
		return;
	}

	ip_pool_destroy(p->ip_pool);
}

struct gtp_range_part *
gtp_range_partition_get_part(struct gtp_range_partition *rp, int part_id)
{
	int i;

	for (i = 0; i < rp->nr_parts; i++) {
		if (rp->parts[i].part_id == part_id)
			return &rp->parts[i];
	}
	return NULL;
}

struct gtp_range_part *
gtp_range_partition_get_part_by_index(struct gtp_range_partition *rp, int idx)
{
	if (idx < 0 || idx >= rp->nr_parts)
		return NULL;
	return &rp->parts[idx];
}

/* Append a pre-allocated pool, keeping parts sorted by part_id */
int
gtp_range_partition_add_part(struct gtp_range_partition *rp, int part_id, void *pool)
{
	struct gtp_range_part *new_parts;
	int insert_at;

	if (!pool || gtp_range_partition_get_part(rp, part_id))
		return -1;

	new_parts = realloc(rp->parts, (rp->nr_parts + 1) * sizeof(*new_parts));
	if (!new_parts)
		return -1;
	rp->parts = new_parts;

	for (insert_at = 0; insert_at < rp->nr_parts; insert_at++) {
		if (rp->parts[insert_at].part_id > part_id)
			break;
	}

	memmove(&rp->parts[insert_at + 1], &rp->parts[insert_at],
		(rp->nr_parts - insert_at) * sizeof(*rp->parts));

	rp->parts[insert_at].part_id = part_id;
	rp->parts[insert_at].id_pool = pool; /* both id_pool and ip_pool share storage */
	rp->nr_parts++;
	return 0;
}

int
gtp_range_partition_del_part(struct gtp_range_partition *rp, int part_id)
{
	int i;

	for (i = 0; i < rp->nr_parts; i++) {
		if (rp->parts[i].part_id != part_id)
			continue;

		part_pool_destroy(rp, &rp->parts[i]);
		memmove(&rp->parts[i], &rp->parts[i + 1],
			(rp->nr_parts - i - 1) * sizeof(*rp->parts));
		rp->nr_parts--;
		return 0;
	}
	return -1;
}

static void
parts_destroy_all(struct gtp_range_partition *rp)
{
	int i;

	for (i = 0; i < rp->nr_parts; i++)
		part_pool_destroy(rp, &rp->parts[i]);

	free(rp->parts);
	rp->parts = NULL;
	rp->nr_parts = 0;
}


/*
 *	Auto-split helpers
 *
 * range_str format:
 *   TEID: "0xHEXBASE/PREFIX_BITS" e.g. "0x10000000/8"
 *   IPv4: "A.B.C.D/M"             e.g. "10.0.0.0/8"
 *   IPv6: "X:X::X:X/M"            e.g. "2001:db8::/46"
 */
static int
split_teid(struct gtp_range_partition *rp, const char *range_str, int k, int count)
{
	uint32_t base, part_size;
	int part_prefix, prefix, i;
	char *slash;
	void *pool;

	base = strtoul(range_str, &slash, 0);
	if (*slash != '/')
		return -1;
	prefix = atoi(slash + 1);
	if (prefix < 0 || prefix > 31)
		return -1;

	part_prefix = prefix + k;
	if (part_prefix > 31)
		return -1;

	part_size = 1U << (32 - part_prefix);
	for (i = 0; i < count; i++) {
		pool = id_pool_alloc(base + (uint32_t)(i * part_size), part_prefix);
		if (!pool)
			goto err;
		if (gtp_range_partition_add_part(rp, i, pool) < 0) {
			id_pool_destroy(pool);
			goto err;
		}
	}
	return 0;

err:
	parts_destroy_all(rp);
	return -1;
}

static int
split_ipv4(struct gtp_range_partition *rp, const char *range_str, int k, int count)
{
	char addr_str[INET_ADDRSTRLEN], cidr[64];
	uint32_t base_bits, part_size, prefix_bits;
	union addr base_addr;
	struct in_addr in;
	int part_prefix, i;
	void *pool;

	if (addr_parse_ip(range_str, &base_addr, &prefix_bits, NULL, true) < 0)
		return -1;
	if (base_addr.family != AF_INET)
		return -1;

	part_prefix = (int)prefix_bits + k;
	if (part_prefix > 31)
		return -1;

	part_size = 1U << (32 - part_prefix);
	base_bits = ntohl(base_addr.sin.sin_addr.s_addr);

	for (i = 0; i < count; i++) {
		in.s_addr = htonl(base_bits + (uint32_t)(i * part_size));
		inet_ntop(AF_INET, &in, addr_str, sizeof(addr_str));
		snprintf(cidr, sizeof(cidr), "%s/%d", addr_str, part_prefix);
		pool = ip_pool_alloc(cidr);
		if (!pool)
			goto err;
		if (gtp_range_partition_add_part(rp, i, pool) < 0) {
			ip_pool_destroy(pool);
			goto err;
		}
	}
	return 0;

err:
	parts_destroy_all(rp);
	return -1;
}

static int
split_ipv6(struct gtp_range_partition *rp, const char *range_str, int k, int count)
{
	char addr_str[INET6_ADDRSTRLEN], cidr[64];
	union addr base_addr;
	struct in6_addr addr6;
	uint32_t prefix_bits;
	int part_prefix, b, q;
	void *pool;

	if (addr_parse_ip(range_str, &base_addr, &prefix_bits, NULL, true) < 0)
		return -1;
	if (base_addr.family != AF_INET6)
		return -1;

	part_prefix = (int)prefix_bits + k;
	if (part_prefix > 128)
		return -1;

	for (q = 0; q < count; q++) {
		addr6 = base_addr.sin6.sin6_addr;
		for (b = 0; b < k; b++) {
			int pos = (int)prefix_bits + b;
			if (q & (1 << (k - 1 - b)))
				addr6.s6_addr[pos / 8] |= (uint8_t)(0x80 >> (pos % 8));
		}
		inet_ntop(AF_INET6, &addr6, addr_str, sizeof(addr_str));
		snprintf(cidr, sizeof(cidr), "%s/%d", addr_str, part_prefix);
		pool = ip_pool_alloc(cidr);
		if (!pool)
			goto err;
		if (gtp_range_partition_add_part(rp, q, pool) < 0) {
			ip_pool_destroy(pool);
			goto err;
		}
	}
	return 0;

err:
	parts_destroy_all(rp);
	return -1;
}

int
gtp_range_partition_split(struct gtp_range_partition *rp, const char *range_str,
			  int count)
{
	int k, ret;

	if (count <= 0 || (count & (count - 1))) /* must be power of 2 */
		return -1;

	k = __builtin_ctz(count); /* log2(count) */

	switch (rp->type) {
	case GTP_RANGE_PARTITION_TEID:
		ret = split_teid(rp, range_str, k, count);
		break;
	case GTP_RANGE_PARTITION_IPV4:
		ret = split_ipv4(rp, range_str, k, count);
		break;
	case GTP_RANGE_PARTITION_IPV6:
		ret = split_ipv6(rp, range_str, k, count);
		break;
	default:
		return -1;
	}

	if (ret < 0)
		return -1;

	rp->auto_split = true;
	bsd_strlcpy(rp->split_range, range_str, GTP_STR_MAX_LEN - 1);
	rp->split_count = count;
	return 0;
}

int
gtp_range_partition_split_clear(struct gtp_range_partition *rp)
{
	if (!rp->auto_split)
		return -1;

	parts_destroy_all(rp);
	rp->auto_split = false;
	rp->split_range[0] = '\0';
	rp->split_count = 0;
	return 0;
}


/*
 *	Lifecycle
 */
struct gtp_range_partition *
gtp_range_partition_get(const char *name)
{
	struct gtp_range_partition *rp;

	list_for_each_entry(rp, &daemon_data->range_partition, next) {
		if (!strncmp(rp->name, name, GTP_NAME_MAX_LEN - 1))
			return rp;
	}
	return NULL;
}

struct gtp_range_partition *
gtp_range_partition_alloc(const char *name)
{
	struct gtp_range_partition *new;

	new = calloc(1, sizeof(*new));
	if (!new)
		return NULL;

	bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);
	new->af = AF_INET;
	INIT_LIST_HEAD(&new->next);
	list_add_tail(&new->next, &daemon_data->range_partition);
	return new;
}

int
gtp_range_partition_free(struct gtp_range_partition *rp)
{
	if (!rp || rp->refcnt)
		return -1;

	list_del(&rp->next);
	parts_destroy_all(rp);
	free(rp);
	return 0;
}

int
gtp_range_partition_destroy(void)
{
	struct gtp_range_partition *rp, *tmp;

	list_for_each_entry_safe(rp, tmp, &daemon_data->range_partition, next) {
		rp->refcnt = 0;
		gtp_range_partition_free(rp);
	}
	return 0;
}
