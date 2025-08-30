/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Routing table implementation
 * Copyright (C) 1997 Kunihiro Ishiguro
 */
#pragma once

#include "prefix.h"

/* Each routing entry */
struct _rt_table;
typedef struct _rt_node {
	/* Actual prefix of this radix */
	prefix_t		p;

	/* Tree link */
	struct _rt_table	*table;
	struct _rt_node		*parent;
	struct _rt_node		*link[2];
#define l_left link[0]
#define l_right link[1]

	/* Lock of this radix */
	unsigned int		lock;

	/* Each node of route */
	void			*info;
} rt_node_t;

/* Routing table top structure */
typedef struct _rt_table {
	rt_node_t	*top;
	int		(*free_info) (void *);
	int		(*dump_info) (void *);
} rt_table_t;


/*
 *	Prototypes
 */
rt_table_t *rt_table_init(int (*free) (void *), int (*dump) (void *));
int rt_table_free(rt_table_t *rt);
int rt_table_dump(rt_table_t *rt);
rt_node_t *rt_node_match(const rt_table_t *table, const prefix_t *p);
rt_node_t *rt_node_match_ipv4(const rt_table_t *table, const struct in_addr *addr);
rt_node_t *rt_node_match_ipv6(const rt_table_t *table, const struct in6_addr *addr);
rt_node_t *rt_node_lookup(rt_table_t *table, prefix_t *p);
rt_node_t *rt_node_lookup_lpm(rt_table_t *table, prefix_t *p);
rt_node_t *rt_node_get(rt_table_t *table, prefix_t *p);
int rt_node_delete(rt_node_t *node);
rt_node_t *rt_next(rt_node_t *node);
rt_node_t *rt_next_until(rt_node_t *node, rt_node_t *limit);
