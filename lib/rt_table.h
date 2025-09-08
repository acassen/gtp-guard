/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Routing table implementation
 * Copyright (C) 1997 Kunihiro Ishiguro
 */
#pragma once

#include "prefix.h"

/* Each routing entry */
struct rt_table;
struct rt_node {
	/* Actual prefix of this radix */
	struct prefix		p;

	/* Tree link */
	struct rt_table		*table;
	struct rt_node		*parent;
	struct rt_node		*link[2];
#define l_left link[0]
#define l_right link[1]

	/* Lock of this radix */
	unsigned int		lock;

	/* Each node of route */
	void			*info;
};

/* Routing table top structure */
struct rt_table {
	struct rt_node	*top;
	int		(*free_info) (void *);
	int		(*dump_info) (void *);
};


/*
 *	Prototypes
 */
struct rt_table *rt_table_init(int (*free) (void *), int (*dump) (void *));
int rt_table_free(struct rt_table *rt);
int rt_table_dump(struct rt_table *rt);
struct rt_node *rt_node_match(const struct rt_table *table, const struct prefix *p);
struct rt_node *rt_node_match_ipv4(const struct rt_table *table, const struct in_addr *addr);
struct rt_node *rt_node_match_ipv6(const struct rt_table *table, const struct in6_addr *addr);
struct rt_node *rt_node_lookup(struct rt_table *table, struct prefix *p);
struct rt_node *rt_node_lookup_lpm(struct rt_table *table, struct prefix *p);
struct rt_node *rt_node_get(struct rt_table *table, struct prefix *p);
int rt_node_delete(struct rt_node *node);
struct rt_node *rt_next(struct rt_node *node);
struct rt_node *rt_next_until(struct rt_node *node, struct rt_node *limit);
