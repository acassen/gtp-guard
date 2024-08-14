/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Routing table implementation
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#include <time.h>
#include <ctype.h>
#include "memory.h"
#include "utils.h"
#include "prefix.h"
#include "rt_table.h"


/* Utility mask array. */
static const uint8_t maskbit[] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };


/*
 *	Routing table structure
 */
rt_table_t *
rt_table_init(int (*free) (void *), int (*dump) (void *))
{
	rt_table_t *rt;

	rt = (rt_table_t *) MALLOC(sizeof(rt_table_t));
	rt->free_info = free;
	rt->dump_info = dump;

	return rt;
}

void
rt_table_finish(rt_table_t *rt)
{
	rt_table_free(rt);
}

static rt_node_t *
rt_node_new(void)
{
	rt_node_t *node;

	node = (rt_node_t *) MALLOC(sizeof(rt_node_t));

	return node;
}

static rt_node_t *
rt_node_set(rt_table_t *table, prefix_t *prefix)
{
	rt_node_t *node = rt_node_new();

	prefix_copy(&node->p, prefix);
	node->table = table;

	return node;
}

static void
rt_node_free(rt_node_t *node)
{
	FREE(node);
}

int
rt_table_free(rt_table_t *rt)
{
	rt_node_t *tmp_node, *node;

	if (rt == NULL)
		return -1;

	node = rt->top;

	while (node) {
		if (node->l_left) {
			node = node->l_left;
			continue;
		}

		if (node->l_right) {
			node = node->l_right;
			continue;
		}

		tmp_node = node;
		node = node->parent;

		if (node != NULL) {
			if (node->l_left == tmp_node)
				node->l_left = NULL;
			else
				node->l_right = NULL;

			if (rt->free_info)
				(*rt->free_info) (tmp_node->info);
			rt_node_free(tmp_node);
		} else {
			if (rt->free_info)
				(*rt->free_info) (tmp_node->info);
			rt_node_free(tmp_node);
			break;
		}
	}

	FREE(rt);
	return 0;
}

int
rt_table_dump(rt_table_t *rt)
{
	rt_node_t *tmp_node, *node;

	if (rt == NULL)
		return -1;

	node = rt->top;

	while (node) {
		if (node->l_left) {
			node = node->l_left;
			continue;
		}

		if (node->l_right) {
			node = node->l_right;
			continue;
		}

		tmp_node = node;
		node = node->parent;

		if (node != NULL) {
			if (node->l_left == tmp_node)
				node->l_left = NULL;
			else
				node->l_right = NULL;

			if (rt->dump_info) {
				prefix_dump(&tmp_node->p);
				(*rt->dump_info) (tmp_node->info);
			}
		} else {
			if (rt->dump_info) {
				prefix_dump(&tmp_node->p);
				(*rt->dump_info) (tmp_node->info);
			}
			break;
		}
	}

	return 0;
}


/*
 *	Routing table handler
 */
static void
rt_common(prefix_t *n, prefix_t *p, prefix_t *new)
{
	int i;
	uint8_t diff, mask;
	uint8_t *np = (uint8_t *)&n->u.prefix;
	uint8_t *pp = (uint8_t *)&p->u.prefix;
	uint8_t *newp = (uint8_t *)&new->u.prefix;

	for (i = 0; i < p->prefixlen / 8; i++) {
		if (np[i] == pp[i])
			newp[i] = np[i];
		else
			break;
	}

	new->prefixlen = i * 8;

	if (new->prefixlen != p->prefixlen) {
		diff = np[i] ^ pp[i];
		mask = 0x80;
		while (new->prefixlen < p->prefixlen && !(mask & diff)) {
			mask >>= 1;
			new->prefixlen++;
		}
		newp[i] = np[i] & maskbit[new->prefixlen % 8];
	}
}

static void
set_link(rt_node_t *node, rt_node_t *new)
{
	unsigned int bit = prefix_bit(&new->p.u.prefix, node->p.prefixlen);

	node->link[bit] = new;
	new->parent = node;
}

/* Lock node. */
rt_node_t *
rt_lock_node(rt_node_t *node)
{
	node->lock++;
	return node;
}

/* Unlock node. */
void
rt_unlock_node(rt_node_t *node)
{
	node->lock--;

	if (node->lock == 0)
		rt_node_delete(node);
}

/* Find matched prefix. */
rt_node_t *
rt_node_match(const rt_table_t *table, const prefix_t *p)
{
	rt_node_t *node, *matched;

	matched = NULL;
	node = table->top;

	/* Walk down tree.  If there is matched route then store it to
	   matched. */
	while (node && node->p.prefixlen <= p->prefixlen && prefix_match(&node->p, p)) {
		if (node->info)
			matched = node;

		if (node->p.prefixlen == p->prefixlen)
			break;

		node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
	}

	/* If matched route found, return it. */
	if (matched)
		return rt_lock_node(matched);

	return NULL;
}

rt_node_t *
rt_node_match_ipv4(const rt_table_t *table, const struct in_addr *addr)
{
	prefix_ipv4_t p;

	memset(&p, 0, sizeof(prefix_ipv4_t));
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_PREFIXLEN;
	p.prefix = *addr;

	return rt_node_match(table, (prefix_t *) &p);
}

rt_node_t *
rt_node_match_ipv6(const rt_table_t *table, const struct in6_addr *addr)
{
	prefix_ipv6_t p;

	memset(&p, 0, sizeof(prefix_ipv6_t));
	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_PREFIXLEN;
	p.prefix = *addr;

	return rt_node_match(table, (prefix_t *) &p);
}


/* Lookup same prefix node.  Return NULL when we can't find route. */
rt_node_t *
rt_node_lookup(rt_table_t *table, prefix_t *p)
{
	rt_node_t *node = table->top;

	while (node && node->p.prefixlen <= p->prefixlen && prefix_match(&node->p, p)) {
		if (node->p.prefixlen == p->prefixlen) {
			return node->info ? rt_lock_node(node) : NULL;
		}

		node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
	}

	return NULL;
}

/* Longest prefix match */
rt_node_t *
rt_node_lookup_lpm(rt_table_t *table, prefix_t *p)
{
	rt_node_t *node = table->top, *match = NULL;

	while (node && node->p.prefixlen <= p->prefixlen && prefix_match(&node->p, p)) {
		if (node->info)
			match = node;
		node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
	}

	return match;
}

/* Add node to routing table. */
rt_node_t *
rt_node_get(rt_table_t *table, prefix_t *p)
{
	rt_node_t *new, *node = table->top, *match = NULL;

	while (node && node->p.prefixlen <= p->prefixlen && prefix_match(&node->p, p)) {
		if (node->p.prefixlen == p->prefixlen)
			return rt_lock_node(node);

		match = node;
		node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
	}

	if (node == NULL) {
		new = rt_node_set(table, p);
		if (match)
			set_link(match, new);
		else
			table->top = new;
	} else {
		new = rt_node_new();
		rt_common(&node->p, p, &new->p);
		new->p.family = p->family;
		new->table = table;
		set_link(new, node);

		if (match)
			set_link(match, new);
		else
			table->top = new;

		if (new->p.prefixlen != p->prefixlen) {
			match = new;
			new = rt_node_set(table, p);
			set_link(match, new);
		}
	}

	rt_lock_node(new);

	return new;
}

/* Delete node from the routing table. */
int
rt_node_delete(rt_node_t *node)
{
	rt_node_t *child, *parent;

	if (node->lock == 0 || node->info == NULL)
		return -1;

	if (node->l_left && node->l_right)
		return 0;

	if (node->l_left)
		child = node->l_left;
	else
		child = node->l_right;

	parent = node->parent;

	if (child)
		child->parent = parent;

	if (parent) {
		if (parent->l_left == node)
			parent->l_left = child;
		else
			parent->l_right = child;
	} else {
		node->table->top = child;
	}

	rt_node_free(node);

	/* If parent node is stub then delete it also. */
	if (parent && parent->lock == 0)
		rt_node_delete(parent);

	return 0;
}

/* Get first node and lock it.  This function is useful when one want
   to lookup all the node exist in the routing table. */
rt_node_t *
rt_top(rt_table_t *table)
{
	/* If there is no node in the routing table return NULL. */
	if (table->top == NULL)
		return NULL;

	/* Lock the top node and return it. */
	rt_lock_node(table->top);
	return table->top;
}

/* Unlock current node and lock next node then return it. */
rt_node_t *
rt_next(rt_node_t *node)
{
	rt_node_t *next, *start;

	/* Node may be deleted from route_unlock_node so we have to preserve
	   next node's pointer. */

	if (node->l_left) {
		next = node->l_left;
		rt_lock_node(next);
		rt_unlock_node(node);
		return next;
	}

	if (node->l_right) {
		next = node->l_right;
		rt_lock_node(next);
		rt_unlock_node(node);
		return next;
	}

	start = node;
	while (node->parent) {
		if (node->parent->l_left == node && node->parent->l_right) {
			next = node->parent->l_right;
			rt_lock_node(next);
			rt_unlock_node(start);
			return next;
		}
		node = node->parent;
	}

	rt_unlock_node(start);
	return NULL;
}

/* Unlock current node and lock next node until limit. */
rt_node_t *
rt_next_until(rt_node_t *node, rt_node_t *limit)
{
	rt_node_t *next, *start;

	/* Node may be deleted from route_unlock_node so we have to preserve
	   next node's pointer. */
	if (node->l_left) {
		next = node->l_left;
		rt_lock_node(next);
		rt_unlock_node(node);
		return next;
	}

	if (node->l_right) {
		next = node->l_right;
		rt_lock_node(next);
		rt_unlock_node(node);
		return next;
	}

	start = node;
	while (node->parent && node != limit) {
		if (node->parent->l_left == node && node->parent->l_right) {
			next = node->parent->l_right;
			rt_lock_node(next);
			rt_unlock_node(start);
			return next;
		}
		node = node->parent;
	}

	rt_unlock_node(start);
	return NULL;
}
