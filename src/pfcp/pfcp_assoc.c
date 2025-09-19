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

#include <assert.h>

#include "pfcp_assoc.h"
#include "jhash.h"
#include "bitops.h"
#include "addr.h"
#include "utils.h"
#include "memory.h"
#include "pfcp_ie.h"


/* Local data */
struct hlist_head *pfcp_assoc_tab;


/*
 *	Association Connection tracking
 */
static int pfcp_assoc_count = 0;

int
pfcp_assoc_count_read(void)
{
	return pfcp_assoc_count;
}


/*
 *      Refcounting
 */
int
pfcp_assoc_get(struct pfcp_assoc *c)
{
	if (!c)
		return 0;
	__sync_add_and_fetch(&c->refcnt, 1);
	return 0;
}

int
pfcp_assoc_put(struct pfcp_assoc *c)
{
	if (!c)
		return 0;
	__sync_sub_and_fetch(&c->refcnt, 1);
	return 0;
}


/*
 *	Hashtab handling
 */
static struct hlist_head *
pfcp_assoc_hashkey(struct pfcp_node_id *node_id)
{
	uint32_t hkey;

	switch (node_id->type) {
	case PFCP_NODE_ID_TYPE_IPV4:
		hkey = jhash_1word(node_id->id.ipv4.s_addr, 0);
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		hkey = addr_hash_in6_addr(&node_id->id.ipv6);
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		hkey = fnv1a_hash(node_id->id.fqdn,
		    		  strlen((char *)node_id->id.fqdn));
		break;

	default:
		return 0;
	};

	return pfcp_assoc_tab + (hkey & ASSOC_HASHTAB_MASK);
}

static int
pfcp_assoc_cmp(struct pfcp_node_id *a, struct pfcp_node_id *b)
{
	if (a->type != b->type)
		return -1;

	switch (a->type) {
	case PFCP_NODE_ID_TYPE_IPV4:
		if (__addr_ip4_equal(&a->id.ipv4, &b->id.ipv4))
			return 0;
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		if (__addr_ip6_equal(&a->id.ipv6, &b->id.ipv6))
			return 0;
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		if (strlen((char *)a->id.fqdn) != strlen((char *)b->id.fqdn))
			return -1;
		if (!memcmp(a->id.fqdn, b->id.fqdn, strlen((char *)a->id.fqdn)))
			return 0;
		break;

	default:
		return -1;
	};

	return -1;
}

struct pfcp_assoc *
pfcp_assoc_get_by_node_id(struct pfcp_node_id *node_id)
{
	struct hlist_head *head = pfcp_assoc_hashkey(node_id);
	struct hlist_node *n;
	struct pfcp_assoc *a;

	hlist_for_each_entry(a, n, head, hlist) {
		if (!pfcp_assoc_cmp(&a->node_id, node_id)) {
			__sync_add_and_fetch(&a->refcnt, 1);
			return a;
		}
	}

	return NULL;
}

int
pfcp_assoc_hash(struct pfcp_assoc *c)
{
	struct hlist_head *head;

	if (!c)
		return -1;

	head = pfcp_assoc_hashkey(&c->node_id);
	hlist_add_head(&c->hlist, head);
	__set_bit(PFCP_ASSOC_F_HASHED, &c->flags);
	__sync_add_and_fetch(&pfcp_assoc_count, 1);
	__sync_add_and_fetch(&c->refcnt, 1);
	return 0;
}

int
pfcp_assoc_unhash(struct pfcp_assoc *c)
{
	if (!c)
		return -1;

	hlist_del(&c->hlist);
	__clear_bit(PFCP_ASSOC_F_HASHED, &c->flags);
	__sync_sub_and_fetch(&pfcp_assoc_count, 1);
	__sync_sub_and_fetch(&c->refcnt, 1);
	return 0;
}

int
pfcp_assoc_vty(struct vty *vty, int (*vty_assoc) (struct vty *, struct pfcp_assoc *),
	       struct pfcp_node_id *node_id)
{
	struct hlist_node *n;
	struct pfcp_assoc *a;
	int i;

	if (node_id) {
		a = pfcp_assoc_get_by_node_id(node_id);
		if (!a)
			return -1;

		(*vty_assoc) (vty, a);
		pfcp_assoc_put(a);
		return 0;
	}

	/* Iterate */
	for (i = 0; i < ASSOC_HASHTAB_SIZE; i++) {
		hlist_for_each_entry(a, n, &pfcp_assoc_tab[i], hlist) {
			pfcp_assoc_get(a);
			(*vty_assoc) (vty, a);
			pfcp_assoc_put(a);
		}
	}

	return 0;
}

/*
 *	Connection related
 */
struct pfcp_assoc *
pfcp_assoc_alloc(struct pfcp_ie_node_id *node_id,
		 struct pfcp_ie_recovery_time_stamp *ts)
{
	struct pfcp_assoc *new;

	PMALLOC(new);
	assert(new != NULL);
	new->recovery_ts = ts->recovery_time_stamp;

	switch (node_id->node_id_type) {
	case PFCP_NODE_ID_TYPE_IPV4:
		new->node_id.id.ipv4 = node_id->value.ipv4;
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		new->node_id.id.ipv6 = node_id->value.ipv6;
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		/* node_id_type count as '\0' */
		new->node_id.id.fqdn = MALLOC(ntohs(node_id->h.length));
		memcpy(new->node_id.id.fqdn, node_id->value.fqdn,
	 	       ntohs(node_id->h.length) - 1);
		break;

	default:
		FREE(new);
		return NULL;
	};

	pfcp_assoc_hash(new);

	return new;
}


/*
 *	Association tracking init
 */
int
pfcp_assoc_init(void)
{
	pfcp_assoc_tab = (struct hlist_head *) MALLOC(sizeof(struct hlist_head) *
					 	      ASSOC_HASHTAB_SIZE);
	return 0;
}

int
pfcp_assoc_destroy(void)
{
	struct hlist_node *n, *n2;
	struct pfcp_assoc *a;
	int i;

	for (i = 0; i < ASSOC_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(a, n, n2, &pfcp_assoc_tab[i], hlist) {
			FREE(a);
		}
	}

	FREE(pfcp_assoc_tab);
	return 0;
}
