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

#include <stdio.h>
#include <assert.h>

#include "pfcp_assoc.h"
#include "gtp_stddef.h"
#include "jhash.h"
#include "bitops.h"
#include "addr.h"
#include "utils.h"
#include "memory.h"
#include "timer.h"
#include "inet_utils.h"
#include "pfcp_ie.h"


/* Local data */
static struct hlist_head *pfcp_assoc_tab;


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
		hkey = jhash_1word(node_id->ipv4.s_addr, 0);
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		hkey = addr_hash_in6_addr(&node_id->ipv6);
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		hkey = fnv1a_hash(node_id->fqdn,
				  strlen((char *)node_id->fqdn));
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
		if (__addr_ip4_equal(&a->ipv4, &b->ipv4))
			return 0;
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		if (__addr_ip6_equal(&a->ipv6, &b->ipv6))
			return 0;
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		if (strlen((char *)a->fqdn) != strlen((char *)b->fqdn))
			return -1;
		if (!memcmp(a->fqdn, b->fqdn, strlen((char *)a->fqdn)))
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

struct pfcp_assoc *
pfcp_assoc_get_by_ie(struct pfcp_ie_node_id *ie)
{
	struct pfcp_node_id n;

	if (!ie)
		return NULL;

	n.type = ie->node_id_type;
	switch (ie->node_id_type) {
	case PFCP_NODE_ID_TYPE_IPV4:
		n.ipv4 = ie->value.ipv4;
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		n.ipv4 = ie->value.ipv4;
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		memcpy2str((char *)n.fqdn, GTP_NAME_MAX_LEN,
			   ie->value.fqdn, ntohs(ie->h.length) - 1);
		break;

	default:
		return NULL;
	};

	return pfcp_assoc_get_by_node_id(&n);
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

static int
pfcp_assoc_dump(struct pfcp_assoc *c, char *buf, size_t bsize)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct tm *t = &c->creation_time;
	int k = 0;
	char *b;

	switch (c->node_id.type) {
	case PFCP_NODE_ID_TYPE_IPV4:
		snprintf(addr_str, INET6_ADDRSTRLEN, "%u.%u.%u.%u",
			 NIPQUAD(c->node_id.ipv4.s_addr));
		k += scnprintf(buf + k, bsize - k, "pfcp-association(%s):\n",
			       addr_str);
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		b = addr_stringify_in6_addr(&c->node_id.ipv6, addr_str,
					    INET6_ADDRSTRLEN);
		k += scnprintf(buf + k, bsize - k, "pfcp-association(%s):\n",
			       (b) ? : "!!!invalid_ipv6!!!");
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		k += scnprintf(buf + k, bsize - k, "pfcp-association(%s):\n",
			       c->node_id.fqdn);
		break;

	default:
		return -1;
	}

	k += scnprintf(buf + k, bsize - k, " recovery_ts:0x%.4x"
					   " creation:%.2d/%.2d/%.2d-%.2d:%.2d:%.2d\n",
		       ntohl(c->recovery_ts),
		       t->tm_mday, t->tm_mon+1, t->tm_year+1900,
		       t->tm_hour, t->tm_min, t->tm_sec);
	return k;
}


int
pfcp_assoc_vty(struct vty *vty, struct pfcp_node_id *node_id)
{
	struct hlist_node *n;
	struct pfcp_assoc *a;
	char buf[4096];
	int i;

	if (node_id) {
		a = pfcp_assoc_get_by_node_id(node_id);
		if (!a)
			return -1;

		pfcp_assoc_dump(a, buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		pfcp_assoc_put(a);
		return 0;
	}

	/* Iterate */
	for (i = 0; i < ASSOC_HASHTAB_SIZE; i++) {
		hlist_for_each_entry(a, n, &pfcp_assoc_tab[i], hlist) {
			pfcp_assoc_get(a);
			pfcp_assoc_dump(a, buf, sizeof(buf));
			vty_out(vty, "%s", buf);
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
	time_now_to_calendar(&new->creation_time);
	new->recovery_ts = ts->ts;
	new->node_id.type = node_id->node_id_type;

	switch (node_id->node_id_type) {
	case PFCP_NODE_ID_TYPE_IPV4:
		new->node_id.ipv4 = node_id->value.ipv4;
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		new->node_id.ipv6 = node_id->value.ipv6;
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		memcpy2str((char *)new->node_id.fqdn, GTP_NAME_MAX_LEN,
			   node_id->value.fqdn, ntohs(node_id->h.length) - 1);
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
