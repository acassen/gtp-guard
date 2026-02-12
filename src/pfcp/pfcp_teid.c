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

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#include "pfcp_teid.h"
#include "jhash.h"
#include "bitops.h"
#include "addr.h"
#include "utils.h"
#include "vty.h"
#include "table.h"



/*
 *	TEID tracking
 */
static int pfcp_teid_count = 0;

int
pfcp_teid_count_read(void)
{
	return pfcp_teid_count;
}


/*
 *	Hashtab handling
 */
static struct hlist_head *
pfcp_teid_hashkey(struct hlist_head *h, uint32_t id, struct in_addr *ipv4,
		  struct in6_addr *ipv6)
{
	uint32_t hkey = jhash_3words(id, (ipv4) ? ipv4->s_addr : 0
				       , (ipv6) ? addr_hash_in6_addr(ipv6) : 0
				       , 0);
	return h + (hkey & TEID_HASHTAB_MASK);
}

static int
pfcp_teid_cmp(struct pfcp_teid *a, uint32_t id, struct in_addr *ipv4,
	      struct in6_addr *ipv6)
{
	int ip4_cmp = (ipv4) ? 1 : 0, ip6_cmp = (ipv6) ? 1 : 0;

	if (a->id != id)
		return -1;

	if (__test_bit(PFCP_TEID_F_IPV4, &a->flags))
		ip4_cmp++;
	if (ip4_cmp && ip4_cmp != 2)
		return -1;

	if (__test_bit(PFCP_TEID_F_IPV6, &a->flags))
		ip6_cmp++;
	if (ip6_cmp && ip6_cmp != 2)
		return -1;

	if (ip4_cmp && !__addr_ip4_equal(&a->ipv4, ipv4))
		return -1;

	if (ip6_cmp && !__addr_ip6_equal(&a->ipv6, ipv6))
		return -1;

	return 0;
}

struct pfcp_teid *
pfcp_teid_get(struct hlist_head *h, uint32_t id, struct in_addr *ipv4,
	      struct in6_addr *ipv6)
{
	struct hlist_head *head = pfcp_teid_hashkey(h, id, ipv4, ipv6);
	struct pfcp_teid *t;

	hlist_for_each_entry(t, head, hlist) {
		if (!pfcp_teid_cmp(t, id, ipv4, ipv6)) {
			return t;
		}
	}

	return NULL;
}

struct pfcp_teid *
pfcp_teid_get_by_ie_f_teid(struct hlist_head *h, struct pfcp_ie_f_teid *ie)
{
	struct hlist_head *head;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	struct pfcp_teid *t;
	uint32_t id;

	id = ntohl(ie->s.teid);
	if (ie->v4)
		ipv4 = ie->s.ip.v4;
	if (ie->v6)
		ipv6 = ie->s.ip.v6;
	head = pfcp_teid_hashkey(h, id, (ie->v4) ? &ipv4 : NULL,
				 (ie->v4) ? &ipv6 : NULL);

	hlist_for_each_entry(t, head, hlist) {
		if (!pfcp_teid_cmp(t, id, (ie->v4) ? &ipv4 : NULL,
				   (ie->v4) ? &ipv6 : NULL)) {
			return t;
		}
	}

	return NULL;
}



int
pfcp_teid_hash(struct hlist_head *h, struct pfcp_teid *t)
{
	struct hlist_head *head;
	struct in_addr *ipv4;
	struct in6_addr *ipv6;

	if (!t)
		return -1;

	ipv4 = __test_bit(PFCP_TEID_F_IPV4, &t->flags) ? &t->ipv4 : NULL;
	ipv6 = __test_bit(PFCP_TEID_F_IPV6, &t->flags) ? &t->ipv6 : NULL;

	head = pfcp_teid_hashkey(h, t->id, ipv4, ipv6);
	hlist_add_head(&t->hlist, head);
	__set_bit(PFCP_TEID_F_HASHED, &t->flags);
	__sync_add_and_fetch(&pfcp_teid_count, 1);
	return 0;
}

int
pfcp_teid_unhash(struct pfcp_teid *t)
{
	if (!t)
		return -1;

	hlist_del(&t->hlist);
	__clear_bit(PFCP_TEID_F_HASHED, &t->flags);
	__sync_sub_and_fetch(&pfcp_teid_count, 1);
	return 0;
}

int
pfcp_teid_dump(struct pfcp_teid *t, char *buf, size_t bsize)
{
	char addr_str[INET6_ADDRSTRLEN];
	int k = 0;

	k += scnprintf(buf + k, bsize - k, "F-TEID(%s): {ID:0x%.8x",
		       __test_bit(PFCP_TEID_F_INGRESS, &t->flags) ? "ingress" : "egress",
		       t->id);

	if (__test_bit(PFCP_TEID_F_IPV4, &t->flags)) {
		if (!inet_ntop(AF_INET, &t->ipv4, addr_str, INET6_ADDRSTRLEN))
			k += scnprintf(buf + k, bsize - k, ", IPv4:!!!invalid_ipv4!!!");
		else
			k += scnprintf(buf + k, bsize - k, ", IPv4:%s", addr_str);
	}

	if (__test_bit(PFCP_TEID_F_IPV6, &t->flags)) {
		if (!inet_ntop(AF_INET6, &t->ipv6, addr_str, INET6_ADDRSTRLEN))
			k += scnprintf(buf + k, bsize - k, ", IPv6:!!!invalid_ipv6!!!");
		else
			k += scnprintf(buf + k, bsize - k, ", IPv6:%s", addr_str);
	}

	k += scnprintf(buf + k, bsize - k, "}\n");

	k += scnprintf(buf + k, bsize - k, " Packets:%ld Bytes:%ld\n",
		       t->metrics.count, t->metrics.bytes);
	return k;
}

static void
pfcp_teid_table_add(struct table *tbl, struct pfcp_teid *t)
{
	char addr4[INET6_ADDRSTRLEN];
	char addr6[INET6_ADDRSTRLEN];

	if (__test_bit(PFCP_TEID_F_IPV4, &t->flags)) {
		if (!inet_ntop(AF_INET, &t->ipv4, addr4, INET6_ADDRSTRLEN))
			snprintf(addr4, INET6_ADDRSTRLEN, "!!!invalid_ipv4!!!");
	}

	if (__test_bit(PFCP_TEID_F_IPV6, &t->flags)) {
		if (!inet_ntop(AF_INET6, &t->ipv6, addr6, INET6_ADDRSTRLEN))
			snprintf(addr6, INET6_ADDRSTRLEN, "!!!invalid_ipv6!!!");
	}

	table_add_row_fmt(tbl, "0x%.8x|%s|%s|%s|%ld|%ld",
			  t->id,
			  __test_bit(PFCP_TEID_F_IPV4, &t->flags) ? addr4 : "none",
			  __test_bit(PFCP_TEID_F_IPV6, &t->flags) ? addr6 : "none",
			  __test_bit(PFCP_TEID_F_INGRESS, &t->flags) ? "ingress" : "egress",
			  t->metrics.count, t->metrics.bytes);
}

int
pfcp_teid_vty(struct vty *vty, struct hlist_head *h, uint32_t id, struct in_addr *ipv4,
	      struct in6_addr *ipv6)
{
	struct pfcp_teid *t;
	struct table *tbl;
	char buf[4096];
	int i;

	if (id) {
		t = pfcp_teid_get(h, id, ipv4, ipv6);
		if (!t)
			return -1;

		pfcp_teid_dump(t, buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		return 0;
	}

	/* Global display */
	tbl = table_init(6, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "TEID", "Endpoint IPv4 Address",
		  	 "Endpoint IPv6 Address",
			 "Direction", "Packets", "Bytes");
	table_set_header_align(tbl, ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
			       ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER);

	for (i = 0; i < TEID_HASHTAB_SIZE; i++) {
		hlist_for_each_entry(t, &h[i], hlist)
			pfcp_teid_table_add(tbl, t);
	}

	table_vty_out(tbl, vty);
	table_destroy(tbl);

	return 0;
}

/*
 *	teid related
 */
uint32_t
pfcp_teid_roll_the_dice(struct hlist_head *h, uint64_t *seed, struct in_addr *ipv4,
			struct in6_addr *ipv6)
{
	struct pfcp_teid *t;
	uint32_t id;
	int retry = 0;

shoot_again:
	/* roll the dice ! */
	id = (uint32_t) (xorshift_prng(seed) >> 32);
	t = pfcp_teid_get(h, id, ipv4, ipv6);
	if (t && retry++ < 5)
		goto shoot_again;

	/* Something went wrong in the casino... */
	if (t)
		return 0;

	return id;
}

static void
pfcp_teid_set(struct hlist_head *h, struct pfcp_teid *t, uint8_t interface,
	      uint32_t id, struct in_addr *ipv4, struct in6_addr *ipv6)
{
	t->id = id;
	t->interface = interface;
	if (ipv4) {
		__set_bit(PFCP_TEID_F_IPV4, &t->flags);
		t->ipv4 = *ipv4;
	}
	if (ipv6) {
		__set_bit(PFCP_TEID_F_IPV6, &t->flags);
		memcpy(&t->ipv6, ipv6, sizeof(struct in6_addr));
	}

	if (interface == PFCP_SRC_INTERFACE_TYPE_ACCESS)
		__set_bit(PFCP_TEID_F_EGRESS, &t->flags);
	else
		__set_bit(PFCP_TEID_F_INGRESS, &t->flags);

	pfcp_teid_hash(h, t);
}

struct pfcp_teid *
pfcp_teid_alloc(struct hlist_head *h, uint64_t *seed, uint8_t interface,
		uint32_t id, struct in_addr *ipv4, struct in6_addr *ipv6)
{
	struct pfcp_teid *new, *t;
	uint32_t new_id = id;

	t = pfcp_teid_get(h, id, ipv4, ipv6);
	if (t) {
		new_id = pfcp_teid_roll_the_dice(h, seed, ipv4, ipv6);
		if (!new_id)
			return NULL;
	}

	/* Sanitized id ready */
	new = calloc(1, sizeof(*new));
	if (!new)
		return NULL;
	pfcp_teid_set(h, new, interface, new_id, ipv4, ipv6);

	return new;
}

void
pfcp_teid_free(struct pfcp_teid *t)
{
	if (!t)
		return;

	pfcp_teid_unhash(t);
	free(t);
}

struct pfcp_teid *
pfcp_teid_restore(struct hlist_head *h, struct pfcp_ie_f_teid *ie)
{
	struct pfcp_teid *new, *t;

	t = pfcp_teid_get_by_ie_f_teid(h, ie);
	if (t)
		return NULL;

	new = calloc(1, sizeof(*new));
	if (!new)
		return NULL;
	new->id = ntohl(ie->s.teid);
	if (ie->v4) {
		__set_bit(PFCP_TEID_F_IPV4, &new->flags);
		new->ipv4 = ie->s.ip.v4;
	}
	if (ie->v6) {
		__set_bit(PFCP_TEID_F_IPV6, &new->flags);
		memcpy(&new->ipv6, &ie->s.ip.v6, sizeof(struct in6_addr));
	}

	pfcp_teid_hash(h, new);

	return new;
}

/*
 *	TEID tracking init
 */
struct hlist_head *
pfcp_teid_init(void)
{
	return calloc(TEID_HASHTAB_SIZE, sizeof(struct hlist_head));
}

int
pfcp_teid_destroy(struct hlist_head *h)
{
	struct hlist_node *n;
	struct pfcp_teid *t;
	int i;

	for (i = 0; i < TEID_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(t, n, &h[i], hlist) {
			free(t);
		}
	}

	free(h);
	return 0;
}
