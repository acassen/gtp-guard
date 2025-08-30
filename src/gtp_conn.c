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

#include "gtp_conn.h"
#include "gtp_session.h"
#include "jhash.h"
#include "bitops.h"
#include "memory.h"


/* Local data */
struct hlist_head *gtp_conn_tab;


/*
 *	Connection tracking (IMSI)
 */
static int gtp_conn_count = 0;

int
gtp_conn_count_read(void)
{
	return gtp_conn_count;
}


/*
 *      Refcounting
 */
int
gtp_conn_get(gtp_conn_t *c)
{
	if (!c)
		return 0;
	__sync_add_and_fetch(&c->refcnt, 1);
	return 0;
}

int
gtp_conn_put(gtp_conn_t *c)
{
	if (!c)
		return 0;
	__sync_sub_and_fetch(&c->refcnt, 1);
	return 0;
}


/*
 *	IMSI Hashtab handling
 */
static struct hlist_head *
gtp_conn_hashkey(uint64_t id)
{
	return gtp_conn_tab + (jhash_2words((uint32_t)id, (uint32_t) (id >> 32), 0) & CONN_HASHTAB_MASK);
}

gtp_conn_t *
gtp_conn_get_by_imsi(uint64_t imsi)
{
	struct hlist_head *head = gtp_conn_hashkey(imsi);
	struct hlist_node *n;
	gtp_conn_t *c;

	hlist_for_each_entry(c, n, head, hlist) {
		if (c->imsi == imsi) {
			__sync_add_and_fetch(&c->refcnt, 1);
			return c;
		}
	}

	return NULL;
}

int
gtp_conn_hash(gtp_conn_t *c)
{
	struct hlist_head *head;

	if (!c)
		return -1;

	head = gtp_conn_hashkey(c->imsi);
	hlist_add_head(&c->hlist, head);
	__set_bit(GTP_CONN_F_HASHED, &c->flags);
	__sync_add_and_fetch(&gtp_conn_count, 1);
	__sync_add_and_fetch(&c->refcnt, 1);
	return 0;
}

int
gtp_conn_unhash(gtp_conn_t *c)
{
	if (!c)
		return -1;

	hlist_del(&c->hlist);
	__clear_bit(GTP_CONN_F_HASHED, &c->flags);
	__sync_sub_and_fetch(&gtp_conn_count, 1);
	__sync_sub_and_fetch(&c->refcnt, 1);
	return 0;
}

int
gtp_conn_vty(vty_t *vty, int (*vty_conn) (vty_t *, gtp_conn_t *), uint64_t imsi)
{
	struct hlist_node *n;
	gtp_conn_t *c;
	int i;

	if (imsi) {
		c = gtp_conn_get_by_imsi(imsi);
		if (!c)
			return -1;

		(*vty_conn) (vty, c);
		gtp_conn_put(c);
		return 0;
	}

	/* Iterate */
	for (i = 0; i < CONN_HASHTAB_SIZE; i++) {
		hlist_for_each_entry(c, n, &gtp_conn_tab[i], hlist) {
			gtp_conn_get(c);
			(*vty_conn) (vty, c);
			gtp_conn_put(c);
		}
	}

	return 0;
}

/*
 *	Connection related
 */
gtp_conn_t *
gtp_conn_alloc(uint64_t imsi)
{
	gtp_conn_t *new;

	PMALLOC(new);
	new->imsi = imsi;
	new->ts = time(NULL);
	INIT_LIST_HEAD(&new->gtp_sessions);
	INIT_LIST_HEAD(&new->pppoe_sessions);

	gtp_conn_hash(new);

	return new;
}


/*
 *	Connection tracking init
 */
int
gtp_conn_init(void)
{
	gtp_conn_tab = (struct hlist_head *) MALLOC(sizeof(struct hlist_head) *
						    CONN_HASHTAB_SIZE);
	return 0;
}

int
gtp_conn_destroy(void)
{
	struct hlist_node *n, *n2;
	gtp_conn_t *c;
	int i;

	for (i = 0; i < CONN_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(c, n, n2, &gtp_conn_tab[i], hlist) {
			gtp_sessions_free(c);
			FREE(c);
		}
	}

	FREE(gtp_conn_tab);
	return 0;
}
