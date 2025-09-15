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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "pfcp_msg.h"
#include "rbtree_api.h"
#include "memory.h"
#include "pfcp.h"
#include "utils.h"


/*
 * PFCP msg are built with stacked ie. We are using a RBTREE
 * for indexing since IE can, and are, unordered based on
 * IE type. This index is only here to prevent o(n) search since
 * IE for the same msg can be accessed multiple time during
 * protocol msg handling. So o(log n) sounds better here even
 * if it comes with a little memory overhead to do so.
 */
size_t
pfcp_msg_hlen(struct pfcp_hdr *h)
{
	size_t len = PFCP_HEADER_LEN;

	if (!h->s)
		len -= PFCP_SEID_LEN;

	return len;
}

static int
pfcp_msg_ie_cmp(const void *type, const struct rb_node *a)
{
	return less_equal_greater_than(ntohs(*((uint16_t *) type)),
				       ntohs(rb_entry_const(a, struct pfcp_msg_ie, n)->h->type));
}

struct pfcp_msg_ie *
pfcp_msg_ie_get(struct pfcp_msg *msg, uint16_t type)
{
	struct rb_root_cached *root = &msg->ie;
	uint16_t t = htons(type);
	struct rb_node *node;

	node = rb_find(&t, &root->rb_root, pfcp_msg_ie_cmp);
	return (node) ? rb_entry(node, struct pfcp_msg_ie, n) : NULL;
}

static inline bool
pfcp_msg_ie_less(struct rb_node *a, const struct rb_node *b)
{
	const struct pfcp_msg_ie *r1 = rb_entry_const(a, struct pfcp_msg_ie, n);
	const struct pfcp_msg_ie *r2 = rb_entry_const(b, struct pfcp_msg_ie, n);

	return ntohs(r1->h->type) < ntohs(r2->h->type);
}

static struct pfcp_msg_ie *
pfcp_msg_ie_alloc(const uint8_t *buffer, struct rb_root_cached *rbroot)
{
	struct pfcp_msg_ie *msg_ie;

	PMALLOC(msg_ie);
	if (!msg_ie)
		return NULL;
	msg_ie->h = (struct pfcp_ie *) buffer;
	msg_ie->data = buffer + sizeof(struct pfcp_ie);
	rb_add_cached(&msg_ie->n, rbroot, pfcp_msg_ie_less);

	return msg_ie;
}

void
pfcp_msg_ie_destroy(struct pfcp_msg_ie *msg_ie)
{
	FREE(msg_ie);
}

void
pfcp_msg_ie_dump(const char *prefix, const struct pfcp_msg_ie *msg_ie)
{
	printf("%sIE Type : %d\n", prefix, ntohs(msg_ie->h->type));
	dump_buffer(prefix, (char *) msg_ie->data, ntohs(msg_ie->h->length));
}


struct pfcp_msg *
pfcp_msg_alloc(const struct pkt_buffer *pbuff)
{
	const uint8_t *cp;
	size_t offset;
	struct pfcp_msg *msg;
	struct pfcp_ie *ie;

	PMALLOC(msg);
	if (!msg)
		return NULL;
	msg->h = (struct pfcp_hdr *) pbuff->head;
	msg->ie = RB_ROOT_CACHED;
	offset = pfcp_msg_hlen(msg->h);

	for (cp = pbuff->head + offset; cp < pbuff->end; cp += offset) {
		ie = (struct pfcp_ie *) cp;
		offset = sizeof(struct pfcp_ie) + ntohs(ie->length);

		/* if not the case length is bogus ?! */
		if (cp + offset > pbuff->end)
			continue;

		pfcp_msg_ie_alloc(cp, &msg->ie);
	}

	return msg;
}

void
pfcp_msg_destroy(struct pfcp_msg *msg)
{
	struct pfcp_msg_ie *msg_ie, *_msg_ie;
	struct rb_root_cached *root = (msg) ? &msg->ie : NULL;

	if (!msg)
		return;

	rb_for_each_entry_safe_cached(msg_ie, _msg_ie, root, n) {
		rb_erase_cached(&msg_ie->n, root);
		pfcp_msg_ie_destroy(msg_ie);
	}
	FREE(msg);
}

void
pfcp_msg_dump(const char *prefix, struct pfcp_msg *msg)
{
	struct pfcp_hdr *h = msg->h;
	struct pfcp_msg_ie *msg_ie;

	printf("%sPacket Forwarding Control Protocol\n", prefix);
	printf("%sFlags : 0x%.x\n", prefix, h->flags);
	rb_for_each_entry_cached(msg_ie, &msg->ie, n)
		pfcp_msg_ie_dump(prefix, msg_ie);
}
