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
#include <arpa/inet.h>

#include "gtp_msg.h"
#include "rbtree_api.h"
#include "memory.h"
#include "utils.h"

size_t
gtp_msg_hlen(struct gtp_hdr *h)
{
	size_t len = GTPV2C_HEADER_LEN;

	if (!h->teid_presence)
		len -= GTP_TEID_LEN;

	return len;
}

static int
gtp_msg_ie_cmp(const void *type, const struct rb_node *a)
{
	return less_equal_greater_than(*((uint8_t *) type),
				       rb_entry_const(a, struct gtp_msg_ie, n)->h->type);
}

struct gtp_msg_ie *
gtp_msg_ie_get(struct gtp_msg *msg, uint8_t type)
{
	struct rb_root_cached *root = &msg->ie;
	struct rb_node *node;

	node = rb_find(&type, &root->rb_root, gtp_msg_ie_cmp);
	return (node) ? rb_entry(node, struct gtp_msg_ie, n) : NULL;
}

static inline bool
gtp_msg_ie_less(struct rb_node *a, const struct rb_node *b)
{
	const struct gtp_msg_ie *r1 = rb_entry_const(a, struct gtp_msg_ie, n);
	const struct gtp_msg_ie *r2 = rb_entry_const(b, struct gtp_msg_ie, n);

	return r1->h->type < r2->h->type;
}

static struct gtp_msg_ie *
gtp_msg_ie_alloc(const uint8_t *buffer, struct rb_root_cached *rbroot)
{
	struct gtp_msg_ie *msg_ie;

	PMALLOC(msg_ie);
	if (!msg_ie)
		return NULL;
	msg_ie->h = (struct gtp_ie *) buffer;
	msg_ie->data = buffer + sizeof(struct gtp_ie);
	rb_add_cached(&msg_ie->n, rbroot, gtp_msg_ie_less);

	return msg_ie;
}

void
gtp_msg_ie_destroy(struct gtp_msg_ie *msg_ie)
{
	FREE(msg_ie);
}

void
gtp_msg_ie_dump(const char *prefix, const struct gtp_msg_ie *msg_ie)
{
	printf("%sIE Type : %d\n", prefix, msg_ie->h->type);
	hexdump(prefix, msg_ie->data, ntohs(msg_ie->h->length));
}


struct gtp_msg *
gtp_msg_alloc(const struct pkt_buffer *pbuff)
{
	const uint8_t *cp;
	size_t offset;
	struct gtp_msg *msg;
	struct gtp_ie *ie;

	PMALLOC(msg);
	if (!msg)
		return NULL;
	msg->h = (struct gtp_hdr *) pbuff->head;
	msg->ie = RB_ROOT_CACHED;
	offset = gtp_msg_hlen(msg->h);

	for (cp = pbuff->head + offset; cp < pbuff->end; cp += offset) {
		ie = (struct gtp_ie *) cp;
		offset = sizeof(struct gtp_ie) + ntohs(ie->length);

		/* if not the case length is bogus ?! */
		if (cp + offset > pbuff->end)
			continue;

		gtp_msg_ie_alloc(cp, &msg->ie);
	}

	return msg;
}

void
gtp_msg_destroy(struct gtp_msg *msg)
{
	struct gtp_msg_ie *msg_ie, *_msg_ie;
	struct rb_root_cached *root = (msg) ? &msg->ie : NULL;

	if (!msg)
		return;

	rb_for_each_entry_safe_cached(msg_ie, _msg_ie, root, n) {
		rb_erase_cached(&msg_ie->n, root);
		gtp_msg_ie_destroy(msg_ie);
	}
	FREE(msg);
}

void
gtp_msg_dump(const char *prefix, struct gtp_msg *msg)
{
	struct gtp_hdr *h = msg->h;
	struct gtp_msg_ie *msg_ie;

	printf("%sGPRS Tunneling Protocol V2\n", prefix);
	printf("%sFlags : 0x%.x\n", prefix, h->flags);
	rb_for_each_entry_cached(msg_ie, &msg->ie, n)
		gtp_msg_ie_dump(prefix, msg_ie);
}
