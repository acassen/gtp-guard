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

/* local includes */
#include "gtp_guard.h"


size_t
gtp_msg_hlen(gtp_hdr_t *h)
{
	size_t len = GTPV2C_HEADER_LEN;

	if (!h->teid_presence)
		len -= GTP_TEID_LEN;

	return len;
}

static inline bool
gtp_msg_ie_less(rb_node_t *a, const rb_node_t *b)
{
	const gtp_msg_ie_t *r1 = rb_entry_const(a, gtp_msg_ie_t, n);
	const gtp_msg_ie_t *r2 = rb_entry_const(b, gtp_msg_ie_t, n);

	return r1->h->type < r2->h->type;
}

static gtp_msg_ie_t *
gtp_msg_ie_alloc(const uint8_t *buffer, rb_root_cached_t *rbroot)
{
	gtp_msg_ie_t *msg_ie;

	PMALLOC(msg_ie);
	if (!msg_ie)
		return NULL;
	msg_ie->h = (gtp_ie_t *) buffer;
	msg_ie->data = buffer + sizeof(gtp_ie_t);
	rb_add_cached(&msg_ie->n, rbroot, gtp_msg_ie_less);

	return msg_ie;
}

void
gtp_msg_ie_destroy(gtp_msg_ie_t *msg_ie)
{
	FREE(msg_ie);
}

void
gtp_msg_ie_dump(const char *prefix, const gtp_msg_ie_t *msg_ie)
{
	printf("%sIE Type : %d\n", prefix, msg_ie->h->type);
	dump_buffer(prefix, (char *) msg_ie->data, ntohs(msg_ie->h->length));
}


static int
gtp_msg_ie_cmp(const void *type, const struct rb_node *a)
{
	return less_equal_greater_than(*((uint8_t *) type), rb_entry_const(a, gtp_msg_ie_t, n)->h->type);
}

gtp_msg_ie_t *
gtp_msg_ie_get(gtp_msg_t *msg, uint8_t type)
{
	rb_root_cached_t *root = &msg->ie;
	rb_node_t *node;

	node = rb_find(&type, &root->rb_root, gtp_msg_ie_cmp);
	return (node) ? rb_entry(node, gtp_msg_ie_t, n) : NULL;
}

gtp_msg_t *
gtp_msg_alloc(const pkt_buffer_t *pbuff)
{
	const uint8_t *cp;
	size_t offset;
	gtp_msg_t *msg;
	gtp_ie_t *ie;

	PMALLOC(msg);
	if (!msg)
		return NULL;
	msg->h = (gtp_hdr_t *) pbuff->head;
	msg->ie = RB_ROOT_CACHED;
	offset = gtp_msg_hlen(msg->h);

	for (cp = pbuff->head + offset; cp < pbuff->end; cp += offset) {
		ie = (gtp_ie_t *) cp;
		offset = sizeof(gtp_ie_t) + ntohs(ie->length);

		/* if not the case length is bogus ?! */
		if (cp + offset > pbuff->end)
			continue;

		gtp_msg_ie_alloc(cp, &msg->ie);
	}

	return msg;
}

void
gtp_msg_destroy(gtp_msg_t *msg)
{
	gtp_msg_ie_t *msg_ie, *_msg_ie;
	rb_root_cached_t *root = (msg) ? &msg->ie : NULL;

	if (!msg)
		return;

	rb_for_each_entry_safe_cached(msg_ie, _msg_ie, root, n) {
		rb_erase_cached(&msg_ie->n, root);
		gtp_msg_ie_destroy(msg_ie);
	}
	FREE(msg);
}

void
gtp_msg_dump(const char *prefix, gtp_msg_t *msg)
{
	gtp_hdr_t *h = msg->h;
	gtp_msg_ie_t *msg_ie;

	printf("%sGPRS Tunneling Protocol V2\n", prefix);
	printf("%sFlags : 0x%.x\n", prefix, h->flags);
	rb_for_each_entry_cached(msg_ie, &msg->ie, n)
		gtp_msg_ie_dump(prefix, msg_ie);
}
