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
#pragma once

#include <stdint.h>
#include "rbtree_types.h"
#include "pfcp_ie.h"
#include "pkt_buffer.h"

/*
 *	PFCP Message indexation
 */
struct pfcp_msg_ie {
	struct pfcp_ie		*h;
	void const		*data;

	struct rb_node		n;
};

struct pfcp_msg {
	struct pfcp_hdr		*h;

	struct rb_root_cached	ie;
};


/* Prototypes */
size_t pfcp_msg_hlen(struct pfcp_hdr *h);
void pfcp_msg_ie_dump(const char *prefix, const struct pfcp_msg_ie *msg_ie);
struct pfcp_msg_ie *pfcp_msg_ie_get(struct pfcp_msg *msg, uint16_t type);
struct pfcp_msg *pfcp_msg_alloc(const struct pkt_buffer *pbuff);
void pfcp_msg_destroy(struct pfcp_msg *msg);
void pfcp_msg_dump(const char *prefix, struct pfcp_msg *msg);
