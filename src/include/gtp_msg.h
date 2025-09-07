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
#include "gtp.h"
#include "pkt_buffer.h"

/*
 *	GTPv2 Message
 */
struct gtp_msg_ie {
	struct gtp_ie		*h;
	void const		*data;

	struct rb_node		n;
};

struct gtp_msg {
	struct gtp_hdr		*h;

	struct rb_root_cached	ie;
};


/* Prototypes */
size_t gtp_msg_hlen(struct gtp_hdr *);
void gtp_msg_ie_dump(const char *, const struct gtp_msg_ie *);
struct gtp_msg_ie *gtp_msg_ie_get(struct gtp_msg *, uint8_t);
struct gtp_msg *gtp_msg_alloc(const struct pkt_buffer *);
void gtp_msg_destroy(struct gtp_msg *);
void gtp_msg_dump(const char *, struct gtp_msg *);
