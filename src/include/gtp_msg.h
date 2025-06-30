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

/*
 *	GTPv2 Message
 */
typedef struct _gtp_msg_ie {
	gtp_ie_t		*h;
	void const		*data;

	rb_node_t		n;
} gtp_msg_ie_t;

typedef struct _gtp_msg {
	gtp_hdr_t		*h;

	rb_root_cached_t	ie;
} gtp_msg_t;


/* Prototypes */
extern size_t gtp_msg_hlen(gtp_hdr_t *);
extern void gtp_msg_ie_dump(const char *, const gtp_msg_ie_t *);
extern gtp_msg_ie_t *gtp_msg_ie_get(gtp_msg_t *, uint8_t);
extern gtp_msg_t *gtp_msg_alloc(const pkt_buffer_t *);
extern void gtp_msg_destroy(gtp_msg_t *);
extern void gtp_msg_dump(const char *, gtp_msg_t *);
