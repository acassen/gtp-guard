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
#include "rbtree_api.h"
#include "pfcp.h"
#include "pkt_buffer.h"

/*
 *	PFCP Message indexation
 */
typedef struct pfcp_msg_ie {
	pfcp_ie_t		*h;
	void const		*data;

	rb_node_t		n;
} pfcp_msg_ie_t;

typedef struct pfcp_msg {
	pfcp_hdr_t		*h;

	rb_root_cached_t	ie;
} pfcp_msg_t;


/* Prototypes */
size_t pfcp_msg_hlen(pfcp_hdr_t *h);
void pfcp_msg_ie_dump(const char *prefix, const pfcp_msg_ie_t *msg_ie);
pfcp_msg_ie_t *pfcp_msg_ie_get(pfcp_msg_t *msg, uint16_t type);
pfcp_msg_t *pfcp_msg_alloc(const pkt_buffer_t *pbuff);
void pfcp_msg_destroy(pfcp_msg_t *msg);
void pfcp_msg_dump(const char *prefix, pfcp_msg_t *msg);
