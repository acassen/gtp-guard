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
 *              Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#pragma once

#include <stdint.h>
#include "gtp_stddef.h"
#include "list_head.h"

/* default protocol timeout values */
#define CGN_PROTO_TIMEOUT_TCP_EST	600
#define CGN_PROTO_TIMEOUT_TCP_SYNFIN	120
#define CGN_PROTO_TIMEOUT_UDP		120
#define CGN_PROTO_TIMEOUT_ICMP		120

/* timeout are in seconds */
struct port_timeout_config
{
	uint16_t udp;
	uint16_t tcp_synfin;
	uint16_t tcp_est;
};

enum cgn_flags {
	CGN_FL_SHUTDOWN_BIT,
};

struct cgn_ctx
{
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	unsigned long		flags;
	struct list_head	next;

	/* conf */
	uint32_t		*cgn_addr;	/* array of size 'cgn_addr_n' */
	uint32_t		cgn_addr_n;
	uint16_t		port_start;
	uint16_t		port_end;
	uint16_t		block_size;	/* # of port per block */
	uint16_t		block_count;	/* # of block per ip */
	struct port_timeout_config timeout;
	struct port_timeout_config timeout_by_port[0x10000];
	uint16_t		timeout_icmp;

	/* metrics */
};

/* Prototypes */
int cgn_ctx_compact_cgn_addr(struct cgn_ctx *c, uint64_t *out);
int cgn_ctx_dump(struct cgn_ctx *c, char *b, size_t s);
struct cgn_ctx *cgn_ctx_get_by_name(const char *name);
void cgn_ctx_release(struct cgn_ctx *c);
struct cgn_ctx *cgn_ctx_alloc(const char *name);
int cgn_init(void);
int cgn_destroy(void);

