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
#include <netinet/in.h>
#include "pfcp_ie.h"
#include "list_head.h"
#include "vty.h"

/* Hash table */
#define ASSOC_HASHTAB_BITS  10
#define ASSOC_HASHTAB_SIZE  (1 << ASSOC_HASHTAB_BITS)
#define ASSOC_HASHTAB_MASK  (ASSOC_HASHTAB_SIZE - 1)

/* Connection flags */
enum conn_flags {
	PFCP_ASSOC_F_HASHED,
	PFCP_ASSOC_F_DEBUG,
};

struct pfcp_node_id {
	uint8_t	type;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		uint8_t *fqdn;
	};
};

struct pfcp_assoc {
	struct pfcp_node_id	node_id;

	time_t			recovery_ts;

	/* hash stuff */
        struct hlist_node       hlist;

	unsigned long		flags;
	int			refcnt;
};


/* Prototypes */
int pfcp_assoc_count_read(void);
int pfcp_assoc_get(struct pfcp_assoc *);
int pfcp_assoc_put(struct pfcp_assoc *);
struct pfcp_assoc *pfcp_assoc_alloc(struct pfcp_ie_node_id *node_id,
				    struct pfcp_ie_recovery_time_stamp *ts);
struct pfcp_assoc *pfcp_assoc_get_by_imsi(uint64_t);
int pfcp_assoc_hash(struct pfcp_assoc *);
int pfcp_assoc_unhash(struct pfcp_assoc *);
int pfcp_assoc_vty(struct vty *vty, int (*vty_assoc) (struct vty *, struct pfcp_assoc *),
		   struct pfcp_node_id *node_id);
int pfcp_assoc_init(void);
int pfcp_assoc_destroy(void);
