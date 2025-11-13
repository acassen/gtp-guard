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
#include "pfcp_metrics.h"
#include "pfcp_ie.h"
#include "list_head.h"

/* Hash table */
#define TEID_HASHTAB_BITS  20
#define TEID_HASHTAB_SIZE  (1 << TEID_HASHTAB_BITS)
#define TEID_HASHTAB_MASK  (TEID_HASHTAB_SIZE - 1)

/* F-TEID flags */
enum teid_flags {
	PFCP_TEID_F_HASHED,
	PFCP_TEID_F_IPV4,
	PFCP_TEID_F_IPV6,
	PFCP_TEID_F_INGRESS,
	PFCP_TEID_F_EGRESS,
	PFCP_TEID_F_DEBUG,
};

struct pfcp_teid {
	uint32_t		id;
	struct in_addr		ipv4;
	struct in6_addr		ipv6;
	struct pfcp_metrics_pkt	metrics;

	struct hlist_node	hlist;

	unsigned long		flags;
};


/* Prototypes */
int pfcp_teid_dump(struct pfcp_teid *t, char *buf, size_t bsize);
uint32_t pfcp_teid_roll_the_dice(struct hlist_head *h, uint64_t *seed,
				 struct in_addr *ipv4,
				 struct in6_addr *ipv6);
struct pfcp_teid *pfcp_teid_alloc(struct hlist_head *h, uint64_t *seed,
				  uint32_t id,
				  struct in_addr *ipv4,
				  struct in6_addr *ipv6);
struct pfcp_teid *pfcp_teid_restore(struct hlist_head *h,
				    struct pfcp_ie_f_teid *ie);
struct hlist_head *pfcp_teid_init(void);
int pfcp_teid_destroy(struct hlist_head *h);
