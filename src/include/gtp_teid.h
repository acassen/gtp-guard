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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include "list_head.h"
#include "gtp.h"

/* Tunnel type */
enum {
	GTP_TEID_C = 1,
	GTP_TEID_U,
};

/* flags */
enum gtp_teid_flags {
	GTP_TEID_FL_LINKED,
	GTP_TEID_FL_HASHED,
	GTP_TEID_FL_VTEID_HASHED,
	GTP_TEID_FL_VSQN_HASHED,
	GTP_TEID_FL_INGRESS,
	GTP_TEID_FL_EGRESS,
	GTP_TEID_FL_FWD,
	GTP_TEID_FL_RT,
	GTP_TEID_FL_XDP_DELAYED,
	GTP_TEID_FL_XDP_SET,
};

/* Defines */
#define TEID_IS_DUMMY(X)	((X)->type == 0xff)

/* GTP Connection tracking */
struct gtp_teid {
	uint8_t			version;	/* GTPv1 or GTPv2 */
	uint8_t			type;		/* User or Control plane */
	uint32_t		id;		/* Remote TEID */
	uint32_t		vid;		/* Local Virtual TEID */
	uint32_t		ipv4;		/* Remote IPv4 */
	uint8_t			bearer_id;	/* Bearer we belong to */
	struct sockaddr_in	sgw_addr;	/* Remote sGW endpoint */
	struct sockaddr_in	pgw_addr;	/* Remote pGW endpoint */
	uint8_t			family;

	uint32_t		sqn;		/* Local Seqnum */
	uint32_t		vsqn;		/* Local Virtual Seqnum */

	struct gtp_session	*session;	/* backpointer */
	struct gtp_teid		*peer_teid;	/* Linked TEID */
	struct gtp_teid		*old_teid;	/* Old Linked TEID */
	struct gtp_teid		*bearer_teid;	/* GTP-C Bearer TEID */

	uint8_t			action;
	struct hlist_node	hlist_teid;
	struct hlist_node	hlist_vteid;
	struct hlist_node	hlist_vsqn;
	struct list_head	next;

	unsigned long		flags;
	int			refcnt;
};

struct gtp_f_teid {
	uint8_t			version;
	uint32_t		*teid_grekey;
	union {
		uint32_t	*ipv4;
		uint32_t	*ipv6[4];
	};
};


/* Prototypes */
int gtp_teid_init(void);
int gtp_teid_destroy(void);
void gtp_teid_free(struct gtp_teid *);
int gtp_teid_unuse_queue_size(void);
int gtp_teid_put(struct gtp_teid *);
struct gtp_teid *gtp_teid_get(struct hlist_head *, struct gtp_f_teid *);
struct gtp_teid *gtpc_teid_get(struct gtp_f_teid *);
struct gtp_teid *gtpu_teid_get(struct gtp_f_teid *);
struct gtp_teid *gtp_teid_alloc_peer(struct hlist_head *, struct gtp_teid *, uint32_t,
				     struct gtp_ie_eps_bearer_id *, unsigned int *);
struct gtp_teid *gtpc_teid_alloc_peer(struct gtp_teid *, uint32_t,
				      struct gtp_ie_eps_bearer_id *, unsigned int *);
struct gtp_teid *gtpu_teid_alloc_peer(struct gtp_teid *, uint32_t,
				      struct gtp_ie_eps_bearer_id *, unsigned int *);
struct gtp_teid *gtp_teid_alloc(struct hlist_head *, struct gtp_f_teid *,
				struct gtp_ie_eps_bearer_id *);
struct gtp_teid *gtpc_teid_alloc(struct gtp_f_teid *, struct gtp_ie_eps_bearer_id *);
struct gtp_teid *gtpu_teid_alloc(struct gtp_f_teid *, struct gtp_ie_eps_bearer_id *);
int gtp_teid_unhash(struct hlist_head *, struct gtp_teid *);
int gtpc_teid_unhash(struct gtp_teid *);
int gtpu_teid_unhash(struct gtp_teid *);
void gtp_teid_bind(struct gtp_teid *, struct gtp_teid *);
int gtp_teid_masq(struct gtp_f_teid *, struct sockaddr_storage *, uint32_t);
int gtp_teid_restore(struct gtp_teid *, struct gtp_f_teid *);
int gtp_teid_update_sgw(struct gtp_teid *, struct sockaddr_storage *);
int gtp_teid_update_pgw(struct gtp_teid *, struct sockaddr_storage *);
void gtp_teid_dump(struct gtp_teid *);
int gtp_vteid_alloc(struct hlist_head *, struct gtp_teid *, unsigned int *);
int gtp_vteid_unhash(struct hlist_head *, struct gtp_teid *);
struct gtp_teid *gtp_vteid_get(struct hlist_head *, uint32_t);
