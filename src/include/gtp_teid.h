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
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _GTP_TEID_H
#define _GTP_TEID_H

/* Tunnel type */
enum {
	GTP_TEID_C = 1,
	GTP_TEID_U,
};

/* GTP Connection tracking */
typedef struct _gtp_teid {
	uint8_t			version;	/* GTPv1 or GTPv2 */
	uint8_t			type;		/* User or Contrlo plane */
	uint32_t		id;		/* Remote TEID */
	uint32_t		vid;		/* Local Virtual TEID */
	uint32_t		ipv4;		/* Remote IPv4 */
	uint8_t			bearer_id;	/* Bearer we belong to */
	struct sockaddr_in	sgw_addr;	/* Remote sGW endpoint */
	struct sockaddr_in	pgw_addr;	/* Remote pGW endpoint */

	uint32_t		sqn;		/* Local Seqnum */
	uint32_t		vsqn;		/* Local Virtual Seqnum */

	struct _gtp_session	*session;	/* backpointer */
	struct _gtp_teid	*peer_teid;	/* Linked TEID */
	struct _gtp_teid	*old_teid;	/* Old Linked TEID */
	struct _gtp_teid	*bearer_teid;	/* GTP-C Bearer TEID */

	uint8_t			action;
	uint32_t		refcnt;
	struct hlist_node	hlist_teid;
	struct hlist_node	hlist_vteid;
	struct hlist_node	hlist_vsqn;
	list_head_t		next;
} gtp_teid_t;

typedef struct _gtp_f_teid {
	uint8_t			version;
	uint32_t		*teid_grekey;
	union {
		uint32_t	*ipv4;
		uint32_t	*ipv6[4];
	};
} gtp_f_teid_t;


/* Prototypes */
extern int gtp_teid_put(gtp_teid_t *);
extern gtp_teid_t *gtp_teid_get(gtp_htab_t *, gtp_f_teid_t *);
extern gtp_teid_t *gtp_teid_alloc(gtp_htab_t *, gtp_f_teid_t *, gtp_ie_eps_bearer_id_t *);
extern int gtp_teid_unhash(gtp_htab_t *, gtp_teid_t *);
extern void gtp_teid_bind(gtp_teid_t *, gtp_teid_t *);
extern int gtp_teid_masq(gtp_f_teid_t *, struct sockaddr_storage *, uint32_t);
extern int gtp_teid_restore(gtp_teid_t *, gtp_f_teid_t *);
extern void gtp_teid_dump(gtp_teid_t *);
extern int gtp_vteid_alloc(gtp_htab_t *, gtp_teid_t *, unsigned int *);
extern int gtp_vteid_unhash(gtp_htab_t *, gtp_teid_t *);
extern gtp_teid_t *gtp_vteid_get(gtp_htab_t *, uint32_t);

#endif
