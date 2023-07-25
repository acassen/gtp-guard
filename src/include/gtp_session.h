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

#ifndef _GTP_SESSION_H
#define _GTP_SESSION_H


/* Tunnel Actions */
#define GTP_ACTION_DELETE_SESSION	0x01
#define GTP_ACTION_DELETE_BEARER	0x02

/* Tunnel type */
#define GTP_TEID_C	0x01
#define GTP_TEID_U	0x02

/* GTP Connection tracking */
typedef struct _gtp_teid {
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

/* GTP session */
typedef struct _gtp_session {
	uint32_t		id;
	gtp_apn_t		*apn;
	list_head_t		gtpc_teid;
	list_head_t		gtpu_teid;

	gtp_conn_t		*conn;		/* backpointer */

	uint8_t			action;
        uint32_t                refcnt;

	/* Expiration handling */
	char			tmp_str[64];
	struct tm		creation_time;
	timeval_t		sands;
	rb_node_t		n;

	list_head_t		next;
} gtp_session_t;


/* Prototypes */
extern void gtp_session_dump(gtp_session_t *s);
extern gtp_teid_t *gtp_session_gtpu_teid_get_by_sqn(gtp_session_t *, uint32_t);
extern int gtp_session_gtpc_teid_add(gtp_session_t *, gtp_teid_t *);
extern int gtp_session_gtpu_teid_add(gtp_session_t *, gtp_teid_t *);
extern gtp_session_t *gtp_session_alloc(gtp_conn_t *, gtp_apn_t *);
extern int gtp_session_gtpu_teid_destroy(gtp_ctx_t *, gtp_teid_t *);
extern int gtp_session_gtpc_teid_destroy(gtp_ctx_t *, gtp_teid_t *);
extern int gtp_session_destroy(gtp_ctx_t *, gtp_session_t *);
extern int gtp_session_set_delete_bearer(gtp_ctx_t *, gtp_session_t *, gtp_ie_eps_bearer_id_t *);
extern int gtp_session_destroy_bearer(gtp_ctx_t *, gtp_session_t *);
extern int gtp_sessions_init(void);
extern int gtp_sessions_destroy(void);
extern int gtp_sessions_vty_init(void);

#endif
