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
enum {
	GTP_ACTION_DELETE_SESSION = 1,
	GTP_ACTION_DELETE_BEARER,
	GTP_ACTION_SEND_DELETE_BEARER_REQUEST,
};

/* GTP session */
typedef struct _gtp_session {
	uint32_t		id;
	uint32_t		charging_id;
	uint32_t		ipv4;
	uint64_t		mei;
	uint64_t		msisdn;
	uint8_t			ptype;

	gtp_apn_t		*apn;
	list_head_t		gtpc_teid;
	list_head_t		gtpu_teid;

	/* local method */
	int (*gtpc_teid_destroy) (gtp_teid_t *);
	int (*gtpu_teid_destroy) (gtp_teid_t *);

	gtp_conn_t		*conn;		/* backpointer */
	spppoe_t		*s_pppoe;	/* PPPoE session peer */
	gtp_server_worker_t	*w;		/* Server worker used */

	uint8_t			action;

	/* Expiration handling */
	char			tmp_str[64];
	struct tm		creation_time;
	timer_node_t		t_node;

	list_head_t		next;

	int			refcnt;
} gtp_session_t;


/* Prototypes */
extern void gtp_session_dump(gtp_session_t *s);
extern gtp_session_t *gtp_session_get_by_ptype(gtp_conn_t *, uint8_t);
extern gtp_teid_t *gtp_session_gtpu_teid_get_by_sqn(gtp_session_t *, uint32_t);
extern int gtp_session_gtpc_teid_add(gtp_session_t *, gtp_teid_t *);
extern int gtp_session_gtpu_teid_add(gtp_session_t *, gtp_teid_t *);
extern int gtp_session_gtpu_teid_xdp_add(gtp_session_t *);
extern gtp_session_t *gtp_session_alloc(gtp_conn_t *, gtp_apn_t *,
					int (*gtpc_destroy) (gtp_teid_t *),
					int (*gtpu_destroy) (gtp_teid_t *));
extern int gtp_session_gtpu_teid_destroy(gtp_teid_t *);
extern int gtp_session_gtpc_teid_destroy(gtp_teid_t *);
extern int gtp_session_destroy(gtp_session_t *);
extern int gtp_session_set_delete_bearer(gtp_session_t *, gtp_ie_eps_bearer_id_t *);
extern int gtp_session_destroy_bearer(gtp_session_t *);
extern int gtp_session_destroy_teid(gtp_teid_t *);
extern int gtp_session_expire_now(gtp_session_t *);
extern int gtp_sessions_free(gtp_conn_t *);
extern int gtp_sessions_init(void);
extern int gtp_sessions_destroy(void);
extern int gtp_sessions_vty_init(void);

#endif
