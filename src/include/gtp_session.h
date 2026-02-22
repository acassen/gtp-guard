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

#include "gtp_apn.h"
#include "gtp_conn.h"
#include "gtp_server.h"
#include "pppoe_session.h"

/* flags */
enum gtp_session_flags {
	GTP_SESSION_FL_HPLMN,
	GTP_SESSION_FL_ROAMING_IN,
	GTP_SESSION_FL_ROAMING_OUT,
};

/* Tunnel Actions */
enum {
	GTP_ACTION_DELETE_SESSION = 1,
	GTP_ACTION_DELETE_BEARER,
	GTP_ACTION_SEND_DELETE_BEARER_REQUEST,
};

/* GTP session */
struct gtp_session {
	uint32_t		id;
	uint32_t		charging_id;
	uint32_t		ipv4;
	uint64_t		mei;
	uint64_t		msisdn;
	uint8_t			ptype;
	struct gtp_plmn		serving_plmn;
	struct gtp_cdr		*cdr;

	struct gtp_apn		*apn;
	struct list_head	gtpc_teid;
	struct list_head	gtpu_teid;

	/* local method */
	int (*gtpc_teid_destroy) (struct gtp_teid *);
	int (*gtpu_teid_destroy) (struct gtp_teid *);

	struct gtp_conn		*conn;		/* backpointer */
	struct spppoe		*s_pppoe;	/* PPPoE session peer */
	struct gtp_server	*srv;		/* Server used */

	uint8_t			action;

	/* Expiration handling */
	char			tmp_str[64];
	struct tm		creation_time;

	/* I/O MUX */
	struct thread		*timer;

	struct list_head	next;

	int			refcnt;

	unsigned long		flags;
};

/* Prototypes */
int gtp_sessions_count_read(void);
void gtp_session_dump(struct gtp_session *s);
struct gtp_teid *gtp_session_gtpu_teid_get_by_sqn(struct gtp_session *, uint32_t);
int gtp_session_gtpc_teid_add(struct gtp_session *, struct gtp_teid *);
int gtp_session_gtpu_teid_add(struct gtp_session *, struct gtp_teid *);
int gtp_session_gtpu_teid_xdp_add(struct gtp_session *);
void gtp_session_mod_timer(struct gtp_session *, int);
const char *gtp_session_roaming_status_str(struct gtp_session *);
int gtp_session_roaming_status_set(struct gtp_session *);
struct gtp_session *gtp_session_alloc(struct gtp_conn *, struct gtp_apn *,
				 int (*gtpc_destroy) (struct gtp_teid *),
				 int (*gtpu_destroy) (struct gtp_teid *));
int gtp_session_gtpu_teid_destroy(struct gtp_teid *);
int gtp_session_gtpc_teid_destroy(struct gtp_teid *);
int gtp_session_destroy(struct gtp_session *);
int gtp_session_set_delete_bearer(struct gtp_session *, struct gtp_ie_eps_bearer_id *);
int gtp_session_destroy_bearer(struct gtp_session *);
int gtp_session_destroy_teid(struct gtp_teid *);
int gtp_session_uniq_ptype(struct gtp_conn *, uint8_t);
int gtp_session_expire_now(struct gtp_session *);
int gtp_sessions_release(struct gtp_conn *);
int gtp_sessions_free(struct gtp_conn *);
int gtp_sessions_init(void);
int gtp_sessions_destroy(void);
