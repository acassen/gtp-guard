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

#ifndef _GTP_PPPOE_SESSION_H
#define _GTP_PPPOE_SESSION_H

enum gtp_pppoe_session_flags {
	GTP_PPPOE_UNIQUE_FL_HASHED,
	GTP_PPPOE_SESSION_FL_HASHED,
};

typedef struct _spppoe {
	int			state;		/* [K] discovery phase or session connected */
	struct ether_addr	hw_src;		/* [K] our hardware address */
	struct ether_addr	hw_dst;		/* [K] hardware address of concentrator */
	char			gtp_username[PPPOE_NAMELEN];
	uint16_t		session_id;	/* [K] PPPoE session id */
	uint8_t			*ac_cookie;	/* [K] content of AC cookie we must echo back */
	size_t			ac_cookie_len;	/* [K] length of cookie data */
	uint8_t			*relay_sid;	/* [K] content of relay SID we must echo back */
	size_t			relay_sid_len;	/* [K] length of relay SID data */
	uint32_t		unique;		/* [I] our unique id */
	int			padi_retried;	/* [K] number of PADI retries already done */
	int			padr_retried;	/* [K] number of PADR retries already done */

	time_t	 		session_time;	/* time the session was established */

	struct _gtp_session	*s_gtp;		/* our GTP Session peer */
	struct _sppp		*s_ppp;		/* PPP session */
	gtp_pppoe_t		*pppoe;		/* back-pointer */
	gtp_teid_t		*teid;		/* TEID we are linked to */
	gtp_server_worker_t	*w;		/* Server worker used */
	struct sockaddr_storage gtpc_peer_addr;	/* Remote GTP-C peer */

	/* Expiration handling */
	char			tmp_str[64];
	struct tm		creation_time;
	timer_node_t		t_node;

	struct hlist_node	h_session;	/* h by {MAC,session_id}*/
	struct hlist_node	h_unique;	/* h by unique*/
	list_head_t		next;		/* member of gtp_conn_t->pppoe_sessions */

	unsigned long		flags;
	int			refcnt;
} spppoe_t;


/* Prototypes */
extern spppoe_t *spppoe_get_by_unique(gtp_htab_t *, uint32_t);
extern spppoe_t *spppoe_get_by_session(gtp_htab_t *, struct ether_addr *, uint16_t);
extern int spppoe_session_hash(gtp_htab_t *h, spppoe_t *, struct ether_addr *, uint16_t);
extern spppoe_t *spppoe_init(gtp_pppoe_t *, gtp_conn_t *,
			     void (*pp_tls)(struct _sppp *), void (*pp_tlf)(struct _sppp *),
			     void (*pp_con)(struct _sppp *), void (*pp_chg)(struct _sppp *, int),
			     const uint64_t, const uint64_t, const char *);
extern int spppoe_destroy(spppoe_t *);

#endif
