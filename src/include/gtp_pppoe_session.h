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
	GTP_PPPOE_SESSION_FL_HASHED,
};

typedef struct _gtp_pppoe_session {
	int			state;		/* [K] discovery phase or session connected */
	struct ether_addr	hw_src;		/* [K] our hardware address */
	struct ether_addr	hw_dst;		/* [K] hardware address of concentrator */
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
	gtp_pppoe_t		*pppoe;		/* back-pointer */

	/* Expiration handling */
	char			tmp_str[64];
	struct tm		creation_time;
	timeval_t		sands;
	rb_node_t		n;

	struct hlist_node	hlist;

	unsigned long		flags;
	int			refcnt;
} gtp_pppoe_session_t;


/* Prototypes */
extern gtp_pppoe_session_t *gtp_pppoe_session_get(gtp_htab_t *, uint32_t);
extern void gtp_pppoe_timer_add(gtp_pppoe_timer_t *, gtp_pppoe_session_t *, int);
extern void gtp_pppoe_timer_del(gtp_pppoe_timer_t *, gtp_pppoe_session_t *);
extern int gtp_pppoe_timer_init(gtp_pppoe_t *, gtp_pppoe_timer_t *);
extern int gtp_pppoe_timer_destroy(gtp_pppoe_timer_t *);
extern gtp_pppoe_session_t *gtp_pppoe_session_init(gtp_pppoe_t *, struct ether_addr *, uint64_t);
extern int gtp_pppoe_session_destroy(gtp_pppoe_session_t *);

#endif
