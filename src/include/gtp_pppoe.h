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

#ifndef _GTP_PPPOE_H
#define _GTP_PPPOE_H

/*
 *	PPPoE RFC 2516 related
 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

#define PPPOE_STATE_INITIAL	0
#define PPPOE_STATE_PADI_SENT	1
#define	PPPOE_STATE_PADR_SENT	2
#define	PPPOE_STATE_SESSION	3
#define	PPPOE_STATE_CLOSING	4

#define PPPOE_NAMELEN		512		/* should be enough */

#define	PPPOE_HEADERLEN		sizeof(pppoe_hdr_t)
#define	PPPOE_OVERHEAD		(PPPOE_HEADERLEN + 2)
#define	PPPOE_VERTYPE		0x11		/* VER=1, TYPE = 1 */

#define	PPPOE_TAG_EOL		0x0000		/* end of list */
#define	PPPOE_TAG_SNAME		0x0101		/* service name */
#define	PPPOE_TAG_ACNAME	0x0102		/* access concentrator name */
#define	PPPOE_TAG_HUNIQUE	0x0103		/* host unique */
#define	PPPOE_TAG_ACCOOKIE	0x0104		/* AC cookie */
#define	PPPOE_TAG_VENDOR	0x0105		/* vendor specific */
#define	PPPOE_TAG_RELAYSID	0x0110		/* relay session id */
#define	PPPOE_TAG_MAX_PAYLOAD	0x0120		/* RFC 4638 max payload */
#define	PPPOE_TAG_SNAME_ERR	0x0201		/* service name error */
#define	PPPOE_TAG_ACSYS_ERR	0x0202		/* AC system error */
#define	PPPOE_TAG_GENERIC_ERR	0x0203		/* generic error */

#define	PPPOE_CODE_PADI		0x09		/* Active Discovery Initiation */
#define	PPPOE_CODE_PADO		0x07		/* Active Discovery Offer */
#define	PPPOE_CODE_PADR		0x19		/* Active Discovery Request */
#define	PPPOE_CODE_PADS		0x65		/* Active Discovery Session confirmation */
#define	PPPOE_CODE_PADT		0xA7		/* Active Discovery Terminate */

/* two byte PPP protocol discriminator, then IP data */
#define	PPPOE_MTU	(ETHERMTU - PPPOE_OVERHEAD)
#define	PPPOE_MAXMTU	PP_MAX_MRU

/* Add a 16 bit unsigned value to a buffer pointed to by PTR */
#define	PPPOE_ADD_16(PTR, VAL)			\
		*(PTR)++ = (VAL) / 256;		\
		*(PTR)++ = (VAL) % 256

/* Add a complete PPPoE header to the buffer pointed to by PTR */
#define	PPPOE_ADD_HEADER(PTR, CODE, SESS, LEN)	\
		*(PTR)++ = PPPOE_VERTYPE;	\
		*(PTR)++ = (CODE);		\
		PPPOE_ADD_16(PTR, SESS);	\
		PPPOE_ADD_16(PTR, LEN)

#define	PPPOE_DISC_TIMEOUT	5	/* base for quick timeout calculation (seconds) */
#define	PPPOE_SLOW_RETRY	60	/* persistent retry interval (seconds) */
#define	PPPOE_DISC_MAXPADI	4	/* retry PADI four times (quickly) */
#define	PPPOE_DISC_MAXPADR	2	/* retry PADR twice */

typedef struct _pppoe_hdr {
	uint8_t		vertype;
	uint8_t		code;
	uint16_t	session;
	uint16_t	plen;
} __attribute__((packed)) pppoe_hdr_t;

typedef struct _pppoe_tag {
	uint16_t	tag;
	uint16_t	len;
} __attribute__((packed)) pppoe_tag_t;


/* Timers */
#define GTP_PPPOE_RECV_TIMER	(3 * TIMER_HZ)

typedef struct _gtp_pppoe_session {
	int			state;
	struct ether_addr	dst;
	uint16_t		session_id;

	struct _gtp_pppoe	*pppoe;			/* back-pointer */

	uint8_t			*ac_cookie;		/* [K] content of AC cookie we must echo back */
	size_t			ac_cookie_len;		/* [K] length of cookie data */
	uint8_t			*relay_sid;		/* [K] content of relay SID we must echo back */
	size_t			relay_sid_len;		/* [K] length of relay SID data */
	uint32_t		unique;			/* [I] our unique id */
	int			padi_retried;		/* [K] number of PADI retries already done */
	int			padr_retried;		/* [K] number of PADR retries already done */

	time_t	 		session_time;		/* time the session was established */	
} gtp_pppoe_session_t;

typedef struct _gtp_pkt {
	pkt_buffer_t		*pbuff;

	list_head_t		next;
} gtp_pkt_t;

typedef struct _gtp_pkt_queue {
	pthread_mutex_t		mutex;
	list_head_t		queue;
} gtp_pkt_queue_t;

typedef struct _gtp_pppoe_worker {
	char			pname[GTP_PNAME];
	int			id;
	pthread_t		task;
	struct _gtp_pppoe	*pppoe;		/* backpointer */

	pthread_cond_t		cond;
	pthread_mutex_t		mutex;

	gtp_pkt_queue_t		pkt_q;
} gtp_pppoe_worker_t;


typedef struct _gtp_pppoe {
	char			ifname[GTP_NAME_MAX_LEN];
	char			ac_name[PPPOE_NAMELEN];
	char			service_name[PPPOE_NAMELEN];
	int			thread_cnt;
	int			refcnt;
	int			fd_disc;
	int			fd_session;
	pthread_t		task;

	/* I/O MUX related */
	thread_master_t		*master;
	thread_ref_t		r_thread;

	gtp_pkt_queue_t		pkt_q;

	gtp_pppoe_worker_t	*worker;

	list_head_t		next;

	unsigned long		flags;
} gtp_pppoe_t;


/* Prototypes */
extern gtp_pkt_t *gtp_pkt_get(gtp_pkt_queue_t *);
extern int gtp_pkt_put(gtp_pkt_queue_t *, gtp_pkt_t *);
extern ssize_t gtp_pkt_send(int, gtp_pkt_queue_t *, gtp_pkt_t *);
extern int gtp_pppoe_put(gtp_pppoe_t *);
extern int gtp_pppoe_start(gtp_pppoe_t *);
extern int gtp_pppoe_release(gtp_pppoe_t *);
extern gtp_pppoe_t *gtp_pppoe_init(const char *);
extern int gtp_pppoe_destroy(void);

#endif
