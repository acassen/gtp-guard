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

#define AUTHFLAG_NOCALLOUT	1 /* don't require authentication on callouts */
#define AUTHFLAG_NORECHALLENGE	2 /* don't re-challenge CHAP */

/*
 * Don't change the order of this.  Ordering the phases this way allows
 * for a comparison of ``pp_phase >= PHASE_AUTHENTICATE'' in order to
 * know whether LCP is up.
 */
enum ppp_phase {
	PHASE_DEAD, PHASE_ESTABLISH, PHASE_TERMINATE,
	PHASE_AUTHENTICATE, PHASE_NETWORK
};


#define AUTHMAXLEN	256	/* including terminating '\0' */
#define AUTHCHALEN	16	/* length of the challenge we send */

#define IPCP_MAX_DNSSRV	2
struct sdnsreq {
	int cmd;
	struct in_addr dns[IPCP_MAX_DNSSRV];
};

#define IDX_LCP 0		/* idx into state table */

typedef struct slcp {
	unsigned long	opts;		/* LCP options to send (bitfield) */
	uint32_t	magic;          /* local magic number */
	uint32_t	mru;		/* our max receive unit */
	uint32_t	their_mru;	/* their max receive unit */
	uint32_t	protos;		/* bitmask of protos that are started */
	uint8_t 	echoid;         /* id of last keepalive echo request */
	/* restart max values, see RFC 1661 */
	int		timeout;	/* seconds */
	int		max_terminate;
	int		max_configure;
	int		max_failure;
} slcp_t;


#define IDX_IPCP	1		/* idx into state table */
#define IDX_IPV6CP	2

typedef struct sipcp {
	unsigned long	opts;		/* IPCP options to send (bitfield) */
	uint32_t	flags;
#define IPCP_HISADDR_SEEN	1	/* have seen his address already */
#define IPCP_MYADDR_DYN		2	/* my address is dynamically assigned */
#define IPCP_MYADDR_SEEN	4	/* have seen my address already */
#define IPCP_HISADDR_DYN	8	/* his address is dynamically assigned */
#define IPV6CP_MYIFID_DYN	1	/* my ifid is dynamically assigned */
#define IPV6CP_MYIFID_SEEN	2	/* have seen my suggested ifid */
	uint32_t	saved_hisaddr; /* if hisaddr (IPv4) is dynamic, save
					* original one here, in network byte order */
	uint32_t	req_hisaddr;	/* remote address requested (IPv4) */
	uint32_t	req_myaddr;	/* local address requested (IPv4) */
	struct in_addr	dns[IPCP_MAX_DNSSRV]; /* IPv4 DNS servers (RFC 1877) */
	struct in6_addr	req_ifid;	/* local ifid requested (IPv6) */
} sipcp_t;

typedef struct sauth {
	uint16_t	proto;		/* authentication protocol to use */
	uint16_t	flags;
	char		*name;		/* system identification name */
	char		*secret;	/* secret password */
} sauth_t;

#define IDX_PAP		3

#define IDX_COUNT (IDX_PAP + 1) /* bump this when adding cp's! */

typedef struct _sppp {
	spppoe_t	*s_pppoe;		/* PPPoE back-pointer */
	unsigned long	pp_flags;
	uint32_t	pp_framebytes;		/* number of bytes added by hardware framing */
	uint16_t	pp_alivecnt;		/* keepalive packets counter */
	uint16_t	pp_loopcnt;		/* loopback detection counter */
	uint32_t	pp_seq;			/* local sequence number */
	uint32_t	pp_rseq;		/* remote sequence number */
	time_t		pp_last_receive;	/* peer's last "sign of life" */
	time_t		pp_last_activity;	/* second of last payload data s/r */
	enum ppp_phase	pp_phase;		/* phase we're currently in */
	int		state[IDX_COUNT];	/* state machine */
	uint8_t		confid[IDX_COUNT];	/* id of last configuration request */
	int		rst_counter[IDX_COUNT];	/* restart counter */
	int		fail_counter[IDX_COUNT];/* negotiation failure counter */
	thread_t	*ch[IDX_COUNT];
	thread_t	*pap_my_to_ch;
	thread_t	*keepalive;
	slcp_t		lcp;			/* LCP params */
	sipcp_t		ipcp;			/* IPCP params */
	sipcp_t		ipv6cp;			/* IPV6CP params */
	sauth_t		myauth;			/* auth params, i'm peer */
	sauth_t		hisauth;		/* auth params, i'm authenticator */
	uint8_t		chap_challenge[AUTHCHALEN]; /* random challenge used by CHAP */

	/*
	 * These functions are filled in by sppp_attach(), and are
	 * expected to be used by the lower layer (hardware) drivers
	 * in order to communicate the (un)availability of the
	 * communication link.  Lower layer drivers that are always
	 * ready to communicate (like hardware HDLC) can shortcut
	 * pp_up from pp_tls, and pp_down from pp_tlf.
	 */
	void	(*pp_up)(struct _sppp *);
	void	(*pp_down)(struct _sppp *);
	/*
	 * These functions need to be filled in by the lower layer
	 * (hardware) drivers if they request notification from the
	 * PPP layer whether the link is actually required.  They
	 * correspond to the tls and tlf actions.
	 */
	void	(*pp_tls)(struct _sppp *);
	void	(*pp_tlf)(struct _sppp *);
	/*
	 * These (optional) functions may be filled by the hardware
	 * driver if any notification of established connections
	 * (currently: IPCP up) is desired (pp_con) or any internal
	 * state change of the interface state machine should be
	 * signaled for monitoring purposes (pp_chg).
	 */
	void	(*pp_con)(struct _sppp *);
	void	(*pp_chg)(struct _sppp *, int);
} sppp_t;

#define PP_KEEPALIVE	0x01	/* use keepalive protocol */
				/* 0x02 was PP_CISCO */
				/* 0x04 was PP_TIMO */
#define PP_CALLIN	0x08	/* we are being called */
#define PP_NEEDAUTH	0x10	/* remote requested authentication */
#define PP_NOFRAMING	0x20	/* do not add/expect encapsulation
				   around PPP frames (i.e. the serial
				   HDLC like encapsulation, RFC1662) */

#define PP_MIN_MRU	IP_MSS	/* minimal MRU */
#define PP_MTU		1500	/* default MTU */
#define PP_MAX_MRU	2048	/* maximal MRU we want to negotiate */

#define MAXALIVECNT	3	/* max. missed alive packets */
#define	NORECV_TIME	15	/* before we get worried */

#define FAILMSG "Failed..."
#define SUCCMSG "Welcome!"

/* Prototypes */
extern void sppp_lcp_init(sppp_t *);
extern void sppp_lcp_up(sppp_t *);
extern void sppp_lcp_down(sppp_t *);
extern void sppp_lcp_open(sppp_t *);
extern void sppp_lcp_close(sppp_t *);
extern void sppp_lcp_TO(thread_t *);
extern int sppp_lcp_RCR(sppp_t *, lcp_hdr_t *, int);
extern void sppp_lcp_RCN_rej(sppp_t *, lcp_hdr_t *, int);
extern void sppp_lcp_RCN_nak(sppp_t *, lcp_hdr_t *, int);
extern void sppp_lcp_tlu(sppp_t *);
extern void sppp_lcp_tld(sppp_t *);
extern void sppp_lcp_tls(sppp_t *);
extern void sppp_lcp_tlf(sppp_t *);
extern void sppp_lcp_scr(sppp_t *);
extern void sppp_lcp_check_and_close(sppp_t *);
extern int sppp_ncp_check(sppp_t *);

extern void sppp_ipcp_init(sppp_t *);
extern void sppp_ipcp_destroy(sppp_t *);
extern void sppp_ipcp_up(sppp_t *);
extern void sppp_ipcp_down(sppp_t *);
extern void sppp_ipcp_open(sppp_t *);
extern void sppp_ipcp_close(sppp_t *);
extern void sppp_ipcp_TO(thread_t *);
extern int sppp_ipcp_RCR(sppp_t *, lcp_hdr_t *, int);
extern void sppp_ipcp_RCN_rej(sppp_t *, lcp_hdr_t *, int);
extern void sppp_ipcp_RCN_nak(sppp_t *, lcp_hdr_t *, int);
extern void sppp_ipcp_tlu(sppp_t *);
extern void sppp_ipcp_tls(sppp_t *);
extern void sppp_ipcp_tlf(sppp_t *);
extern void sppp_ipcp_scr(sppp_t *);

extern void sppp_ipv6cp_init(sppp_t *);
extern void sppp_ipv6cp_destroy(sppp_t *);
extern void sppp_ipv6cp_up(sppp_t *);
extern void sppp_ipv6cp_down(sppp_t *);
extern void sppp_ipv6cp_open(sppp_t *);
extern void sppp_ipv6cp_close(sppp_t *);
extern void sppp_ipv6cp_TO(thread_t *);
extern int sppp_ipv6cp_RCR(sppp_t *, lcp_hdr_t *, int);
extern void sppp_ipv6cp_RCN_rej(sppp_t *, lcp_hdr_t *, int);
extern void sppp_ipv6cp_RCN_nak(sppp_t *, lcp_hdr_t *, int);
extern void sppp_ipv6cp_tlu(sppp_t *);
extern void sppp_ipv6cp_tld(sppp_t *);
extern void sppp_ipv6cp_tls(sppp_t *);
extern void sppp_ipv6cp_tlf(sppp_t *);
extern void sppp_ipv6cp_scr(sppp_t *);

extern void sppp_pap_input(sppp_t *, pkt_t *pkt);
extern void sppp_pap_init(sppp_t *);
extern void sppp_pap_open(sppp_t *);
extern void sppp_pap_close(sppp_t *);
extern void sppp_pap_TO(thread_t *);
extern void sppp_pap_my_TO(thread_t *);
extern void sppp_pap_tlu(sppp_t *);
extern void sppp_pap_tld(sppp_t *);
extern void sppp_pap_scr(sppp_t *);

extern void sppp_input(sppp_t *, pkt_t *);
extern int sppp_up(spppoe_t *);
extern int sppp_down(spppoe_t *);
extern sppp_t *sppp_init(spppoe_t *, void (*pp_tls)(struct _sppp *)
				   , void (*pp_tlf)(sppp_t *)
				   , void (*pp_con)(sppp_t *)
				   , void (*pp_chg)(struct _sppp *, int));
extern void sppp_destroy(sppp_t *);
