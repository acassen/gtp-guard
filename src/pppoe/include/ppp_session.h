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

#include "ppp.h"
#include "pppoe_session.h"

#define AUTHFLAG_NOCALLOUT	1 /* don't require authentication on callouts */
#define AUTHFLAG_NORECHALLENGE	2 /* don't re-challenge CHAP */

/*
 * Don't change the order of this.  Ordering the phases this way allows
 * for a comparison of ``pp_phase >= PHASE_AUTHENTICATE'' in order to
 * know whether LCP is up.
 */
enum ppp_phase {
	PHASE_DEAD,
	PHASE_ESTABLISH,
	PHASE_TERMINATE,
	PHASE_AUTHENTICATE,
	PHASE_NETWORK
};


#define AUTHMAXLEN	256	/* including terminating '\0' */
#define AUTHCHALEN	16	/* length of the challenge we send */

#define IPCP_MAX_DNSSRV	2
struct sdnsreq {
	int cmd;
	struct in_addr dns[IPCP_MAX_DNSSRV];
};

#define IDX_LCP 0		/* idx into state table */

struct slcp {
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
};


#define IDX_IPCP	1		/* idx into state table */
#define IDX_IPV6CP	2

struct sipcp {
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
};

struct sauth {
	uint16_t	proto;		/* authentication protocol to use */
	uint16_t	flags;
	char		*name;		/* system identification name */
	char		*secret;	/* secret password */
};

#define IDX_PAP		3

#define IDX_COUNT (IDX_PAP + 1) /* bump this when adding cp's! */

struct sppp {
	struct spppoe	*s_pppoe;		/* PPPoE back-pointer */
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
	struct thread	*ch[IDX_COUNT];
	struct thread	*pap_my_to_ch;
	struct thread	*keepalive;
	struct slcp	lcp;			/* LCP params */
	struct sipcp	ipcp;			/* IPCP params */
	struct sipcp	ipv6cp;			/* IPV6CP params */
	struct sauth	myauth;			/* auth params, i'm peer */
	struct sauth	hisauth;		/* auth params, i'm authenticator */
	uint8_t		chap_challenge[AUTHCHALEN]; /* random challenge used by CHAP */

	/*
	 * These functions are filled in by sppp_attach(), and are
	 * expected to be used by the lower layer (hardware) drivers
	 * in order to communicate the (un)availability of the
	 * communication link.  Lower layer drivers that are always
	 * ready to communicate (like hardware HDLC) can shortcut
	 * pp_up from pp_tls, and pp_down from pp_tlf.
	 */
	void	(*pp_up)(struct sppp *);
	void	(*pp_down)(struct sppp *);
	/*
	 * These functions need to be filled in by the lower layer
	 * (hardware) drivers if they request notification from the
	 * PPP layer whether the link is actually required.  They
	 * correspond to the tls and tlf actions.
	 */
	void	(*pp_tls)(struct sppp *);
	void	(*pp_tlf)(struct sppp *);
	/*
	 * These (optional) functions may be filled by the hardware
	 * driver if any notification of established connections
	 * (currently: IPCP up) is desired (pp_con) or any internal
	 * state change of the interface state machine should be
	 * signaled for monitoring purposes (pp_chg).
	 */
	void	(*pp_con)(struct sppp *);
	void	(*pp_chg)(struct sppp *, int);
};

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
void sppp_lcp_init(struct sppp *);
void sppp_lcp_up(struct sppp *);
void sppp_lcp_down(struct sppp *);
void sppp_lcp_open(struct sppp *);
void sppp_lcp_close(struct sppp *);
void sppp_lcp_TO(struct thread *);
int sppp_lcp_RCR(struct sppp *, struct lcp_hdr *, int);
void sppp_lcp_RCN_rej(struct sppp *, struct lcp_hdr *, int);
void sppp_lcp_RCN_nak(struct sppp *, struct lcp_hdr *, int);
void sppp_lcp_tlu(struct sppp *);
void sppp_lcp_tld(struct sppp *);
void sppp_lcp_tls(struct sppp *);
void sppp_lcp_tlf(struct sppp *);
void sppp_lcp_scr(struct sppp *);
void sppp_lcp_check_and_close(struct sppp *);
int sppp_ncp_check(struct sppp *);

void sppp_ipcp_init(struct sppp *);
void sppp_ipcp_destroy(struct sppp *);
void sppp_ipcp_up(struct sppp *);
void sppp_ipcp_down(struct sppp *);
void sppp_ipcp_open(struct sppp *);
void sppp_ipcp_close(struct sppp *);
void sppp_ipcp_TO(struct thread *);
int sppp_ipcp_RCR(struct sppp *, struct lcp_hdr *, int);
void sppp_ipcp_RCN_rej(struct sppp *, struct lcp_hdr *, int);
void sppp_ipcp_RCN_nak(struct sppp *, struct lcp_hdr *, int);
void sppp_ipcp_tlu(struct sppp *);
void sppp_ipcp_tls(struct sppp *);
void sppp_ipcp_tlf(struct sppp *);
void sppp_ipcp_scr(struct sppp *);

void sppp_ipv6cp_init(struct sppp *);
void sppp_ipv6cp_destroy(struct sppp *);
void sppp_ipv6cp_up(struct sppp *);
void sppp_ipv6cp_down(struct sppp *);
void sppp_ipv6cp_open(struct sppp *);
void sppp_ipv6cp_close(struct sppp *);
void sppp_ipv6cp_TO(struct thread *);
int sppp_ipv6cp_RCR(struct sppp *, struct lcp_hdr *, int);
void sppp_ipv6cp_RCN_rej(struct sppp *, struct lcp_hdr *, int);
void sppp_ipv6cp_RCN_nak(struct sppp *, struct lcp_hdr *, int);
void sppp_ipv6cp_tlu(struct sppp *);
void sppp_ipv6cp_tld(struct sppp *);
void sppp_ipv6cp_tls(struct sppp *);
void sppp_ipv6cp_tlf(struct sppp *);
void sppp_ipv6cp_scr(struct sppp *);

void sppp_pap_input(struct sppp *, struct pkt *pkt);
void sppp_pap_init(struct sppp *);
void sppp_pap_open(struct sppp *);
void sppp_pap_close(struct sppp *);
void sppp_pap_TO(struct thread *);
void sppp_pap_my_TO(struct thread *);
void sppp_pap_tlu(struct sppp *);
void sppp_pap_tld(struct sppp *);
void sppp_pap_scr(struct sppp *);

void sppp_input(struct sppp *, struct pkt *);
int sppp_up(struct spppoe *);
int sppp_down(struct spppoe *);
struct sppp *sppp_init(struct spppoe *, void (*pp_tls)(struct sppp *),
		       void (*pp_tlf)(struct sppp *),
		       void (*pp_con)(struct sppp *),
		       void (*pp_chg)(struct sppp *, int));
void sppp_destroy(struct sppp *);
