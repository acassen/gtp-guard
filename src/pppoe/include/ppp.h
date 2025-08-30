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

#include "pppoe.h"

#define PPPDEBUG(a)	do {	\
	if (debug & 8)		\
		printf a;	\
} while(0)

/*
 *	PPPoE RFC 1661 related
 */
#define PPP_ALLSTATIONS	0xff		/* All-Stations broadcast address */
#define PPP_UI		0x03		/* Unnumbered Information */
#define PPP_IP		0x0021		/* Internet Protocol */
#define PPP_ISO		0x0023		/* ISO OSI Protocol */
#define PPP_XNS		0x0025		/* Xerox NS Protocol */
#define PPP_IPX		0x002b		/* Novell IPX Protocol */
#define PPP_IPV6	0x0057		/* Internet Protocol v6 */
#define PPP_LCP		0xc021		/* Link Control Protocol */
#define PPP_PAP		0xc023		/* Password Authentication Protocol */
#define PPP_CHAP	0xc223		/* Challenge-Handshake Auth Protocol */
#define PPP_IPCP	0x8021		/* Internet Protocol Control Protocol */
#define PPP_IPV6CP	0x8057		/* IPv6 Control Protocol */

#define CONF_REQ	1		/* PPP configure request */
#define CONF_ACK	2		/* PPP configure acknowledge */
#define CONF_NAK	3		/* PPP configure negative ack */
#define CONF_REJ	4		/* PPP configure reject */
#define TERM_REQ	5		/* PPP terminate request */
#define TERM_ACK	6		/* PPP terminate acknowledge */
#define CODE_REJ	7		/* PPP code reject */
#define PROTO_REJ	8		/* PPP protocol reject */
#define ECHO_REQ	9		/* PPP echo request */
#define ECHO_REPLY	10		/* PPP echo reply */
#define DISC_REQ	11		/* PPP discard request */

enum lcp_opts {
	LCP_OPT_MRU = 1,	/* maximum receive unit */
	LCP_OPT_ASYNC_MAP,	/* async control character map */
	LCP_OPT_AUTH_PROTO,	/* authentication protocol */
	LCP_OPT_QUAL_PROTO,	/* quality protocol */
	LCP_OPT_MAGIC,		/* magic number */
	LCP_OPT_RESERVED,	/* reserved */
	LCP_OPT_PROTO_COMP,	/* protocol field compression */
	LCP_OPT_ADDR_COMP,	/* address/control field compression */
};

enum ipcp_opts {
	IPCP_OPT_ADDRESSES =	1,	/* both IP addresses; deprecated */
	IPCP_OPT_COMPRESSION =	2,	/* IP compression protocol (VJ) */
	IPCP_OPT_ADDRESS =	3,	/* local IP address */
	IPCP_OPT_PRIMDNS =	129,	/* primary remote dns address */
	IPCP_OPT_SECDNS =	131,	/* secondary remote dns address */
};

/* bitmask value to enable or disable individual IPCP options */
enum ipcp_bitmask {
	SPPP_IPCP_OPT_ADDRESSES = 1,
	SPPP_IPCP_OPT_COMPRESSION,
	SPPP_IPCP_OPT_ADDRESS,
	SPPP_IPCP_OPT_PRIMDNS,
	SPPP_IPCP_OPT_SECDNS,
};

enum ipv6cp_opts {
	IPV6CP_OPT_IFID = 1,	/* interface identifier */
	IPV6CP_OPT_COMPRESSION,	/* IPv6 compression protocol */
};

#define PAP_REQ			1	/* PAP name/password request */
#define PAP_ACK			2	/* PAP acknowledge */
#define PAP_NAK			3	/* PAP fail */

#define CHAP_CHALLENGE		1	/* CHAP challenge request */
#define CHAP_RESPONSE		2	/* CHAP challenge response */
#define CHAP_SUCCESS		3	/* CHAP response ok */
#define CHAP_FAILURE		4	/* CHAP response failed */

#define CHAP_MD5		5	/* hash algorithm - MD5 */

/* states are named and numbered according to RFC 1661 */
#define STATE_INITIAL	0
#define STATE_STARTING	1
#define STATE_CLOSED	2
#define STATE_STOPPED	3
#define STATE_CLOSING	4
#define STATE_STOPPING	5
#define STATE_REQ_SENT	6
#define STATE_ACK_RCVD	7
#define STATE_ACK_SENT	8
#define STATE_OPENED	9

#define PKTHDRLEN	2

typedef struct _ppp_hdr {
	uint8_t		address;
	uint8_t		control;
	uint16_t	protocol;
} __attribute__((packed)) ppp_hdr_t;
#define PPP_HEADER_LEN		sizeof(ppp_hdr_t)

typedef struct _lcp_hdr {
	uint8_t		type;
	uint8_t		ident;
	uint16_t	len;
} __attribute__((packed)) lcp_hdr_t;
#define LCP_HEADER_LEN		sizeof(lcp_hdr_t)


/* Prototypes */
extern int ppp_set_default(pppoe_t *);
extern int ppp_init(void);
extern int ppp_destroy(void);
