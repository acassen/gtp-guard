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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com> 
 */

#pragma once

#include <stdint.h>


/* default values */
#define PFCP_VERSION		1
#define PFCP_PORT		8805
#define PFCP_MAX_PACKET_SIZE	4096
#define PFCP_HEADER_LEN		16
#define PFCP_SEID_LEN		8


/* Macro */
#define PFCP_SQN(s) (ntohl(sqn) >> 8)


/* 3GPP.TS.29.244 7.2.2.1 */
typedef struct pfcp_hdr {
	union {
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t		s:1;
			uint8_t		mp:1;
			uint8_t		fo:1;
			uint8_t		spare:2;
			uint8_t		version:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t		version:3;
			uint8_t		spare:2;
			uint8_t		fo:1;
			uint8_t		mp:1;
			uint8_t		s:1;
#else
# error "Please fix <bits/endian.h>"
#endif
		};
		uint8_t			flags;
	};

	uint8_t				type;
	uint16_t			length;
	union {
		struct {
			uint64_t	seid;
			uint32_t	sqn;
		};
		uint32_t		sqn_only;

	};
} __attribute__((packed)) pfcp_hdr_t;


/*
 *	Message Types
 */

/* 3GPP.TS.29.244 7.3 */
/* . PFCP Node related messages */
#define PFCP_HEARTBEAT_REQUEST			1
#define PFCP_HEARTBEAT_RESPONSE			2
#define PFCP_PFD_MANAGEMENT_REQUEST		3
#define PFCP_PFD_MANAGEMENT_RESPONSE		4
#define PFCP_ASSOCIATION_SETUP_REQUEST		5
#define PFCP_ASSOCIATION_SETUP_RESPONSE		6
#define PFCP_ASSOCIATION_UPDATE_REQUEST		7
#define PFCP_ASSOCIATION_UPDATE_RESPONSE	8
#define PFCP_ASSOCIATION_RELEASE_REQUEST	9
#define PFCP_ASSOCIATION_RELEASE_RESPONSE	10
#define PFCP_VERSION_NOT_SUPPORTED_RESPONSE	11
#define PFCP_NODE_REPORT_REQUEST		12
#define PFCP_NODE_REPORT_RESPONSE		13
#define PFCP_SESSION_SET_DELETION_REQUEST	14
#define PFCP_SESSION_SET_DELETION_RESPONSE	15
#define PFCP_SESSION_SET_MODIFICATION_REQUEST	16
#define PFCP_SESSION_SET_MODIFICATION_RESPONSE	17
/* . PFCP Session related messages */
#define PFCP_SESSION_ESTABLISHMENT_REQUEST	50
#define PFCP_SESSION_ESTABLISHMENT_RESPONSE	51
#define PFCP_SESSION_MODIFICATION_REQUEST	52
#define PFCP_SESSION_MODIFICATION_RESPONSE	53
#define PFCP_SESSION_DELETION_REQUEST		54
#define PFCP_SESSION_DELETION_RESPONSE		55
#define PFCP_SESSION_REPORT_REQUEST		56
#define PFCP_SESSION_REPORT_RESPONSE		57


/*
 *	PFCP IE
 */
/* 3GPP.TS.29.244.8 */
typedef struct pfcp_ie {
	uint16_t	type;
	uint16_t	length;
} __attribute__((packed)) pfcp_ie_t;







/* Prototypes */
int pfcp_init(void);
int pfcp_destroy(void);
