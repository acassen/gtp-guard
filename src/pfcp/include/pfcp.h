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
struct pfcp_hdr {
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
} __attribute__((packed));


/* 3GPP.TS.29.244 7.3 */
enum pfcp_msg_type {
	/* . PFCP Node related messages */
	PFCP_HEARTBEAT_REQUEST			= 1,
	PFCP_HEARTBEAT_RESPONSE			= 2,
	PFCP_PFD_MANAGEMENT_REQUEST		= 3,
	PFCP_PFD_MANAGEMENT_RESPONSE		= 4,
	PFCP_ASSOCIATION_SETUP_REQUEST		= 5,
	PFCP_ASSOCIATION_SETUP_RESPONSE		= 6,
	PFCP_ASSOCIATION_UPDATE_REQUEST		= 7,
	PFCP_ASSOCIATION_UPDATE_RESPONSE	= 8,
	PFCP_ASSOCIATION_RELEASE_REQUEST	= 9,
	PFCP_ASSOCIATION_RELEASE_RESPONSE	= 10,
	PFCP_VERSION_NOT_SUPPORTED_RESPONSE	= 11,
	PFCP_NODE_REPORT_REQUEST		= 12,
	PFCP_NODE_REPORT_RESPONSE		= 13,
	PFCP_SESSION_SET_DELETION_REQUEST	= 14,
	PFCP_SESSION_SET_DELETION_RESPONSE	= 15,
	PFCP_SESSION_SET_MODIFICATION_REQUEST	= 16,
	PFCP_SESSION_SET_MODIFICATION_RESPONSE	= 17,

	/* . PFCP Session related messages */
	PFCP_SESSION_ESTABLISHMENT_REQUEST	= 50,
	PFCP_SESSION_ESTABLISHMENT_RESPONSE	= 51,
	PFCP_SESSION_MODIFICATION_REQUEST	= 52,
	PFCP_SESSION_MODIFICATION_RESPONSE	= 53,
	PFCP_SESSION_DELETION_REQUEST		= 54,
	PFCP_SESSION_DELETION_RESPONSE		= 55,
	PFCP_SESSION_REPORT_REQUEST		= 56,
	PFCP_SESSION_REPORT_RESPONSE		= 57,
};


/* 3GPP.TS.29.244 8.2.1 */
enum pfcp_cause {
	PFCP_CAUSE_REQUEST_ACCEPTED		= 1,
	PFCP_CAUSE_MORE_USAGE_REPORT_TO_SEND	= 2,
	PFCP_CAUSE_REQUEST_PARTIALLY_ACCEPTED	= 3,
	PFCP_CAUSE_REQUEST_REJECTED		= 64,
	PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND	= 65,
	PFCP_CAUSE_MANDATORY_IE_MISSING		= 66,
	PFCP_CAUSE_CONDITIONAL_IE_MISSING	= 67,
	PFCP_CAUSE_INVALID_LENGTH		= 68,
	PFCP_CAUSE_MANDATORY_IE_INCORRECT	= 69,
	PFCP_CAUSE_INVALID_FORWARDING_POLICY	= 70,
	PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION = 71,
	PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION = 72,
	PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE = 73,
	PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION	= 74,
	PFCP_CAUSE_NO_RESOURCES_AVAILABLE	= 75,
	PFCP_CAUSE_SERVICE_NOT_SUPPORTED	= 76,
	PFCP_CAUSE_SYSTEM_FAILURE		= 77,
	PFCP_CAUSE_REDIRECTION_REQUESTED	= 78,
	PFCP_CAUSE_ALL_DYNAMIC_ADDRESS_ARE_OCCUPIED = 79,
	PFCP_CAUSE_UNKNOWN_PRE_DEFINED_RULE	= 80,
	PFCP_CAUSE_UNKNOWN_APPLICATION_ID	= 81,
};


/* Prototypes */
int pfcp_init(void);
int pfcp_destroy(void);
