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

#ifndef _GTP_H
#define _GTP_H

/* default values */
#define GTP_MAX_PACKET_SIZE		4096
#define GTPV1C_HEADER_LEN_SHORT		8
#define GTPV1C_HEADER_LEN_LONG		12
#define GTPV1U_HEADER_LEN		8
#define GTPV1U_EXTENSION_HEADER_LEN	4
#define GTPV2C_HEADER_LEN		12
#define GTP_TEID_LEN			4
#define GTP_C_PORT			2123
#define GTP_U_PORT			2152

/* GTP-C Message family */
#define GTP_INIT			(1 << 0)
#define GTP_TRIG			(1 << 2)

/* GTP-C Message Type */
#define GTP_ECHO_REQUEST_TYPE				1
#define GTP_ECHO_RESPONSE_TYPE				2
#define GTP_VERSION_NOT_SUPPORTED_INDICATION_TYPE	3
#define GTP_CREATE_PDP_CONTEXT_REQUEST			16
#define GTP_CREATE_PDP_CONTEXT_RESPONSE			17
#define GTP_UPDATE_PDP_CONTEXT_REQUEST			18
#define GTP_UPDATE_PDP_CONTEXT_RESPONSE			19
#define GTP_DELETE_PDP_CONTEXT_REQUEST			20
#define GTP_DELETE_PDP_CONTEXT_RESPONSE			21
#define GTP_CREATE_SESSION_REQUEST_TYPE			32
#define GTP_CREATE_SESSION_RESPONSE_TYPE		33
#define GTP_MODIFY_BEARER_REQUEST_TYPE			34
#define GTP_MODIFY_BEARER_RESPONSE_TYPE			35
#define GTP_DELETE_SESSION_REQUEST_TYPE			36
#define GTP_DELETE_SESSION_RESPONSE_TYPE		37
#define GTP_CHANGE_NOTIFICATION_REQUEST			38
#define GTP_CHANGE_NOTIFICATION_RESPONSE		39
#define GTP_RESUME_NOTIFICATION				164
#define GTP_RESUME_ACK					165
#define GTP_MODIFY_BEARER_COMMAND			64
#define GTP_MODIFY_BEARER_FAILURE_IND			65
#define GTP_DELETE_BEARER_COMMAND			66
#define GTP_DELETE_BEARER_FAILURE_IND			67
#define GTP_BEARER_RESSOURCE_COMMAND			68
#define GTP_BEARER_RESSOURCE_FAILURE_IND		69
#define GTP_CREATE_BEARER_REQUEST			95
#define GTP_CREATE_BEARER_RESPONSE			96
#define GTP_UPDATE_BEARER_REQUEST			97
#define GTP_UPDATE_BEARER_RESPONSE			98
#define GTP_DELETE_BEARER_REQUEST			99
#define GTP_DELETE_BEARER_RESPONSE			100
#define GTP_UPDATE_PDN_CONNECTION_SET_REQUEST		200
#define GTP_UPDATE_PDN_CONNECTION_SET_RESPONSE		201

/* GTP-C Cause */
#define GTP_CAUSE_REQUEST_ACCEPTED			16
#define GTP_CAUSE_CONTEXT_NOT_FOUND			64
#define GTP_CAUSE_INVALID_PEER				109
#define GTP1_CAUSE_REQUEST_ACCEPTED			128
#define GTP1_CAUSE_NON_EXISTENT				192

/* GTP-U Message Type */
#define GTPU_ECHO_REQ_TYPE				1
#define GTPU_ECHO_RSP_TYPE				2
#define GTPU_ERR_IND_TYPE				26
#define GTPU_SUPP_EXTHDR_NOTI_TYPE			31
#define GTPU_END_MARKER_TYPE				254
#define GTPU_GPDU_TYPE					255

/* GTP-U Flags */
#define GTPU_FL_PN					(1 << 0)
#define GTPU_FL_S					(1 << 1)
#define GTPU_FL_E					(1 << 2)
#define GTPU_FL_PT					(1 << 4)
#define GTPU_FL_V					(1 << 5)

/*
 *	GTPv1 IE
 */
typedef struct _gtp1_ie {
	uint8_t		type;
	uint16_t	length;
} __attribute__((packed)) gtp1_ie_t;

#define GTP1_IE_CAUSE_TYPE				1
typedef struct _gtp1_ie_cause {
	uint8_t		type;
	uint8_t		value;
} __attribute__((packed)) gtp1_ie_cause_t;

#define GTP1_IE_IMSI_TYPE				2
typedef struct _gtp1_ie_imsi {
	uint8_t		type;
	uint8_t		imsi[8];
} __attribute__((packed)) gtp1_ie_imsi_t;

#define GTP1_IE_RECOVERY_TYPE				14
typedef struct _gtp1_ie_recovery {
	uint8_t		type;
	uint8_t		recovery;
} __attribute__((packed)) gtp1_ie_recovery_t;

#define GTP1_IE_TEID_DATA_TYPE				16
#define GTP1_IE_TEID_CONTROL_TYPE			17
typedef struct _gtp1_ie_teid {
	uint8_t		type;
	uint32_t	id;
} __attribute__((packed)) gtp1_ie_teid_t;

#define GTP1_IE_APN_TYPE				131
typedef struct _gtp1_ie_apn {
	gtp1_ie_t	h;
	uint8_t		apn[64];
} __attribute__((packed)) gtp1_ie_apn_t;

#define GTP1_IE_GSN_ADDRESS_TYPE			133
typedef struct _gtp1_ie_gsn_address {
	gtp1_ie_t	h;
	uint32_t	ipv4;
} __attribute__((packed)) gtp1_ie_gsn_address_t;


/*
 *	GTPv2 IE
 */
typedef struct _gtpu_ie {
	uint8_t		type;
	uint16_t	length;
} __attribute__((packed)) gtpu_ie_t;

typedef struct _gtpu_ie_private {
	uint8_t		type;
	uint16_t	id;
} __attribute__((packed)) gtpu_ie_private_t;

typedef struct _gtp_ie {
	uint8_t		type;
	uint16_t	length;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t		instance:4;
	uint8_t		spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		spare:4;
	uint8_t		instance:4;
#else
# error "Please fix <bits/endian.h>"
#endif
} __attribute__((packed)) gtp_ie_t;

#define GTP_IE_IMSI_TYPE				1
typedef struct _gtp_ie_imsi {
	gtp_ie_t	h;
	uint8_t		imsi[8];
} __attribute__((packed)) gtp_ie_imsi_t;

#define GTP_IE_CAUSE_TYPE				2
typedef struct _gtp_ie_cause {
	gtp_ie_t	h;
	uint8_t		value;
} __attribute__((packed)) gtp_ie_cause_t;

#define GTP_IE_RECOVERY_TYPE				3
typedef struct _gtp_ie_recovery {
	gtp_ie_t	h;
	uint8_t		recovery;
} __attribute__((packed)) gtp_ie_recovery_t;

#define GTP_IE_APN_TYPE					71
typedef struct _gtp_ie_apn {
	gtp_ie_t	h;
	uint8_t		apn[64];
} __attribute__((packed)) gtp_ie_apn_t;

#define GTP_IE_F_TEID_TYPE				87
typedef struct _gtp_ie_f_teid {
	gtp_ie_t			h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t		interface_type:6;
			uint8_t		v6:1;
			uint8_t		v4:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t		v4:1;
			uint8_t		v6:1;
			uint8_t		interface_type:6;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint32_t			teid_grekey;
	union {
		uint32_t		ipv4;
		uint32_t		ipv6[4];
	};
} __attribute__((packed)) gtp_ie_f_teid_t;
#define GTP_TEID_INTERFACE_TYPE_SGW_GTPU	4
#define GTP_TEID_INTERFACE_TYPE_SGW_GTPC	6

#define GTP_IE_EPS_BEARER_ID				73
typedef struct _gtp_ie_eps_bearer_id {
	gtp_ie_t	h;
	uint8_t		id;
} __attribute__((packed)) gtp_ie_eps_bearer_id_t;

#define GTP_IE_BEARER_CONTEXT_TYPE			93
typedef struct _gtp_ie_bearer_context {
	gtp_ie_t			h;
	/* Grouped IE here */
} __attribute__((packed)) gtp_ie_bearer_context_t;


/*
 *	GTP Protocol headers
 */
typedef struct _gtp_hdr {
	union {
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t		spare:3;
			uint8_t		teid_presence:1;
			uint8_t		piggybacked:1;
			uint8_t		version:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t		version:3;
			uint8_t		piggybacked:1;
			uint8_t		teid_presence:1;
			uint8_t		spare:3;
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
			uint32_t	teid;
			uint32_t	sqn;
		};
		uint32_t		sqn_only;

	};
} __attribute__((packed)) gtp_hdr_t;


typedef struct _gtp1_hdr {
	union {
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t		pn:1;
			uint8_t		seq:1;
			uint8_t		extensionheader:1;
			uint8_t		spare:1;
			uint8_t		protocoltype:1;
			uint8_t		version:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t		version:3;
			uint8_t		protocoltype:1;
			uint8_t		spare:1;
			uint8_t		extensionheader:1;
			uint8_t		seq:1;
			uint8_t		pn:1;
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
			uint32_t	teid;
			uint16_t	sqn;
			uint8_t		npdu;
			uint8_t		next;
		};
		uint32_t		teid_only;
	};
} __attribute__((packed)) gtp1_hdr_t;


typedef union _gtp_packet {
	union {
		gtp1_hdr_t	hdr1;
		gtp_hdr_t	hdr;
	};
	uint8_t		buffer[GTP_MAX_PACKET_SIZE];
} __attribute__((packed)) gtp_packet_t;

#endif
