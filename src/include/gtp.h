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

#include <stdint.h>

/* Flags */
enum gtp_flags {
	GTP_FL_RUNNING_BIT,
	GTP_FL_STARTING_BIT,
	GTP_FL_STOPPING_BIT,
	GTP_FL_HASHED_BIT,
	GTP_FL_CTL_BIT,
	GTP_FL_UPF_BIT,
	GTP_FL_FORCE_PGW_BIT,
	GTP_FL_IPTNL_BIT,
	GTP_FL_DIRECT_TX_BIT,
	GTP_FL_SESSION_EXPIRATION_DELETE_TO_BIT,
	GTP_FL_GTPC_INGRESS_BIT,
	GTP_FL_GTPC_EGRESS_BIT,
	GTP_FL_GTPU_INGRESS_BIT,
	GTP_FL_GTPU_EGRESS_BIT,
};

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
#define GTP_REMOTE_UE_REPORT_NOTIFICATION		40
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
#define GTP_DELETE_PDN_CONNECTION_SET_REQUEST		101
#define GTP_SUSPEND_NOTIFICATION			162
#define GTP_UPDATE_PDN_CONNECTION_SET_REQUEST		200
#define GTP_UPDATE_PDN_CONNECTION_SET_RESPONSE		201

/* GTP-C Cause */
#define GTP_CAUSE_REQUEST_ACCEPTED			16
#define GTP_CAUSE_CONTEXT_NOT_FOUND			64
#define GTP_CAUSE_MISSING_OR_UNKNOWN_APN		78
#define GTP_CAUSE_ALL_DYNAMIC_ADDRESS_OCCUPIED		84
#define GTP_CAUSE_USER_AUTH_FAILED			92
#define GTP_CAUSE_APN_ACCESS_DENIED			93
#define GTP_CAUSE_REQUEST_REJECTED			94
#define GTP_CAUSE_IMSI_IMEI_NOT_KNOWN			96
#define GTP_CAUSE_INVALID_PEER				109
#define GTP_CAUSE_APN_CONGESTION			113
#define GTP_CAUSE_MULTIPLE_PDN_NOT_ALLOWED		116
#define GTP_CAUSE_TIMED_OUT_REQUEST			122
#define GTP_CAUSE_5GC_NOT_ALLOWED			129
#define GTP1_CAUSE_REQUEST_ACCEPTED			128
#define GTP1_CAUSE_NON_EXISTENT				192

/* GTP-C PDN Type */
#define GTP_FL_PDN_IPV4					(1 << 0)
#define GTP_FL_PDN_IPV6					(1 << 1)

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
struct gtp1_ie {
	uint8_t		type;
	uint16_t	length;
} __attribute__((packed));

#define GTP1_IE_CAUSE_TYPE				1
struct gtp1_ie_cause {
	uint8_t		type;
	uint8_t		value;
} __attribute__((packed));

#define GTP1_IE_IMSI_TYPE				2
struct gtp1_ie_imsi {
	uint8_t		type;
	uint8_t		imsi[8];
} __attribute__((packed));

#define GTP1_IE_RAI_TYPE				3
struct gtp1_ie_rai {
	uint8_t		type;
	uint8_t		plmn[3];
	uint16_t	lac;
	uint8_t		rac;
} __attribute__((packed));

#define GTP1_IE_RECOVERY_TYPE				14
struct gtp1_ie_recovery {
	uint8_t		type;
	uint8_t		recovery;
} __attribute__((packed));

#define GTP1_IE_TEID_DATA_TYPE				16
#define GTP1_IE_TEID_CONTROL_TYPE			17
struct gtp1_ie_teid {
	uint8_t		type;
	uint32_t	id;
} __attribute__((packed));

#define GTP1_IE_APN_TYPE				131
struct gtp1_ie_apn {
	struct gtp1_ie	h;
	uint8_t		apn[64];
} __attribute__((packed));

#define GTP1_IE_GSN_ADDRESS_TYPE			133
struct gtp1_ie_gsn_address {
	struct gtp1_ie	h;
	uint32_t	ipv4;
} __attribute__((packed));

#define GTP1_IE_QOS_PROFILE_TYPE			135
struct gtp1_ie_qos_profile {
	struct gtp1_ie	h;
	uint8_t		arp;
} __attribute__((packed));

#define GTP1_IE_ULI_TYPE				152
struct gtp1_ie_uli {
	struct gtp1_ie	h;
	uint8_t		geographic_location_type;
	uint8_t		mcc_mnc[3];
	union {
		struct {
			uint16_t	lac;
			uint16_t	ci;
		} cgi;
		struct {
			uint16_t	lac;
			uint16_t	sac;
		} sai;
		struct {
			uint16_t	lac;
			uint16_t	rac;
		} rai;
		uint32_t		value;
	} u;
} __attribute__((packed));
#define GTP1_ULI_GEOGRAPHIC_LOCATION_TYPE_CGI	0
#define GTP1_ULI_GEOGRAPHIC_LOCATION_TYPE_SAI	(1 << 0)
#define GTP1_ULI_GEOGRAPHIC_LOCATION_TYPE_RAI	(1 << 1)


/*
 *	GTPv2 IE
 */
struct gtpu_ie {
	uint8_t		type;
	uint16_t	length;
} __attribute__((packed));

struct gtpu_ie_private {
	uint8_t		type;
	uint16_t	id;
} __attribute__((packed));

struct gtp_ie {
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
} __attribute__((packed));

#define GTP_IE_IMSI_TYPE				1
struct gtp_ie_imsi {
	struct gtp_ie	h;
	uint8_t		imsi[8];
} __attribute__((packed));

#define GTP_IE_CAUSE_TYPE				2
struct gtp_ie_cause {
	struct gtp_ie	h;
	uint8_t		value;
	uint8_t		spare;
} __attribute__((packed));

#define GTP_IE_RECOVERY_TYPE				3
struct gtp_ie_recovery {
	struct gtp_ie	h;
	uint8_t		recovery;
} __attribute__((packed));

#define GTP_IE_APN_TYPE					71
struct gtp_ie_apn {
	struct gtp_ie	h;
	uint8_t		apn[64];
} __attribute__((packed));

#define GTP_IE_MEI_TYPE					75
struct gtp_ie_mei {
	struct gtp_ie	h;
	uint8_t		mei[8];
} __attribute__((packed));

#define GTP_IE_MSISDN_TYPE				76
struct gtp_ie_msisdn {
	struct gtp_ie	h;
	uint8_t		msisdn[6];
} __attribute__((packed));

#define GTP_IE_INDICATION_TYPE				77
struct gtp_ie_indication {
	struct gtp_ie	h;
	uint32_t	bits;
} __attribute__((packed));

#define GTP_IE_PCO_TYPE					78
struct gtp_ie_pco {
	struct gtp_ie	h;
	uint8_t		ext;
} __attribute__((packed));

/* PPP Protocol or Container ID */
#define GTP_PCO_PID_IPCP	0x8021
#define GTP_PCO_PID_DNS		0x000d
#define GTP_PCO_PID_SBCM	0x0005
#define GTP_PCO_PID_MTU		0x0010
struct gtp_pco_pid {
	uint16_t	type;
	uint8_t		length;
} __attribute__((packed));

#define PPP_CONF_NAK		0x03
struct gtp_pco_pid_ipcp {
	struct gtp_pco_pid h;
	uint8_t		code;
	uint8_t		id;
	uint16_t	length;
} __attribute__((packed));

#define PPP_IPCP_PRIMARY_NS		0x81
#define PPP_IPCP_SECONDARY_NS		0x83
struct gtp_ppp_ipcp_option_ip4 {
	uint8_t		type;
	uint8_t		length;
	uint32_t	addr;
} __attribute__((packed));

struct gtp_pco_pid_dns {
	struct gtp_pco_pid h;
	uint32_t	addr;
} __attribute__((packed));

struct gtp_pco_pid_mtu {
	struct gtp_pco_pid h;
	uint16_t	mtu;
} __attribute__((packed));

struct gtp_pco_pid_sbcm {
	struct gtp_pco_pid h;
	uint8_t		sbcm;
} __attribute__((packed));


#define GTP_IE_F_TEID_TYPE				87
struct gtp_ie_f_teid {
	struct gtp_ie			h;
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
} __attribute__((packed));
#define GTP_TEID_INTERFACE_TYPE_SGW_GTPU	5
#define GTP_TEID_INTERFACE_TYPE_SGW_GTPC	7

#define GTP_IE_AMBR_TYPE				72
struct gtp_ie_ambr {
	struct gtp_ie	h;
	uint32_t	uplink;
	uint32_t	downlink;
} __attribute__((packed));

#define GTP_IE_EPS_BEARER_ID_TYPE			73
struct gtp_ie_eps_bearer_id {
	struct gtp_ie	h;
	uint8_t		id;
} __attribute__((packed));

#define GTP_IE_PAA_TYPE					79
struct gtp_ie_paa {
	struct gtp_ie	h;
	uint8_t		type;
	uint32_t	addr;
} __attribute__((packed));
#define GTP_PAA_IPV4_TYPE	1

#define GTP_IE_RAT_TYPE_TYPE				82
struct gtp_ie_rat_type {
	struct gtp_ie	h;
	uint8_t		mcc_mnc[3];
} __attribute__((packed));

#define GTP_IE_SERVING_NETWORK_TYPE			83
struct gtp_ie_serving_network {
	struct gtp_ie	h;
	uint8_t		mcc_mnc[3];
} __attribute__((packed));

#define GTP_IE_ULI_TYPE					86
struct gtp_ie_uli {
	struct gtp_ie	h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t		cgi:1;
	uint8_t		sai:1;
	uint8_t		rai:1;
	uint8_t		tai:1;
	uint8_t		ecgi:1;
	uint8_t		lai:1;
	uint8_t		macro_enbid:1;
	uint8_t		extended_macro_enbid:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		extended_macro_enbid:1;
	uint8_t		macro_enbid:1;
	uint8_t		lai:1;
	uint8_t		ecgi:1;
	uint8_t		tai:1;
	uint8_t		rai:1;
	uint8_t		sai:1;
	uint8_t		cgi:1;
#else
# error "Please fix <bits/endian.h>"
#endif
	/* Grouped identities in following order according
	 * to presence in previous bitfield:
	 * CGI / SAI / RAI / TAI / ECGI / LAI / MacroeNBID / extMacroeNBID */
} __attribute__((packed));

struct gtp_id_cgi {
	uint8_t		mcc_mnc[3];
	uint16_t	lac;
	uint16_t	ci;
} __attribute__((packed));

struct gtp_id_sai {
	uint8_t		mcc_mnc[3];
	uint16_t	lac;
	uint16_t	sac;
} __attribute__((packed));

struct gtp_id_rai {
	uint8_t		mcc_mnc[3];
	uint16_t	lac;
	uint8_t		rac;
	uint8_t		spare;
} __attribute__((packed));

struct gtp_id_tai {
	uint8_t		mcc_mnc[3];
	uint16_t	tac;
} __attribute__((packed));

struct gtp_ecgi {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t	cellid:8;
	uint32_t	enbid:20;
	uint32_t	spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t	spare:4;
	uint32_t	enbid:20;
	uint32_t	cellid:8;
#else
# error "Please fix <bits/endian.h>"
#endif
} __attribute__((packed));

struct gtp_id_ecgi {
	uint8_t			mcc_mnc[3];
	union {
		struct gtp_ecgi	ecgi;
		uint32_t	value;
	} u;
} __attribute__((packed));

struct gtp_id_lai {
	uint8_t		mcc_mnc[3];
	uint16_t	lac;
} __attribute__((packed));

#define GTP_IE_BEARER_CONTEXT_TYPE			93
struct gtp_ie_bearer_context {
	struct gtp_ie	h;
	/* Grouped IE here */
} __attribute__((packed));

#define GTP_IE_CHARGING_ID_TYPE				94
struct gtp_ie_charging_id {
	struct gtp_ie	h;
	uint32_t	id;
} __attribute__((packed));

#define GTP_IE_PDN_TYPE					99
struct gtp_ie_pdn_type {
	struct gtp_ie	h;
	uint8_t		pdn_type;
} __attribute__((packed));

#define GTP_IE_APN_RESTRICTION_TYPE			127
struct gtp_ie_apn_restriction {
	struct gtp_ie	h;
	uint8_t		value;
} __attribute__((packed));


/*
 *	GTP Protocol headers
 */
struct gtp_hdr {
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
} __attribute__((packed));


struct gtp1_hdr {
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
} __attribute__((packed));
