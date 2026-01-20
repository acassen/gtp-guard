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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <endian.h>

#include "pfcp_metrics.h"
#include "pkt_buffer.h"

/*
 * PFCP (Packet Forwarding Control Protocol) Information Elements
 * Based on 3GPP TS 29.244 8.2
 */

/* PFCP IE Types */
enum pfcp_ie_type {
	/* Elementary IEs */
	PFCP_IE_PDI				= 2,
	PFCP_IE_CAUSE				= 19,
	PFCP_IE_SOURCE_INTERFACE		= 20,
	PFCP_IE_F_TEID				= 21,
	PFCP_IE_NETWORK_INSTANCE		= 22,
	PFCP_IE_SDF_FILTER			= 23,
	PFCP_IE_APPLICATION_ID			= 24,
	PFCP_IE_GATE_STATUS			= 25,
	PFCP_IE_MBR				= 26,
	PFCP_IE_GBR				= 27,
	PFCP_IE_QER_CORRELATION_ID		= 28,
	PFCP_IE_PRECEDENCE			= 29,
	PFCP_IE_TRANSPORT_LEVEL_MARKING		= 30,
	PFCP_IE_VOLUME_THRESHOLD		= 31,
	PFCP_IE_TIME_THRESHOLD			= 32,
	PFCP_IE_MONITORING_TIME			= 33,
	PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD	= 34,
	PFCP_IE_SUBSEQUENT_TIME_THRESHOLD	= 35,
	PFCP_IE_INACTIVITY_DETECTION_TIME	= 36,
	PFCP_IE_REPORTING_TRIGGERS		= 37,
	PFCP_IE_REDIRECT_INFORMATION		= 38,
	PFCP_IE_REPORT_TYPE			= 39,
	PFCP_IE_OFFENDING_IE			= 40,
	PFCP_IE_FORWARDING_POLICY		= 41,
	PFCP_IE_DESTINATION_INTERFACE		= 42,
	PFCP_IE_UP_FUNCTION_FEATURES		= 43,
	PFCP_IE_APPLY_ACTION			= 44,
	PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION = 45,
	PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY = 46,
	PFCP_IE_DL_BUFFERING_DURATION		= 47,
	PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT = 48,
	PFCP_IE_PFCPSMREQ_FLAGS			= 49,
	PFCP_IE_PFCPSRRSP_FLAGS			= 50,
	PFCP_IE_SEQUENCE_NUMBER			= 52,
	PFCP_IE_METRIC				= 53,
	PFCP_IE_TIMER				= 55,
	PFCP_IE_PDR_ID				= 56,
	PFCP_IE_F_SEID				= 57,
	PFCP_IE_NODE_ID				= 60,
	PFCP_IE_PFD_CONTENTS			= 61,
	PFCP_IE_MEASUREMENT_METHOD		= 62,
	PFCP_IE_USAGE_REPORT_TRIGGER		= 63,
	PFCP_IE_MEASUREMENT_PERIOD		= 64,
	PFCP_IE_FQ_CSID				= 65,
	PFCP_IE_VOLUME_MEASUREMENT		= 66,
	PFCP_IE_DURATION_MEASUREMENT		= 67,
	PFCP_IE_TIME_OF_FIRST_PACKET		= 69,
	PFCP_IE_TIME_OF_LAST_PACKET		= 70,
	PFCP_IE_QUOTA_HOLDING_TIME		= 71,
	PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD	= 72,
	PFCP_IE_VOLUME_QUOTA			= 73,
	PFCP_IE_TIME_QUOTA			= 74,
	PFCP_IE_START_TIME			= 75,
	PFCP_IE_END_TIME			= 76,
	PFCP_IE_URR_ID				= 81,
	PFCP_IE_LINKED_URR_ID			= 82,
	PFCP_IE_OUTER_HEADER_CREATION		= 84,
	PFCP_IE_BAR_ID				= 88,
	PFCP_IE_CP_FUNCTION_FEATURES		= 89,
	PFCP_IE_USAGE_INFORMATION		= 90,
	PFCP_IE_APPLICATION_INSTANCE_ID		= 91,
	PFCP_IE_FLOW_INFORMATION		= 92,
	PFCP_IE_UE_IP_ADDRESS			= 93,
	PFCP_IE_PACKET_RATE			= 94,
	PFCP_IE_OUTER_HEADER_REMOVAL		= 95,
	PFCP_IE_RECOVERY_TIME_STAMP		= 96,
	PFCP_IE_DL_FLOW_LEVEL_MARKING		= 97,
	PFCP_IE_HEADER_ENRICHMENT		= 98,
	PFCP_IE_MEASUREMENT_INFORMATION		= 100,
	PFCP_IE_NODE_REPORT_TYPE		= 101,
	PFCP_IE_REMOTE_GTP_U_PEER		= 103,
	PFCP_IE_UR_SEQN				= 104,
	PFCP_IE_ACTIVATE_PREDEFINED_RULES	= 106,
	PFCP_IE_DEACTIVATE_PREDEFINED_RULES	= 107,
	PFCP_IE_FAR_ID				= 108,
	PFCP_IE_QER_ID				= 109,
	PFCP_IE_OCI_FLAGS			= 110,
	PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST = 111,
	PFCP_IE_GRACEFUL_RELEASE_PERIOD		= 112,
	PFCP_IE_PDN_TYPE			= 113,
	PFCP_IE_FAILED_RULE_ID			= 114,
	PFCP_IE_TIME_QUOTA_MECHANISM		= 115,
	PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION = 116,
	PFCP_IE_USER_PLANE_INACTIVITY_TIMER	= 117,
	PFCP_IE_MULTIPLIER			= 119,
	PFCP_IE_AGGREGATED_URR_ID		= 120,
	PFCP_IE_SUBSEQUENT_VOLUME_QUOTA		= 121,
	PFCP_IE_SUBSEQUENT_TIME_QUOTA		= 122,
	PFCP_IE_RQI				= 123,
	PFCP_IE_QFI				= 124,
	PFCP_IE_QUERY_URR_REFERENCE		= 125,
	PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION = 126,
	PFCP_IE_TRAFFIC_ENDPOINT_ID		= 131,
	PFCP_IE_MAC_ADDRESS			= 133,
	PFCP_IE_C_TAG				= 134,
	PFCP_IE_S_TAG				= 135,
	PFCP_IE_ETHERTYPE			= 136,
	PFCP_IE_PROXYING			= 137,
	PFCP_IE_ETHERNET_FILTER_ID		= 138,
	PFCP_IE_ETHERNET_FILTER_PROPERTIES	= 139,
	PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT = 140,
	PFCP_IE_USER_ID				= 141,
	PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION = 142,
	PFCP_IE_MAC_ADDRESSES_DETECTED		= 144,
	PFCP_IE_MAC_ADDRESSES_REMOVED		= 145,
	PFCP_IE_ETHERNET_INACTIVITY_TIMER	= 146,
	PFCP_IE_EVENT_QUOTA			= 148,
	PFCP_IE_EVENT_THRESHOLD			= 149,
	PFCP_IE_SUBSEQUENT_EVENT_QUOTA		= 150,
	PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD	= 151,
	PFCP_IE_TRACE_INFORMATION		= 152,
	PFCP_IE_FRAMED_ROUTE			= 153,
	PFCP_IE_FRAMED_ROUTING			= 154,
	PFCP_IE_FRAMED_IPV6_ROUTE		= 155,
	PFCP_IE_TIME_STAMP			= 156,
	PFCP_IE_AVERAGING_WINDOW		= 157,
	PFCP_IE_PPI				= 158,
	PFCP_IE_APN_DNN				= 159,
	PFCP_IE_3GPP_INTERFACE_TYPE		= 160,
	PFCP_IE_PFCPSRREQ_FLAGS			= 161,
	PFCP_IE_PFCPAUREQ_FLAGS			= 162,
	PFCP_IE_ACTIVATION_TIME			= 163,
	PFCP_IE_DEACTIVATION_TIME		= 164,
	PFCP_IE_MAR_ID				= 170,
	PFCP_IE_STEERING_FUNCTIONALITY		= 171,
	PFCP_IE_STEERING_MODE			= 172,
	PFCP_IE_WEIGHT				= 173,
	PFCP_IE_PRIORITY			= 174,
	PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY	= 177,
	PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS	= 178,
	PFCP_IE_PKT_REPLICATION_AND_DETECTION_CARRY_ON_INFORMATION = 179,
	PFCP_IE_SMF_SET_ID			= 180,
	PFCP_IE_QUOTA_VALIDITY_TIME		= 181,
	PFCP_IE_NUMBER_OF_REPORTS		= 182,
	PFCP_IE_PFCPASRSP_FLAGS			= 184,
	PFCP_IE_CP_PFCP_ENTITY_IP_ADDRESS	= 185,
	PFCP_IE_PFCPSEREQ_FLAGS			= 186,
	PFCP_IE_IP_MULTICAST_ADDRESS		= 191,
	PFCP_IE_SOURCE_IP_ADDRESS		= 192,
	PFCP_IE_PACKET_RATE_STATUS		= 193,
	PFCP_IE_CREATE_BRIDGE_ROUTER_INFO	= 194,
	PFCP_IE_DS_TT_PORT_NUMBER		= 196,
	PFCP_IE_NW_TT_PORT_NUMBER		= 197,
	PFCP_IE_5GS_USER_PLANE_NODE		= 198,
	PFCP_IE_PORT_MANAGEMENT_INFORMATION_CONTAINER = 202,
	PFCP_IE_REQUESTED_CLOCK_DRIFT_INFORMATION = 204,
	PFCP_IE_TIME_DOMAIN_NUMBER		= 206,
	PFCP_IE_TIME_OFFSET_THRESHOLD		= 207,
	PFCP_IE_CUMULATIVE_RATERATIO_THRESHOLD	= 208,
	PFCP_IE_TIME_OFFSET_MEASUREMENT		= 209,
	PFCP_IE_CUMULATIVE_RATERATIO_MEASUREMENT = 210,
	PFCP_IE_SRR_ID				= 215,
	PFCP_IE_REQUESTED_ACCESS_AVAILABILITY_INFORMATION = 217,
	PFCP_IE_ACCESS_AVAILABILITY_REPORT	= 218,
	PFCP_IE_ACCESS_AVAILABILITY_INFORMATION	= 219,
	PFCP_IE_MPTCP_CONTROL_INFORMATION	= 222,
	PFCP_IE_ATSSS_LL_CONTROL_INFORMATION	= 223,
	PFCP_IE_PMF_CONTROL_INFORMATION		= 224,
	PFCP_IE_MPTCP_ADDRESS_INFORMATION	= 228,
	PFCP_IE_UE_LINK_SPECIFIC_IP_ADDRESS	= 229,
	PFCP_IE_PMF_ADDRESS_INFORMATION		= 230,
	PFCP_IE_ATSSS_LL_INFORMATION		= 231,
	PFCP_IE_DATA_NETWORK_ACCESS_IDENTIFIER	= 232,
	PFCP_IE_AVERAGE_PACKET_DELAY		= 234,
	PFCP_IE_MINIMUM_PACKET_DELAY		= 235,
	PFCP_IE_MAXIMUM_PACKET_DELAY		= 236,
	PFCP_IE_QOS_REPORT_TRIGGER		= 237,
	PFCP_IE_GTP_U_PATH_INTERFACE_TYPE	= 241,
	PFCP_IE_REQUESTED_QOS_MONITORING	= 243,
	PFCP_IE_REPORTING_FREQUENCY		= 244,
	PFCP_IE_PACKET_DELAY_THRESHOLDS		= 245,
	PFCP_IE_MINIMUM_WAIT_TIME		= 246,
	PFCP_IE_QOS_MONITORING_MEASUREMENT	= 248,
	PFCP_IE_MT_EDT_CONTROL_INFORMATION	= 249,
	PFCP_IE_DL_DATA_PACKETS_SIZE		= 250,
	PFCP_IE_QER_CONTROL_INDICATIONS		= 251,
	PFCP_IE_NF_INSTANCE_ID			= 253,
	PFCP_IE_S_NSSAI				= 257,
	PFCP_IE_IP_VERSION			= 258,
	PFCP_IE_PFCPASREQ_FLAGS			= 259,
	PFCP_IE_DATA_STATUS			= 260,
	PFCP_IE_RDS_CONFIGURATION_INFORMATION	= 262,
	PFCP_IE_MPTCP_APPLICABLE_INDICATION	= 265,
	PFCP_IE_BRIDGE_MANAGEMENT_INFORMATION_CONTAINER	= 266,
	PFCP_IE_NUMBER_OF_UE_IP_ADDRESSES	= 268,
	PFCP_IE_VALIDITY_TIMER			= 269,
	PFCP_IE_OFFENDING_IE_INFORMATION	= 274,
	PFCP_IE_RAT_TYPE			= 275,
	PFCP_IE_TUNNEL_PREFERENCE		= 281,
	PFCP_IE_CALLING_NUMBER			= 282,
	PFCP_IE_CALLED_NUMBER			= 283,
	PFCP_IE_DNS_SERVER_ADDRESS		= 285,
	PFCP_IE_NBNS_SERVER_ADDRESS		= 286,
	PFCP_IE_MAXIMUM_RECEIVE_UNIT		= 287,
	PFCP_IE_THRESHOLDS			= 288,
	PFCP_IE_STEERING_MODE_INDICATOR		= 289,
	PFCP_IE_GROUP_ID			= 291,
	PFCP_IE_CP_IP_ADDRESS			= 292,
	PFCP_IE_IP_ADDRESS_AND_PORT_NUMBER_REPLACEMENT = 293,
	PFCP_IE_DNS_QUERY_FILTER		= 294,
	PFCP_IE_EVENT_NOTIFICATION_URI		= 296,
	PFCP_IE_NOTIFICATION_CORRELATION_ID	= 297,
	PFCP_IE_REPORTING_FLAGS			= 298,
	PFCP_IE_PREDEFINED_RULES_NAME		= 299,
	PFCP_IE_LOCAL_INGRESS_TUNNEL		= 308,
	PFCP_IE_AREA_SESSION_ID			= 314,
	PFCP_IE_PFCPSDRSP_FLAGS			= 318,
	PFCP_IE_QER_INDICATIONS			= 319,
	PFCP_IE_VENDOR_SPECIFIC_NODE_REPORT_TYPE = 320,
	PFCP_IE_CONFIGURED_TIME_DOMAIN		= 321,
	PFCP_IE_TL_CONTAINER			= 336,

	/* Grouped IEs */
	PFCP_IE_CREATE_PDR			= 1,
	PFCP_IE_PDR				= 2,
	PFCP_IE_CREATE_FAR			= 3,
	PFCP_IE_FORWARDING_PARAMETERS		= 4,
	PFCP_IE_DUPLICATING_PARAMETERS		= 5,
	PFCP_IE_CREATE_URR			= 6,
	PFCP_IE_CREATE_QER			= 7,
	PFCP_IE_CREATED_PDR			= 8,
	PFCP_IE_UPDATE_PDR			= 9,
	PFCP_IE_UPDATE_FAR			= 10,
	PFCP_IE_UPDATE_FORWARDING_PARAMETERS	= 11,
	PFCP_IE_UPDATE_BAR_REPORT		= 12,
	PFCP_IE_UPDATE_URR			= 13,
	PFCP_IE_UPDATE_QER			= 14,
	PFCP_IE_REMOVE_PDR			= 15,
	PFCP_IE_REMOVE_FAR			= 16,
	PFCP_IE_REMOVE_URR			= 17,
	PFCP_IE_REMOVE_QER			= 18,
	PFCP_IE_LOAD_CONTROL_INFORMATION	= 51,
	PFCP_IE_OVERLOAD_CONTROL_INFORMATION	= 54,
	PFCP_IE_APPLICATION_ID_PFDS		= 58,
	PFCP_IE_PFD_CONTEXT			= 59,
	PFCP_IE_APPLICATION_DETECTION_INFORMATION = 68,
	PFCP_IE_QUERY_URR			= 77,
	PFCP_IE_USAGE_REPORT_MODIFICATION	= 78,
	PFCP_IE_USAGE_REPORT_DELETION		= 79,
	PFCP_IE_USAGE_REPORT			= 80,
	PFCP_IE_DOWNLINK_DATA_REPORT		= 83,
	PFCP_IE_CREATE_BAR			= 85,
	PFCP_IE_UPDATE_BAR			= 86,
	PFCP_IE_REMOVE_BAR			= 87,
	PFCP_IE_ERROR_INDICATION_REPORT		= 99,
	PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT	= 102,
	PFCP_IE_UPDATE_DUPLICATING_PARAMETERS	= 105,
	PFCP_IE_AGGREGATED_URRS			= 118,
	PFCP_IE_ADDITIONAL_USAGE_REPORT_INFORMATION = 126,
	PFCP_IE_CREATE_TRAFFIC_ENDPOINT		= 127,
	PFCP_IE_CREATED_TRAFFIC_ENDPOINT	= 128,
	PFCP_IE_UPDATE_TRAFFIC_ENDPOINT		= 129,
	PFCP_IE_REMOVE_TRAFFIC_ENDPOINT		= 130,
	PFCP_IE_ETHERNET_PACKET_FILTER		= 132,
	PFCP_IE_ETHERNET_TRAFFIC_INFORMATION	= 143,
	PFCP_IE_ADDITIONAL_MONITORING_TIME	= 147,
	PFCP_IE_CREATE_MAR			= 165,
	PFCP_IE_REMOVE_MAR			= 168,
	PFCP_IE_UPDATE_MAR			= 169,
	PFCP_IE_SESSION_RETENTION_INFORMATION	= 183,
	PFCP_IE_USER_PLANE_PATH_RECOVERY_REPORT	= 187,
	PFCP_IE_CLOCK_DRIFT_CONTROL_INFORMATION	= 203,
	PFCP_IE_REMOVE_SRR			= 211,
	PFCP_IE_CREATE_SRR			= 212,
	PFCP_IE_UPDATE_SRR			= 213,
	PFCP_IE_SESSION_REPORT			= 214,
	PFCP_IE_REDUNDANT_TRANSMISSION_DETECTION_PARAMETERS = 255,
	PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION	= 233,
	PFCP_IE_GTP_U_PATH_QOS_CONTROL_INFORMATION = 238,
	PFCP_IE_PACKET_RATE_STATUS_REPORT	= 252,
	PFCP_IE_UE_IP_ADDRESS_USAGE_INFORMATION	= 267,
	PFCP_IE_PARTIAL_FAILURE_INFORMATION	= 272,
	PFCP_IE_SESSION_CHANGE_INFO		= 290,
	PFCP_IE_PEER_UP_RESTART_REPORT		= 315,
};

/* Common IE header */
struct pfcp_ie {
	uint16_t type;
	uint16_t length;
} __attribute__((packed));

/* Cause IE */
struct pfcp_ie_cause {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Source Interface IE */
#define PFCP_SRC_INTERFACE_TYPE_ACCESS	0
#define PFCP_SRC_INTERFACE_TYPE_CORE	1
#define PFCP_SRC_INTERFACE_TYPE_SGI	2
#define PFCP_SRC_INTERFACE_TYPE_CP	3
#define PFCP_SRC_INTERFACE_TYPE_5GVN	4
struct pfcp_ie_source_interface {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* F-TEID IE */
struct pfcp_ie_f_teid {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t ch:1;
			uint8_t chid:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:3;
			uint8_t chid:1;
			uint8_t ch:1;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		} __attribute__((packed));
	};
	union {
		struct {
			uint32_t teid;
			union {
				struct in_addr v4;
				struct in6_addr v6;
				struct {
					struct in_addr v4;
					struct in6_addr v6;
				} both;
			} ip;
		} s;
		uint8_t choose_id;
	};
} __attribute__((packed));

/* Network Instance IE */
struct pfcp_ie_network_instance {
	struct pfcp_ie h;
	uint8_t network_instance[];
} __attribute__((packed));

/* SDF Filter IE */
struct pfcp_ie_sdf_filter {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t fd:1;
			uint8_t ttc:1;
			uint8_t spi:1;
			uint8_t fl:1;
			uint8_t bid:1;
			uint8_t spare:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:3;
			uint8_t bid:1;
			uint8_t fl:1;
			uint8_t spi:1;
			uint8_t ttc:1;
			uint8_t fd:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t flow_description[];
} __attribute__((packed));

/* Application ID IE */
struct pfcp_ie_application_id {
	struct pfcp_ie h;
	uint8_t id[];
} __attribute__((packed));

/* Gate Status IE */
struct pfcp_ie_gate_status {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t dl_gate:2;
	uint8_t ul_gate:2;
	uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t spare:4;
	uint8_t ul_gate:2;
	uint8_t dl_gate:2;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	uint8_t value[];
} __attribute__((packed));

/* MBR IE */
struct pfcp_ie_mbr {
	struct pfcp_ie h;
	uint8_t h_ul_mbr;
	uint32_t ul_mbr;
	uint8_t h_dl_mbr;
	uint32_t dl_mbr;
} __attribute__((packed));

/* GBR IE */
struct pfcp_ie_gbr {
	struct pfcp_ie h;
	uint64_t ul_gbr;
	uint64_t dl_gbr;
} __attribute__((packed));

/* QER Correlation ID IE */
struct pfcp_ie_qer_correlation_id {
	struct pfcp_ie h;
	uint32_t qer_correlation_id;
} __attribute__((packed));

/* Precedence IE */
struct pfcp_ie_precedence {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Transport Level Marking IE */
struct pfcp_ie_transport_level_marking {
	struct pfcp_ie h;
	uint16_t traffic_class;
} __attribute__((packed));

/* Volume Threshold IE */
struct pfcp_ie_volume_threshold {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t tovol:1;
			uint8_t ulvol:1;
			uint8_t dlvol:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t dlvol:1;
			uint8_t ulvol:1;
			uint8_t tovol:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint64_t total_volume;
	uint64_t uplink_volume;
	uint64_t downlink_volume;
} __attribute__((packed));

/* Time Threshold IE */
struct pfcp_ie_time_threshold {
	struct pfcp_ie h;
	uint32_t time_threshold;
} __attribute__((packed));

/* Monitoring Time IE */
struct pfcp_ie_monitoring_time {
	struct pfcp_ie h;
	uint32_t monitoring_time;
} __attribute__((packed));

/* Subsequent Volume Threshold IE */
struct pfcp_ie_subsequent_volume_threshold {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t tovol:1;
			uint8_t ulvol:1;
			uint8_t dlvol:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t dlvol:1;
			uint8_t ulvol:1;
			uint8_t tovol:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint64_t total_volume;
	uint64_t uplink_volume;
	uint64_t downlink_volume;
} __attribute__((packed));

/* Subsequent Time Threshold IE */
struct pfcp_ie_subsequent_time_threshold {
	struct pfcp_ie h;
	uint32_t time_threshold;
} __attribute__((packed));

/* Inactivity Detection Time IE */
struct pfcp_ie_inactivity_detection_time {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Reporting Triggers IE */
struct pfcp_ie_reporting_triggers {
	struct pfcp_ie h;
	union {
		uint16_t triggers;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t perio:1;
			uint16_t volth:1;
			uint16_t timth:1;
			uint16_t quhti:1;
			uint16_t start:1;
			uint16_t stopt:1;
			uint16_t droth:1;
			uint16_t liusa:1;
			uint16_t volqu:1;
			uint16_t timqu:1;
			uint16_t envcl:1;
			uint16_t macar:1;
			uint16_t eveth:1;
			uint16_t evequ:1;
			uint16_t ipmjl:1;
			uint16_t quvti:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint16_t quvti:1;
			uint16_t ipmjl:1;
			uint16_t evequ:1;
			uint16_t eveth:1;
			uint16_t macar:1;
			uint16_t envcl:1;
			uint16_t timqu:1;
			uint16_t volqu:1;
			uint16_t liusa:1;
			uint16_t droth:1;
			uint16_t stopt:1;
			uint16_t start:1;
			uint16_t quhti:1;
			uint16_t timth:1;
			uint16_t volth:1;
			uint16_t perio:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Redirect Information IE */
struct pfcp_ie_redirect_information {
	struct pfcp_ie h;
	uint8_t redirect_address_type;
	uint16_t redirect_server_address_length;
	uint8_t redirect_server_address[];
} __attribute__((packed));

/* Report Type IE */
struct pfcp_ie_report_type {
	struct pfcp_ie h;
	union {
		uint8_t report_type;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t dldr:1;
			uint8_t usar:1;
			uint8_t erir:1;
			uint8_t upir:1;
			uint8_t pmir:1;
			uint8_t sesr:1;
			uint8_t uprr:1;
			uint8_t spare:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:1;
			uint8_t uprr:1;
			uint8_t sesr:1;
			uint8_t pmir:1;
			uint8_t upir:1;
			uint8_t erir:1;
			uint8_t usar:1;
			uint8_t dldr:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Offending IE */
struct pfcp_ie_offending {
	struct pfcp_ie h;
	uint16_t type_of_offending_ie;
} __attribute__((packed));

/* Forwarding Policy IE */
struct pfcp_ie_forwarding_policy {
	struct pfcp_ie h;
	uint8_t forwarding_policy_identifier_length;
	uint8_t forwarding_policy_identifier[];
} __attribute__((packed));

/* Destination Interface IE */
struct pfcp_ie_destination_interface {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* UP Function Features IE */
#define TREU	(1 << 7)
#define HEEU	(1 << 6)
#define PFDM	(1 << 5)
#define FTUP	(1 << 4)
#define TRST	(1 << 3)
#define DLBD	(1 << 2)
#define DDND	(1 << 1)
#define BUCP	(1 << 0)

#define EPFAR	(1 << 7)
#define PFDE	(1 << 6)
#define FRRT	(1 << 5)
#define TRACE	(1 << 4)
#define QUOAC	(1 << 3)
#define UDBC	(1 << 2)
#define PDIU	(1 << 1)
#define EMPU	(1 << 0)

#define GCOM	(1 << 7)
#define BUNDL	(1 << 6)
#define MTE	(1 << 5)
#define MNOP	(1 << 4)
#define SSET	(1 << 3)
#define UEIP	(1 << 2)
#define ADPDP	(1 << 1)
#define DPDRA	(1 << 0)

#define MPTCP	(1 << 7)
#define TSCU	(1 << 6)
#define IP6PL	(1 << 5)
#define IPTV	(1 << 4)
#define NORP	(1 << 3)
#define VTIME	(1 << 2)
#define RTTL	(1 << 1)
#define MPAS	(1 << 0)

struct pfcp_ie_up_function_features {
	struct pfcp_ie h;
	union {
		uint8_t feature_flags[4];
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			/* Octet 5 */
			uint8_t bucp:1;
			uint8_t ddnd:1;
			uint8_t dlbd:1;
			uint8_t trst:1;
			uint8_t ftup:1;
			uint8_t pfdm:1;
			uint8_t heeu:1;
			uint8_t treu:1;
			/* Octet 6 */
			uint8_t empu:1;
			uint8_t pdiu:1;
			uint8_t udbc:1;
			uint8_t quoac:1;
			uint8_t trace:1;
			uint8_t frrt:1;
			uint8_t pfde:1;
			uint8_t epfar:1;
			/* Octet 7 */
			uint8_t dpdra:1;
			uint8_t adpdp:1;
			uint8_t ueip:1;
			uint8_t sset:1;
			uint8_t mnop:1;
			uint8_t mte:1;
			uint8_t bundl:1;
			uint8_t gcom:1;
			/* Octet 8 */
			uint8_t mpas:1;
			uint8_t rttl:1;
			uint8_t vtime:1;
			uint8_t norp:1;
			uint8_t iptv:1;
			uint8_t ip6pl:1;
			uint8_t tscu:1;
			uint8_t mptcp:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			/* Octet 5 */
			uint8_t treu:1;
			uint8_t heeu:1;
			uint8_t pfdm:1;
			uint8_t ftup:1;
			uint8_t trst:1;
			uint8_t dlbd:1;
			uint8_t ddnd:1;
			uint8_t bucp:1;
			/* Octet 6 */
			uint8_t epfar:1;
			uint8_t pfde:1;
			uint8_t frrt:1;
			uint8_t trace:1;
			uint8_t quoac:1;
			uint8_t udbc:1;
			uint8_t pdiu:1;
			uint8_t empu:1;
			/* Octet 7 */
			uint8_t gcom:1;
			uint8_t bundl:1;
			uint8_t mte:1;
			uint8_t mnop:1;
			uint8_t sset:1;
			uint8_t ueip:1;
			uint8_t adpdp:1;
			uint8_t dpdra:1;
			/* Octet 8 */
			uint8_t mptcp:1;
			uint8_t tscu:1;
			uint8_t ip6pl:1;
			uint8_t iptv:1;
			uint8_t norp:1;
			uint8_t vtime:1;
			uint8_t rttl:1;
			uint8_t mpas:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Apply Action IE */
struct pfcp_ie_apply_action {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t drop:1;
			uint8_t forw:1;
			uint8_t buff:1;
			uint8_t nocp:1;
			uint8_t dupl:1;
			uint8_t ipma:1;
			uint8_t ipmd:1;
			uint8_t dfrt:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t dfrt:1;
			uint8_t ipmd:1;
			uint8_t ipma:1;
			uint8_t dupl:1;
			uint8_t nocp:1;
			uint8_t buff:1;
			uint8_t forw:1;
			uint8_t drop:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Downlink Data Service Information IE */
struct pfcp_ie_downlink_data_service_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t ppi:1;
			uint8_t qfii:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t qfii:1;
			uint8_t ppi:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t paging_policy_indication;
	uint8_t qfi;
} __attribute__((packed));

/* Downlink Data Notification Delay IE */
struct pfcp_ie_downlink_data_notification_delay {
	struct pfcp_ie h;
	uint8_t delay_value_in_integer_multiples_of_50_millisecs_or_zero;
} __attribute__((packed));

/* DL Buffering Duration IE */
struct pfcp_ie_dl_buffering_duration {
	struct pfcp_ie h;
	uint8_t timer_unit;
	uint8_t timer_value;
} __attribute__((packed));

/* DL Buffering Suggested Packet Count IE */
struct pfcp_ie_dl_buffering_suggested_packet_count {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* PFCPSMReq-Flags IE */
struct pfcp_ie_pfcpsmreq_flags {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t drobu:1;
			uint8_t sndem:1;
			uint8_t qaurr:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t qaurr:1;
			uint8_t sndem:1;
			uint8_t drobu:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* PFCPSRRsp-Flags IE */
struct pfcp_ie_pfcpsrrsp_flags {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t drobu:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t drobu:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Sequence Number IE */
struct pfcp_ie_sequence_number {
	struct pfcp_ie h;
	uint32_t sequence_number;
} __attribute__((packed));

/* Metric IE */
struct pfcp_ie_metric {
	struct pfcp_ie h;
	uint8_t metric;
} __attribute__((packed));

/* Timer IE */
struct pfcp_ie_timer {
	struct pfcp_ie h;
	uint8_t timer_unit;
	uint8_t timer_value;
} __attribute__((packed));

/* PDR ID IE */
struct pfcp_ie_pdr_id {
	struct pfcp_ie h;
	uint16_t rule_id;
} __attribute__((packed));

/* F-SEID IE */
struct pfcp_ie_f_seid {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v6:1;
			uint8_t v4:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t v4:1;
			uint8_t v6:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint64_t seid;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		struct {
			struct in_addr ipv4;
			struct in6_addr ipv6;
		} both;
	};
} __attribute__((packed));

/* Node ID IE */
#define PFCP_NODE_ID_TYPE_IPV4		0
#define PFCP_NODE_ID_TYPE_IPV6		1
#define PFCP_NODE_ID_TYPE_FQDN		2
#define PFCP_NODE_ID_FQDN_MAX_LEN	128
struct pfcp_ie_node_id {
	struct pfcp_ie h;
	union {
		uint8_t node_id_type;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t type:4;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t type:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		uint8_t fqdn[PFCP_NODE_ID_FQDN_MAX_LEN];
	};
} __attribute__((packed));

/* PFD Contents IE */
struct pfcp_ie_pfd_contents {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t fd:1;
			uint8_t url:1;
			uint8_t dn:1;
			uint8_t cp:1;
			uint8_t dnp:1;
			uint8_t afd:1;
			uint8_t aurl:1;
			uint8_t adn:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t adn:1;
			uint8_t aurl:1;
			uint8_t afd:1;
			uint8_t dnp:1;
			uint8_t cp:1;
			uint8_t dn:1;
			uint8_t url:1;
			uint8_t fd:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t contents[];
} __attribute__((packed));

/* Measurement Method IE */
struct pfcp_ie_measurement_method {
	struct pfcp_ie h;
	union {
		uint8_t measurement_method;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t durat:1;
			uint8_t volum:1;
			uint8_t event:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t event:1;
			uint8_t volum:1;
			uint8_t durat:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Usage Report Trigger IE */
struct pfcp_ie_usage_report_trigger {
	struct pfcp_ie h;
	union {
		uint16_t trigger_flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t perio:1;
			uint16_t volth:1;
			uint16_t timth:1;
			uint16_t quhti:1;
			uint16_t start:1;
			uint16_t stopt:1;
			uint16_t droth:1;
			uint16_t immer:1;
			uint16_t volqu:1;
			uint16_t timqu:1;
			uint16_t liusa:1;
			uint16_t termr:1;
			uint16_t monit:1;
			uint16_t envcl:1;
			uint16_t macar:1;
			uint16_t eveth:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint16_t eveth:1;
			uint16_t macar:1;
			uint16_t envcl:1;
			uint16_t monit:1;
			uint16_t termr:1;
			uint16_t liusa:1;
			uint16_t timqu:1;
			uint16_t volqu:1;
			uint16_t immer:1;
			uint16_t droth:1;
			uint16_t stopt:1;
			uint16_t start:1;
			uint16_t quhti:1;
			uint16_t timth:1;
			uint16_t volth:1;
			uint16_t perio:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Measurement Period IE */
struct pfcp_ie_measurement_period {
	struct pfcp_ie h;
	uint32_t measurement_period;
} __attribute__((packed));

/* Fully qualified PDN Connection Set Identifier IE */
struct pfcp_ie_fq_csid {
	struct pfcp_ie h;
	union {
		uint8_t node_id_type;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t num_csid:4;
			uint8_t ntype:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t ntype:4;
			uint8_t num_csid:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr ipv4_address;
		struct in6_addr ipv6_address;
		uint32_t mcc_mnc_encoded;
	} node_address;
	uint16_t csid[];
} __attribute__((packed));

/* Volume Measurement IE */
struct pfcp_ie_volume_measurement {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t tovol:1;
			uint8_t ulvol:1;
			uint8_t dlvol:1;
			uint8_t tonop:1;
			uint8_t ulnop:1;
			uint8_t dlnop:1;
			uint8_t spare:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:2;
			uint8_t dlnop:1;
			uint8_t ulnop:1;
			uint8_t tonop:1;
			uint8_t dlvol:1;
			uint8_t ulvol:1;
			uint8_t tovol:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint64_t total_volume;
	uint64_t uplink_volume;
	uint64_t downlink_volume;
	uint64_t total_packets;
	uint64_t uplink_packets;
	uint64_t downlink_packets;
} __attribute__((packed));

/* Duration Measurement IE */
struct pfcp_ie_duration_measurement {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Time of First Packet IE */
struct pfcp_ie_time_of_first_packet {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Time of Last Packet IE */
struct pfcp_ie_time_of_last_packet {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Quota Holding Time IE */
struct pfcp_ie_quota_holding_time {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Dropped DL Traffic Threshold IE */
struct pfcp_ie_dropped_dl_traffic_threshold {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t dlpa:1;
			uint8_t dlby:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t dlby:1;
			uint8_t dlpa:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint64_t downlink_packets;
	uint64_t number_of_bytes_of_downlink_data;
} __attribute__((packed));

/* Volume Quota IE */
struct pfcp_ie_volume_quota {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t tovol:1;
			uint8_t ulvol:1;
			uint8_t dlvol:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t dlvol:1;
			uint8_t ulvol:1;
			uint8_t tovol:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint64_t total_volume;
	uint64_t uplink_volume;
	uint64_t downlink_volume;
} __attribute__((packed));

/* Time Quota IE */
struct pfcp_ie_time_quota {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Start Time IE */
struct pfcp_ie_start_time {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* End Time IE */
struct pfcp_ie_end_time {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* URR ID IE */
struct pfcp_ie_urr_id {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Linked URR ID IE */
struct pfcp_ie_linked_urr_id {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Outer Header Creation IE */
#define PFCP_OUTER_HEADER_GTPUV4	0x0100
struct pfcp_ie_outer_header_creation {
	struct pfcp_ie h;
	uint16_t description;
	uint32_t teid;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip_address;
	uint16_t port_number;
	uint32_t c_tag;
	uint32_t s_tag;
} __attribute__((packed));

/* BAR ID IE */
struct pfcp_ie_bar_id {
	struct pfcp_ie h;
	uint8_t bar_id;
} __attribute__((packed));

/* CP Function Features IE */
struct pfcp_ie_cp_function_features {
	struct pfcp_ie h;
	union {
		uint8_t feature_flags[2];
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			/* Octet 5 */
			uint8_t load:1;
			uint8_t ovrl:1;
			uint8_t epfar:1;
			uint8_t sset:1;
			uint8_t bundl:1;
			uint8_t mpas:1;
			uint8_t ardr:1;
			uint8_t uiaur:1;
			/* Octet 6 */
			uint8_t psucc:1;
			uint8_t rpgur:1;
			uint8_t ciot:1;
			uint8_t lsxh:1;
			uint8_t spare_o6:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			/* Octet 5 */
			uint8_t uiaur:1;
			uint8_t ardr:1;
			uint8_t mpas:1;
			uint8_t bundl:1;
			uint8_t sset:1;
			uint8_t epfar:1;
			uint8_t ovrl:1;
			uint8_t load:1;
			/* Octet 6 */
			uint8_t spare_o6:4;
			uint8_t lsxh:1;
			uint8_t ciot:1;
			uint8_t rpgur:1;
			uint8_t psucc:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Usage Information IE */
struct pfcp_ie_usage_information {
	struct pfcp_ie h;
	union {
		uint8_t usage_information;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t bef:1;
			uint8_t aft:1;
			uint8_t uae:1;
			uint8_t ube:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t ube:1;
			uint8_t uae:1;
			uint8_t aft:1;
			uint8_t bef:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Application Instance ID IE */
struct pfcp_ie_application_instance_id {
	struct pfcp_ie h;
	uint8_t application_instance_identifier[];
} __attribute__((packed));

/* Flow Information IE */
struct pfcp_ie_flow_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t fd:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t fd:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint16_t flow_direction;
	uint8_t flow_description[];
} __attribute__((packed));

/* UE IP Address IE */
struct pfcp_ie_ue_ip_address {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v6:1;
			uint8_t v4:1;
			uint8_t sd:1;
			uint8_t ipv6d:1;
			uint8_t chv4:1;
			uint8_t chv6:1;
			uint8_t ipv6pl:1;
			uint8_t spare:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:1;
			uint8_t ipv6pl:1;
			uint8_t chv6:1;
			uint8_t chv4:1;
			uint8_t ipv6d:1;
			uint8_t sd:1;
			uint8_t v4:1;
			uint8_t v6:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
	uint8_t ipv6_prefix_delegation_bits;
	uint16_t ipv6_prefix_length;
} __attribute__((packed));

/* Packet Rate IE */
struct pfcp_ie_packet_rate {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t ulpr:1;
			uint8_t dlpr:1;
			uint8_t aprc:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t aprc:1;
			uint8_t dlpr:1;
			uint8_t ulpr:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint16_t uplink_time_unit;
	uint16_t maximum_uplink_packet_rate;
	uint16_t downlink_time_unit;
	uint16_t maximum_downlink_packet_rate;
} __attribute__((packed));

/* Outer Header Removal IE */
struct pfcp_ie_outer_header_removal {
	struct pfcp_ie h;
	uint8_t outer_header_removal_description;
	uint8_t gtpu_extension_header_deletion;
} __attribute__((packed));

/* Recovery Time Stamp IE */
struct pfcp_ie_recovery_time_stamp {
	struct pfcp_ie h;
	uint32_t ts;
} __attribute__((packed));

/* DL Flow Level Marking IE */
struct pfcp_ie_dl_flow_level_marking {
	struct pfcp_ie h;
	uint16_t traffic_class;
	uint32_t service_class_indicator;
} __attribute__((packed));

/* Header Enrichment IE */
#define PFCP_HEADER_TYPE_HTTP_HEADER		0
#define PFCP_HEADER_TYPE_SIP_HEADER		1
#define PFCP_HEADER_TYPE_GENERIC_HEADER		2
struct pfcp_ie_enrichment {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t header_type:5;
			uint8_t spare:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:3;
			uint8_t header_type:5;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t header_field_name_length;
	uint8_t header_field_name[];
} __attribute__((packed));

/* Measurement Information IE */
struct pfcp_ie_measurement_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t mbqe:1;
			uint8_t inam:1;
			uint8_t radi:1;
			uint8_t istm:1;
			uint8_t mnop:1;
			uint8_t sspoc:1;
			uint8_t aspoc:1;
			uint8_t ciam:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t ciam:1;
			uint8_t aspoc:1;
			uint8_t sspoc:1;
			uint8_t mnop:1;
			uint8_t istm:1;
			uint8_t radi:1;
			uint8_t inam:1;
			uint8_t mbqe:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Node Report Type IE */
struct pfcp_ie_node_report_type {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t upfr:1;
			uint8_t uprr:1;
			uint8_t ckdr:1;
			uint8_t gpqr:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t gpqr:1;
			uint8_t ckdr:1;
			uint8_t uprr:1;
			uint8_t upfr:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Remote GTP-U Peer IE */
struct pfcp_ie_remote_gtp_u_peer {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t di:1;
			uint8_t ni:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t ni:1;
			uint8_t di:1;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint32_t destination_interface;
	uint8_t network_instance[];
} __attribute__((packed));

/* UR-SEQN IE */
struct pfcp_ie_ur_seqn {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Activate Predefined Rules IE */
struct pfcp_ie_activate_predefined_rules {
	struct pfcp_ie h;
	uint8_t predefined_rules_name[];
} __attribute__((packed));

/* Deactivate Predefined Rules IE */
struct pfcp_ie_deactivate_predefined_rules {
	struct pfcp_ie h;
	uint8_t predefined_rules_name[];
} __attribute__((packed));

/* FAR ID IE */
struct pfcp_ie_far_id {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* QER ID IE */
struct pfcp_ie_qer_id {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* OCI Flags IE */
struct pfcp_ie_oci_flags {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t aoci:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t aoci:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* PFCP Association Release Request IE */
struct pfcp_ie_pfcp_association_release_request {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t sarr:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t sarr:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Graceful Release Period IE */
struct pfcp_ie_graceful_release_period {
	struct pfcp_ie h;
	uint8_t timer_unit;
	uint8_t timer_value;
} __attribute__((packed));

/* PDN Type IE */
#define PFCP_PDN_TYPE_IPV4		1
#define PFCP_PDN_TYPE_IPV6		2
#define PFCP_PDN_TYPE_IPV4V6		3
#define PFCP_PDN_TYPE_NON_IP		4
#define PFCP_PDN_TYPE_ETHERNET		5
struct pfcp_ie_pdn_type {
	struct pfcp_ie h;
	union {
		uint8_t pdn_type;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t type:3;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t type:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Failed Rule ID IE */
#define PFCP_FAILED_RULE_TYPE_PDR	0
#define PFCP_FAILED_RULE_TYPE_FAR	1
#define PFCP_FAILED_RULE_TYPE_QER	2
#define PFCP_FAILED_RULE_TYPE_URR	3
#define PFCP_FAILED_RULE_TYPE_BAR	4
struct pfcp_ie_failed_rule_id {
	struct pfcp_ie h;
	union {
		uint8_t rule_id_type;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t type:4;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t type:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint32_t value;
} __attribute__((packed));

/* Time Quota Mechanism IE */
struct pfcp_ie_time_quota_mechanism {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t btit:2;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t btit:2;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint32_t base_time_interval_type;
} __attribute__((packed));

/* User Plane IP Resource Information IE */
struct pfcp_ie_user_plane_ip_resource_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t teidri:3;
			uint8_t assoni:1;
			uint8_t assosi:1;
			uint8_t ma:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t ma:1;
			uint8_t assosi:1;
			uint8_t assoni:1;
			uint8_t teidri:3;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
	uint8_t network_instance[];
} __attribute__((packed));

/* User Plane Inactivity Timer IE */
struct pfcp_ie_user_plane_inactivity_timer {
	struct pfcp_ie h;
	uint32_t timer;
} __attribute__((packed));

/* Multiplier IE */
struct pfcp_ie_multiplier {
	struct pfcp_ie h;
	uint64_t value_digits;
	int32_t exponent;
} __attribute__((packed));

/* Aggregated URR ID IE */
struct pfcp_ie_aggregated_urr_id {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Subsequent Volume Quota IE */
struct pfcp_ie_subsequent_volume_quota {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t tovol:1;
			uint8_t ulvol:1;
			uint8_t dlvol:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t dlvol:1;
			uint8_t ulvol:1;
			uint8_t tovol:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint64_t total_volume;
	uint64_t uplink_volume;
	uint64_t downlink_volume;
} __attribute__((packed));

/* Subsequent Time Quota IE */
struct pfcp_ie_subsequent_time_quota {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* RQI IE */
struct pfcp_ie_rqi {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t rqi:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t rqi:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* QFI IE */
struct pfcp_ie_qfi {
	struct pfcp_ie h;
	union {
		uint8_t value;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t qfi:6;
			uint8_t spare:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:2;
			uint8_t qfi:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Query URR Reference IE */
struct pfcp_ie_query_urr_reference {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Additional Usage Reports Information IE */
struct pfcp_ie_additional_usage_reports_information {
	struct pfcp_ie h;
	union {
		uint16_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t auri:1;
			uint16_t number_of_additional_usage_reports_value:15;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint16_t number_of_additional_usage_reports_value:15;
			uint16_t auri:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Traffic Endpoint ID IE */
struct pfcp_ie_traffic_endpoint_id {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* MAC Address IE */
struct pfcp_ie_mac_address {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t sour:1;
			uint8_t dest:1;
			uint8_t usou:1;
			uint8_t udes:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t udes:1;
			uint8_t usou:1;
			uint8_t dest:1;
			uint8_t sour:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t source_mac_address[6];
	uint8_t destination_mac_address[6];
	uint8_t upper_source_mac_address[6];
	uint8_t upper_destination_mac_address[6];
} __attribute__((packed));

/* C-TAG IE */
struct pfcp_ie_c_tag {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t pcp:3;
			uint8_t dei:1;
			uint8_t vid:1;
			uint8_t spare:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:3;
			uint8_t vid:1;
			uint8_t dei:1;
			uint8_t pcp:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint16_t cvid_value;
	uint8_t ctag_pcp_value;
	uint8_t ctag_dei_value;
} __attribute__((packed));

/* S-TAG IE */
struct pfcp_ie_s_tag {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t pcp:3;
			uint8_t dei:1;
			uint8_t vid:1;
			uint8_t spare:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:3;
			uint8_t vid:1;
			uint8_t dei:1;
			uint8_t pcp:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint16_t svid_value;
	uint8_t stag_pcp_value;
	uint8_t stag_dei_value;
} __attribute__((packed));

/* Ethertype IE */
struct pfcp_ie_ethertype {
	struct pfcp_ie h;
	uint16_t ethertype;
} __attribute__((packed));

/* Proxying IE */
struct pfcp_ie_proxying {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t arp:1;
			uint8_t ipv6_nd:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t ipv6_nd:1;
			uint8_t arp:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Ethernet Filter ID IE */
struct pfcp_ie_ethernet_filter_id {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Ethernet Filter Properties IE */
struct pfcp_ie_ethernet_filter_properties {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t bide:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t bide:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Suggested Buffering Packets Count IE */
struct pfcp_ie_suggested_buffering_packets_count {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* User ID IE */
struct pfcp_ie_user_id {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t imsif:1;
			uint8_t imeif:1;
			uint8_t msisdnf:1;
			uint8_t naif:1;
			uint8_t supi:1;
			uint8_t gpsi:1;
			uint8_t pei:1;
			uint8_t spare:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:1;
			uint8_t pei:1;
			uint8_t gpsi:1;
			uint8_t supi:1;
			uint8_t naif:1;
			uint8_t msisdnf:1;
			uint8_t imeif:1;
			uint8_t imsif:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t value[];
} __attribute__((packed));

/* Ethernet PDU Session Information IE */
struct pfcp_ie_ethernet_pdu_session_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t ethi:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t ethi:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* MAC Addresses Detected IE */
struct pfcp_ie_mac_addresses_detected {
	struct pfcp_ie h;
	uint8_t number_of_mac_addresses;
	uint8_t mac_addresses[];
} __attribute__((packed));

/* MAC Addresses Removed IE */
struct pfcp_ie_mac_addresses_removed {
	struct pfcp_ie h;
	uint8_t number_of_mac_addresses;
	uint8_t mac_addresses[];
} __attribute__((packed));

/* Ethernet Inactivity Timer IE */
struct pfcp_ie_ethernet_inactivity_timer {
	struct pfcp_ie h;
	uint32_t ethernet_inactivity_timer;
} __attribute__((packed));

/* Event Quota IE */
struct pfcp_ie_event_quota {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Event Threshold IE */
struct pfcp_ie_event_threshold {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Subsequent Event Quota IE */
struct pfcp_ie_subsequent_event_quota {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Subsequent Event Threshold IE */
struct pfcp_ie_subsequent_event_threshold {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Trace Information IE */
struct pfcp_ie_trace_information {
	struct pfcp_ie h;
	uint8_t mcc_mnc[3];
	uint16_t trace_id;
	uint8_t length_of_triggering_events;
	uint8_t triggering_events[];
} __attribute__((packed));

/* Framed Route IE */
struct pfcp_ie_framed_route {
	struct pfcp_ie h;
	uint8_t framed_route[];
} __attribute__((packed));

/* Framed Routing IE */
struct pfcp_ie_framed_routing {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Framed IPv6 Route IE */
struct pfcp_ie_framed_ipv6_route {
	struct pfcp_ie h;
	uint8_t framed_ipv6_route[];
} __attribute__((packed));

/* Time Stamp IE */
struct pfcp_ie_time_stamp {
	struct pfcp_ie h;
	uint32_t timestamp;
} __attribute__((packed));

/* Averaging Window IE */
struct pfcp_ie_averaging_window {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* PPI IE */
struct pfcp_ie_ppi {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* APN/DNN IE */
struct pfcp_ie_apn_dnn {
	struct pfcp_ie h;
	uint8_t apn_dnn[];
} __attribute__((packed));

/* 3GPP Interface Type IE */
#define PFCP_3GPP_INTERFACE_S1U	0
#define PFCP_3GPP_INTERFACE_S5U	1
#define PFCP_3GPP_INTERFACE_SGI	16
#define PFCP_3GPP_INTERFACE_S8U	19
#define PFCP_3GPP_INTERFACE_N9	23
struct pfcp_ie_3gpp_interface_type {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t value:6;
	uint8_t spare:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t spare:2;
	uint8_t value:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* PFCP Session Retention Request Flags IE */
struct pfcp_ie_pfcpsrreq_flags {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:7;
	uint8_t psdbu:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t psdbu:1;
	uint8_t spare:7;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* PFCP Association Update Request Flags IE */
struct pfcp_ie_pfcpaureq_flags {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:7;
	uint8_t parps:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t parps:1;
	uint8_t spare:7;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* Activation Time IE */
struct pfcp_ie_activation_time {
	struct pfcp_ie h;
	uint32_t activation_time;
} __attribute__((packed));

/* Deactivation Time IE */
struct pfcp_ie_deactivation_time {
	struct pfcp_ie h;
	uint32_t deactivation_time;
} __attribute__((packed));

/* MAR ID IE */
struct pfcp_ie_mar_id {
	struct pfcp_ie h;
	uint16_t value;
} __attribute__((packed));

/* Steering Functionality IE */
struct pfcp_ie_steering_functionality {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Steering Mode IE */
struct pfcp_ie_steering_mode {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Weight IE */
struct pfcp_ie_weight {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Priority IE */
struct pfcp_ie_priority {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* UE IP Address Pool Identity IE */
struct pfcp_ie_ue_ip_address_pool_identity {
	struct pfcp_ie h;
	uint8_t pool_identity_length;
	uint8_t pool_identity[];
} __attribute__((packed));

/* Alternative SMF IP Address IE */
struct pfcp_ie_alternative_smf_ip_address {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v6:1;
			uint8_t v4:1;
			uint8_t pfe:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t pfe:1;
			uint8_t v4:1;
			uint8_t v6:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
} __attribute__((packed));

/* Packet Replication and Detection Carry-On Information IE */
struct pfcp_ie_pkt_replication_and_detection_carry_on_information {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:6;
	uint8_t dcaroni:1;
	uint8_t prin6i:1;
	uint8_t spare2:6;
	uint8_t prin19i:1;
	uint8_t priueai:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t prin6i:1;
	uint8_t dcaroni:1;
	uint8_t spare:6;
	uint8_t priueai:1;
	uint8_t prin19i:1;
	uint8_t spare2:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* SMF Set ID IE */
struct pfcp_ie_smf_set_id {
	struct pfcp_ie h;
	uint8_t smf_set_id[];
} __attribute__((packed));

/* Quota Validity Time IE */
struct pfcp_ie_quota_validity_time {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Number of Reports IE */
struct pfcp_ie_number_of_reports {
	struct pfcp_ie h;
	uint16_t value;
} __attribute__((packed));

/* PFCP Association Setup Response Flags IE */
struct pfcp_ie_pfcpasrsp_flags {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:7;
	uint8_t uupsi:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t uupsi:1;
	uint8_t spare:7;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* CP PFCP Entity IP Address IE */
struct pfcp_ie_cp_pfcp_entity_ip_address {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v6:1;
			uint8_t v4:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t v4:1;
			uint8_t v6:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
} __attribute__((packed));

/* PFCP Session Establishment Request Flags IE */
struct pfcp_ie_pfcpsereq_flags {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:7;
	uint8_t sumpc:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t sumpc:1;
	uint8_t spare:7;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* IP Multicast Address IE */
struct pfcp_ie_ip_multicast_address {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:6;
	uint8_t any:1;
	uint8_t range:1;
	uint8_t spare2:6;
	uint8_t v4:1;
	uint8_t v6:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t range:1;
	uint8_t any:1;
	uint8_t spare:6;
	uint8_t v6:1;
	uint8_t v4:1;
	uint8_t spare2:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	union {
		struct {
			struct in_addr start_ipv4_address;
			struct in_addr end_ipv4_address;
		} ipv4_range;
		struct {
			struct in6_addr start_ipv6_address;
			struct in6_addr end_ipv6_address;
		} ipv6_range;
		struct in_addr ipv4_address;
		struct in6_addr ipv6_address;
	};
} __attribute__((packed));

/* Source IP Address IE */
struct pfcp_ie_source_ip_address {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v6:1;
			uint8_t v4:1;
			uint8_t mpl:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t mpl:1;
			uint8_t v4:1;
			uint8_t v6:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		struct {
			struct in_addr ipv4;
			struct in6_addr ipv6;
		} both;
	};
	uint8_t mask_prefix_length;
} __attribute__((packed));

/* Packet Rate Status IE */
struct pfcp_ie_packet_rate_status {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:6;
	uint8_t apr:1;
	uint8_t ul:1;
	uint8_t spare2:6;
	uint8_t dl:1;
	uint8_t apr2:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ul:1;
	uint8_t apr:1;
	uint8_t spare:6;
	uint8_t apr2:1;
	uint8_t dl:1;
	uint8_t spare2:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	uint16_t ul_time_unit;
	uint32_t max_ul_packet_rate;
	uint16_t dl_time_unit;
	uint32_t max_dl_packet_rate;
	uint32_t apr_ul_packet_rate;
	uint32_t apr_dl_packet_rate;
} __attribute__((packed));

/* Create Bridge Router Info IE */
struct pfcp_ie_create_bridge_router_info {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:7;
	uint8_t bir:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t bir:1;
	uint8_t spare:7;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* DS-TT Port Number IE */
struct pfcp_ie_ds_tt_port_number {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* NW-TT Port Number IE */
struct pfcp_ie_nw_tt_port_number {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* 5GS User Plane Node IE */
struct pfcp_ie_5gs_user_plane_node {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:6;
	uint8_t bid:1;
	uint8_t vid:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t vid:1;
	uint8_t bid:1;
	uint8_t spare:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	uint8_t value[];
} __attribute__((packed));

/* Port Management Information Container IE */
struct pfcp_ie_port_management_information_container {
	struct pfcp_ie h;
	uint8_t port_management_information[];
} __attribute__((packed));

/* Requested Clock Drift Information IE */
struct pfcp_ie_requested_clock_drift_information {
	struct pfcp_ie h;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare:6;
	uint8_t rrcr:1;
	uint8_t rrto:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t rrto:1;
	uint8_t rrcr:1;
	uint8_t spare:6;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* Time Domain Number IE */
struct pfcp_ie_time_domain_number {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Time Offset Threshold IE */
struct pfcp_ie_time_offset_threshold {
	struct pfcp_ie h;
	uint64_t value;
} __attribute__((packed));

/* Cumulative Rate Ratio Threshold IE */
struct pfcp_ie_cumulative_rate_ratio_threshold {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Time Offset Measurement IE */
struct pfcp_ie_time_offset_measurement {
	struct pfcp_ie h;
	int64_t value;
} __attribute__((packed));

/* Cumulative Rate Ratio Measurement IE */
struct pfcp_ie_cumulative_rate_ratio_measurement {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* SRR ID IE */
struct pfcp_ie_srr_id {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Requested Access Availability Information IE */
struct pfcp_ie_requested_access_availability_information {
	struct pfcp_ie h;
	uint8_t requested_access_availability_information[];
} __attribute__((packed));

/* Access Availability Information IE */
struct pfcp_ie_access_availability_information {
	struct pfcp_ie h;
	uint8_t access_availability_type;
	uint8_t access_availability_status;
} __attribute__((packed));

/* MPTCP Control Information IE */
struct pfcp_ie_mptcp_control_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t tci:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t tci:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* ATSSS-LL Control Information IE */
struct pfcp_ie_atsss_ll_control_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t lli:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t lli:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* PMF Control Information IE */
struct pfcp_ie_pmf_control_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t pmfi:3;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t pmfi:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t pmf_address[];
} __attribute__((packed));

/* MPTCP Address Information IE */
struct pfcp_ie_mptcp_address_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint16_t mptcp_address_id;
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
} __attribute__((packed));

/* UE Link Specific IP Address IE */
struct pfcp_ie_ue_link_specific_ip_address {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t nv4:1;
			uint8_t nv6:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t nv6:1;
			uint8_t nv4:1;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} nw_ip_address;
} __attribute__((packed));

/* PMF Address Information IE */
struct pfcp_ie_pmf_address_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t mac:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t mac:1;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
	union {
		uint16_t std_access;
		uint16_t non_std_access;
		struct {
			uint16_t std_access;
			uint16_t non_std_access;
		} both;
	} port;
	uint8_t mac_address_std[6];
	uint8_t mac_address_non_std[6];
} __attribute__((packed));

/* ATSSS-LL Information IE */
struct pfcp_ie_atsss_ll_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t lli:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t lli:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t atsss_ll_information[];
} __attribute__((packed));

/* Data Network Access Identifier IE */
struct pfcp_ie_data_network_access_identifier {
	struct pfcp_ie h;
	uint8_t data_network_access_identifier[];
} __attribute__((packed));

/* Average Packet Delay IE */
struct pfcp_ie_average_packet_delay {
	struct pfcp_ie h;
	uint32_t delay_value_in_milliseconds;
} __attribute__((packed));

/* Minimum Packet Delay IE */
struct pfcp_ie_minimum_packet_delay {
	struct pfcp_ie h;
	uint32_t delay_value_in_milliseconds;
} __attribute__((packed));

/* Maximum Packet Delay IE */
struct pfcp_ie_maximum_packet_delay {
	struct pfcp_ie h;
	uint32_t delay_value_in_milliseconds;
} __attribute__((packed));

/* QoS Report Trigger IE */
struct pfcp_ie_qos_report_trigger {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t per:1;
			uint8_t thr:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t thr:1;
			uint8_t per:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* GTP-U Path Interface Type IE */
struct pfcp_ie_gtp_u_path_interface_type {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t n9:1;
			uint8_t n3:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t n3:1;
			uint8_t n9:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Requested QoS Monitoring IE */
struct pfcp_ie_requested_qos_monitoring {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t dl:1;
			uint8_t ul:1;
			uint8_t rp:1;
			uint8_t gtpupm:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t gtpupm:1;
			uint8_t rp:1;
			uint8_t ul:1;
			uint8_t dl:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Reporting Frequency IE */
struct pfcp_ie_reporting_frequency {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t evett:1;
			uint8_t perio:1;
			uint8_t sesrl:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t sesrl:1;
			uint8_t perio:1;
			uint8_t evett:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Packet Delay Thresholds IE */
struct pfcp_ie_packet_delay_thresholds {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t dl:1;
			uint8_t ul:1;
			uint8_t rp:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t rp:1;
			uint8_t ul:1;
			uint8_t dl:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint32_t downlink_packet_delay_threshold;
	uint32_t uplink_packet_delay_threshold;
	uint32_t round_trip_packet_delay_threshold;
} __attribute__((packed));

/* Minimum Wait Time IE */
struct pfcp_ie_minimum_wait_time {
	struct pfcp_ie h;
	uint32_t timer_value;
} __attribute__((packed));

/* QoS Monitoring Measurement IE */
struct pfcp_ie_qos_monitoring_measurement {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t dl:1;
			uint8_t ul:1;
			uint8_t rp:1;
			uint8_t plmf:1;
			uint8_t spare:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:4;
			uint8_t plmf:1;
			uint8_t rp:1;
			uint8_t ul:1;
			uint8_t dl:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint32_t downlink_packet_delay;
	uint32_t uplink_packet_delay;
	uint32_t round_trip_packet_delay;
	uint32_t downlink_packet_loss_rate;
	uint32_t uplink_packet_loss_rate;
} __attribute__((packed));

/* MT-EDT Control Information IE */
struct pfcp_ie_mt_edt_control_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t rdsi:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t rdsi:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* DL Data Packets Size IE */
struct pfcp_ie_dl_data_packets_size {
	struct pfcp_ie h;
	uint16_t value;
} __attribute__((packed));

/* QER Control Indications IE */
struct pfcp_ie_qer_control_indications {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t rcsr:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t rcsr:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* NF Instance ID IE */
struct pfcp_ie_nf_instance_id {
	struct pfcp_ie h;
	uint8_t nf_instance_id[16];
} __attribute__((packed));

/* S-NSSAI IE */
struct pfcp_ie_s_nssai {
	struct pfcp_ie h;
	uint8_t sst;
	uint8_t sd[3];
} __attribute__((packed));

/* IP Version IE */
struct pfcp_ie_ip_version {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* PFCP Association Setup Request Flags IE */
struct pfcp_ie_pfcpasreq_flags {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t uupsi:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t uupsi:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Data Status IE */
struct pfcp_ie_data_status {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t drop:1;
			uint8_t buff:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t buff:1;
			uint8_t drop:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* RDS Configuration Information IE */
struct pfcp_ie_rds_configuration_information {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t rds:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t rds:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* MPTCP Applicable Indication IE */
struct pfcp_ie_mptcp_applicable_indication {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t mai:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t mai:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Bridge Management Information Container IE */
struct pfcp_ie_bridge_management_information_container {
	struct pfcp_ie h;
	uint8_t bridge_management_information[];
} __attribute__((packed));

/* Number of UE IP Addresses IE */
struct pfcp_ie_number_of_ue_ip_addresses {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		uint32_t v4;
		uint32_t v6;
		struct {
			uint32_t v4;
			uint32_t v6;
		} both;
	} ip_addresses;
} __attribute__((packed));

/* Validity Timer IE */
struct pfcp_ie_validity_timer {
	struct pfcp_ie h;
	uint16_t value;
} __attribute__((packed));

/* Offending IE Information IE */
struct pfcp_ie_offending_ie_information {
	struct pfcp_ie h;
	uint16_t type_of_the_offending_ie;
} __attribute__((packed));

/* RAT Type IE */
struct pfcp_ie_rat_type {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Tunnel Preference IE */
struct pfcp_ie_tunnel_preference {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t ch:1;
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t v6:1;
			uint8_t v4:1;
			uint8_t ch:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Calling Number IE */
struct pfcp_ie_calling_number {
	struct pfcp_ie h;
	uint8_t calling_number[];
} __attribute__((packed));

/* Called Number IE */
struct pfcp_ie_called_number {
	struct pfcp_ie h;
	uint8_t called_number[];
} __attribute__((packed));

/* DNS Server Address IE */
struct pfcp_ie_dns_server_address {
	struct pfcp_ie h;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip_address;
} __attribute__((packed));

/* NBNS Server Address IE */
struct pfcp_ie_nbns_server_address {
	struct pfcp_ie h;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip_address;
} __attribute__((packed));

/* Maximum Receive Unit IE */
struct pfcp_ie_maximum_receive_unit {
	struct pfcp_ie h;
	uint16_t value;
} __attribute__((packed));

/* Thresholds IE */
struct pfcp_ie_thresholds {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t rtt:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t rtt:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint32_t rtt_threshold;
} __attribute__((packed));

/* Steering Mode Indicator IE */
struct pfcp_ie_steering_mode_indicator {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* Group ID IE */
struct pfcp_ie_group_id {
	struct pfcp_ie h;
	uint8_t group_id[];
} __attribute__((packed));

/* CP IP Address IE */
struct pfcp_ie_cp_ip_address {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v6:1;
			uint8_t v4:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t v4:1;
			uint8_t v6:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
} __attribute__((packed));

/* IP Address and Port Number Replacement IE */
struct pfcp_ie_ip_address_and_port_number_replacement {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t dpn:1;
			uint8_t sipv4:1;
			uint8_t sipv6:1;
			uint8_t spn:1;
			uint8_t umn6rs:1;
			uint8_t spare:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:1;
			uint8_t umn6rs:1;
			uint8_t spn:1;
			uint8_t sipv6:1;
			uint8_t sipv4:1;
			uint8_t dpn:1;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		struct {
			struct in_addr ipv4;
			struct in6_addr ipv6;
		} both;
	} dst_ip_address;
	uint16_t dst_port_number;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		struct {
			struct in_addr ipv4;
			struct in6_addr ipv6;
		} both;
	} src_ip_address;
	uint16_t src_port_number;
} __attribute__((packed));

/* DNS Query Filter IE */
struct pfcp_ie_dns_query_filter {
	struct pfcp_ie h;
	uint8_t dns_query_filter[];
} __attribute__((packed));

/* Event Notification URI IE */
struct pfcp_ie_event_notification_uri {
	struct pfcp_ie h;
	uint8_t event_notification_uri[];
} __attribute__((packed));

/* Notification Correlation ID IE */
struct pfcp_ie_notification_correlation_id {
	struct pfcp_ie h;
	uint32_t value;
} __attribute__((packed));

/* Reporting Flags IE */
struct pfcp_ie_reporting_flags {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t dupl:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t dupl:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Predefined Rules Name IE */
struct pfcp_ie_predefined_rules_name {
	struct pfcp_ie h;
	uint8_t predefined_rules_name[];
} __attribute__((packed));

/* Local Ingress Tunnel IE */
struct pfcp_ie_local_ingress_tunnel {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t v4:1;
			uint8_t v6:1;
			uint8_t ch:1;
			uint8_t spare:5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:5;
			uint8_t ch:1;
			uint8_t v6:1;
			uint8_t v4:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint16_t port;
	union {
		struct in_addr v4;
		struct in6_addr v6;
		struct {
			struct in_addr v4;
			struct in6_addr v6;
		} both;
	} ip_address;
} __attribute__((packed));

/* PFCP Area Session ID IE */
struct pfcp_ie_area_session_id {
	struct pfcp_ie h;
	uint16_t id;
};

/* PFCP Session Deletion Response Flags IE */
struct pfcp_ie_pfcpsdrsp_flags {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t eir:1;
			uint8_t spare:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:7;
			uint8_t eir:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* QER Indications IE */
struct pfcp_ie_qer_indications {
	struct pfcp_ie h;
	union {
		uint8_t flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t nord:1;
			uint8_t empu:1;
			uint8_t spare:6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t spare:6;
			uint8_t empu:1;
			uint8_t nord:1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
} __attribute__((packed));

/* Vendor-specific Node Report Type IE */
struct pfcp_ie_vendor_specific_node_report_type {
	struct pfcp_ie h;
	uint32_t enterprise_id;
	uint8_t value[];
} __attribute__((packed));

/* Configured Time Domain IE */
struct pfcp_ie_configured_time_domain {
	struct pfcp_ie h;
	uint8_t value;
} __attribute__((packed));

/* TL-Container IE */
struct pfcp_ie_tl_container {
	struct pfcp_ie h;
	uint8_t info[];
} __attribute__((packed));


/* Prototypes */
int pfcp_ie_foreach(const uint8_t *buffer, size_t bsize,
		    int (*parse) (void *, void *, const uint8_t *),
		    void *arg1, void *arg2);
int pfcp_ie_decode_user_id(struct pfcp_ie_user_id *uid, uint64_t *imsi,
			   uint64_t *imei, uint64_t *msisdn);
int pfcp_ie_decode_apn_dnn_ni(struct pfcp_ie_apn_dnn *apn, char *dst,
			      size_t dsize);
int pfcp_ie_put(struct pkt_buffer *pbuff, uint16_t type, uint16_t length);
int pfcp_ie_put_type(struct pkt_buffer *pbuff, uint16_t type);
int pfcp_ie_put_recovery_ts(struct pkt_buffer *pbuff, uint32_t ts);
int pfcp_ie_put_up_function_features(struct pkt_buffer *pbuff,
				     uint8_t *supported_features);
int pfcp_ie_put_cause(struct pkt_buffer *pbuff, uint8_t cause);
int pfcp_ie_put_node_id(struct pkt_buffer *pbuff, const uint8_t *node_id,
			size_t nsize);
int pfcp_ie_put_error_cause(struct pkt_buffer *pbuff, const uint8_t *node_id,
			    size_t nsize, uint8_t cause);
int pfcp_ie_put_f_seid(struct pkt_buffer *pbuff, const uint64_t seid,
		       const struct sockaddr_storage *addr);
int pfcp_ie_put_created_pdr(struct pkt_buffer *pbuff, const uint16_t pdr_id,
			    const uint32_t teid, const struct in_addr *ipv4,
			    const struct in6_addr *ipv6);
int pfcp_ie_put_created_te(struct pkt_buffer *pbuff, const uint8_t id,
		           const uint32_t teid,
			   const struct in_addr *t_ipv4, const struct in6_addr *t_ipv6,
			   const struct in_addr *ue_ipv4, const struct in6_addr *ue_ipv6);
int pfcp_ie_put_usage_report(struct pkt_buffer *pbuff, uint32_t id,
			     uint32_t start_time, uint32_t end_time,
			     struct pfcp_metrics_pkt *uplink,
			     struct pfcp_metrics_pkt *downlink);
