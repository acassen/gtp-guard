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

#include "gtp_apn.h"
#include "gtp_conn.h"
#include "pfcp.h"
#include "pfcp_msg.h"
#include "pfcp_metrics.h"

/* Default values */
#define PFCP_MAX_NR_ELEM	5
#define PFCP_STR_MAX_LEN	32

/* Hash table */
#define PFCP_SESSION_HASHTAB_BITS  20
#define PFCP_SESSION_HASHTAB_SIZE  (1 << PFCP_SESSION_HASHTAB_BITS)
#define PFCP_SESSION_HASHTAB_MASK  (PFCP_SESSION_HASHTAB_SIZE - 1)

/* Session flags */
enum pfcp_session_flags {
	PFCP_SESSION_FL_UE_IPV4,
	PFCP_SESSION_FL_UE_IPV6,
	PFCP_SESSION_FL_HPLMN,
	PFCP_SESSION_FL_ROAMING_IN,
	PFCP_SESSION_FL_ROAMING_OUT,
	PFCP_SESSION_FL_HASHED,
};

/* Session Actions */
enum {
	PFCP_ACTION_DELETE_SESSION = 1,
};

/* Session components */
struct f_seid {
	uint64_t		id;
	struct sockaddr_storage	addr;
};

#define UE_IPV4	(1 << 0)
#define UE_IPV6	(1 << 1)
#define UE_CHV4	(1 << 2)
#define UE_CHV6	(1 << 3)
struct ue_ip_address {
	uint8_t			flags;
	struct in_addr		v4;
	struct in6_addr		v6;
	struct ip_pool		*pool_v4;
	struct ip_pool		*pool_v6;
};

struct traffic_endpoint {
	uint8_t			id;
	uint8_t			choose_id;
	uint8_t			interface_type;
	struct ue_ip_address	ue_ip;
	struct pfcp_teid	*teid[PFCP_DIR_MAX];
};

struct far {
	uint32_t		id;
	uint8_t			dst_interface_type;
	uint8_t			dst_interface;
	uint8_t			tos_tclass;
	uint8_t			tos_mask;

	struct traffic_endpoint	*dst_te;
};

struct qer {
	uint32_t		id;
	uint32_t		ul_mbr;
	uint32_t		dl_mbr;
};

struct urr {
	uint32_t		id;
	uint8_t			measurement_method;
	uint8_t			measurement_info;
	uint16_t		triggers;
	uint32_t		quota_holdtime;
	uint64_t		volume_threshold;
	uint64_t		counter;

	/* metrics */
	uint32_t		start_time;
	uint32_t		end_time;
	struct pfcp_metrics_pkt	uplink;
	struct pfcp_metrics_pkt	downlink;
};

struct pdr {
	uint16_t		id;
	uint32_t		precedence;
	uint8_t			action;

	/* F-TEID in PDI */
	uint8_t			src_interface;
	uint8_t			choose_id;
	struct pfcp_teid	*teid[PFCP_DIR_MAX];
	struct ue_ip_address	ue_ip;

	/* F-TEID in traffic-endpoint when using
	 * PDI Optimization */
	struct traffic_endpoint *te;

	struct far		*far;
	struct urr		*urr[PFCP_MAX_NR_ELEM];
	struct qer		*qer;
	char			predifined_rule[PFCP_STR_MAX_LEN];
};

/* PFCP session */
struct pfcp_session {
	uint64_t		seid;
	struct f_seid		remote_seid;

	struct pdr		pdr[PFCP_MAX_NR_ELEM];
	struct far		far[PFCP_MAX_NR_ELEM];
	struct qer		qer[PFCP_MAX_NR_ELEM];
	struct urr		urr[PFCP_MAX_NR_ELEM];
	struct traffic_endpoint	te[PFCP_MAX_NR_ELEM];

	struct gtp_conn		*conn;		/* backpointer */
	struct pfcp_router	*router;	/* Server used */
	struct gtp_apn		*apn;
	struct gtp_cdr		*cdr;

	uint8_t			action;

	/* Expiration handling */
	char			tmp_str[64];
	struct tm		creation_time;
	struct tm		deletion_time;

	/* I/O MUX */
	struct thread		*timer;

	/* indexing */
	struct list_head	next;
	struct hlist_node	hlist;

	int			refcnt;

	unsigned long		flags;
};

/* Prototypes */
int pfcp_sessions_count_read(void);
struct pfcp_session *pfcp_session_get(uint64_t id);
struct pfcp_session *pfcp_session_alloc(struct gtp_conn *c,
					struct gtp_apn *apn,
					struct pfcp_router *r);
int pfcp_session_destroy(struct pfcp_session *s);
int pfcp_sessions_free(struct gtp_conn *c);
int pfcp_sessions_int(void);
int pfcp_sessions_destroy(void);
int pfcp_session_create(struct pfcp_session *s,
			struct pfcp_session_establishment_request *req,
			struct sockaddr_storage *addr);
int pfcp_session_modify(struct pfcp_session *s,
			struct pfcp_session_modification_request *req);
int pfcp_session_put_created_pdr(struct pkt_buffer *pbuff,
				 struct pfcp_session *s);
int pfcp_session_put_created_traffic_endpoint(struct pkt_buffer *pbuff,
					      struct pfcp_session *s);
int pfcp_session_put_usage_report(struct pkt_buffer *pbuff,
				  struct pfcp_session *s);
int pfcp_session_bpf_action(struct pfcp_session *s, int action);
