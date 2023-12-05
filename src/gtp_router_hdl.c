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

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "timer.h"
#include "mpool.h"
#include "vector.h"
#include "command.h"
#include "list_head.h"
#include "json_writer.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_iptnl.h"
#include "gtp_htab.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_sched.h"
#include "gtp_teid.h"
#include "gtp_server.h"
#include "gtp_router.h"
#include "gtp_conn.h"
#include "gtp_session.h"
#include "gtp_router_hdl.h"
#include "gtp_sqn.h"
#include "gtp_utils.h"
#include "gtp_xdp.h"
#include "gtp_msg.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
extern gtp_teid_t dummy_teid;


/*
 *	Utilities
 */
static gtp_session_t *
gtpc_msg_retransmit(gtp_router_t *ctx, gtp_hdr_t *h, uint8_t *ie_buffer)
{
	gtp_teid_t *teid;
	gtp_f_teid_t f_teid;

	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));
	teid = gtp_teid_get(&ctx->gtpc_teid_tab, &f_teid);
	if (!teid)
		return NULL;

	if (h->teid_presence)
		return (h->sqn == teid->sqn) ? teid->session : NULL;
	if (h->sqn_only == teid->sqn)
		return teid->session;

	return NULL;
}

static gtp_teid_t *
gtp_teid_set(gtp_teid_t *teid, uint8_t type, int direction, gtp_session_t *s, uint32_t sqn)
{
	if (!teid)
		return NULL;

	teid->type = type;
	teid->session = s;
	teid->sqn = sqn;

	/* Add to list */
	if (type == GTP_TEID_C) {
		gtp_session_gtpc_teid_add(s, teid);
	} else if (type == GTP_TEID_U) {
		gtp_session_gtpu_teid_add(s, teid);

		/* Fast-Path setup */
//		gtp_xdp_rt_teid_action(RULE_ADD, teid, direction);
	}

	return teid;
}

static gtp_teid_t *
gtp_teid_create(uint8_t type, int direction, gtp_session_t *s, gtp_htab_t *h,
		uint32_t sqn, gtp_f_teid_t *f_teid, gtp_ie_eps_bearer_id_t *bearer_id)
{
	gtp_teid_t *teid = NULL;

	teid = gtp_teid_get(h, f_teid);
	if (teid) {
		/* update sqn */
		teid->sqn = sqn;
		return teid;
	}

	teid = gtp_teid_alloc(h, f_teid, bearer_id);
	return gtp_teid_set(teid, type, direction, s, sqn);
}

static gtp_teid_t *
gtp_session_append_gtpu(gtp_server_worker_t *w, gtp_session_t *s, int direction, void *arg, uint8_t *ie_buffer)
{
	gtp_server_t *srv = w->srv;
	gtp_router_t *ctx = srv->ctx;
	gtp_ie_eps_bearer_id_t *bearer_id = arg;
	gtp_f_teid_t f_teid;
	gtp_teid_t *teid, *pteid;

	f_teid.version = 2;
	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));

	teid = gtp_teid_create(GTP_TEID_U, direction, s
					 , &ctx->gtpu_teid_tab
					 , 0, &f_teid, bearer_id);
	pteid = gtp_teid_alloc_peer(&ctx->gtpu_teid_tab, teid, &w->seed);
	gtp_teid_set(pteid, GTP_TEID_U, !direction, s, 0);
	return teid;
}

static gtp_teid_t *
gtpc_session_create(gtp_server_worker_t *w, gtp_msg_t *msg, gtp_session_t *s)
{
	gtp_hdr_t *h = msg->h;
	gtp_conn_t *c = s->conn;
	gtp_router_t *ctx = c->ctx;
	gtp_teid_t *teid = NULL, *pteid;
	gtp_msg_ie_t *msg_ie;
	gtp_f_teid_t f_teid;
	gtp_ie_eps_bearer_id_t *bearer_id = NULL;
	uint8_t *ie_buffer, *cp_bid;
	uint32_t sqn;

	/* GTP-C create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (msg_ie) {
		ie_buffer = (uint8_t *) msg_ie->h;
		f_teid.version = 2;
		f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
		f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));
		sqn = (h->teid_presence) ? h->sqn : h->sqn_only;
		teid = gtp_teid_create(GTP_TEID_C, GTP_INGRESS, s
						 , &ctx->gtpc_teid_tab
						 , sqn, &f_teid, NULL);
		pteid = gtp_teid_alloc_peer(&ctx->gtpc_teid_tab, teid, &w->seed);
		gtp_teid_set(pteid, GTP_TEID_U, GTP_EGRESS, s, 0);
	}

	/* GTP-U create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_BEARER_CONTEXT_TYPE);
	if (!msg_ie)
		return teid;

	cp_bid = gtp_get_ie_offset(GTP_IE_EPS_BEARER_ID,(uint8_t *) msg_ie->data, ntohs(msg_ie->h->length), 0);
	bearer_id = (cp_bid) ? (gtp_ie_eps_bearer_id_t *) cp_bid : NULL;
	gtp_foreach_ie(GTP_IE_F_TEID_TYPE, (uint8_t *) msg_ie->data, 0
					 , (uint8_t *) msg_ie->data + ntohs(msg_ie->h->length)
					 , w, s, GTP_INGRESS
					 , bearer_id, gtp_session_append_gtpu);
	return teid;
}


/*
 *	GTP-C Protocol helpers
 */
static int
gtpc_echo_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_ie_recovery_t *rec;
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_RECOVERY_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		rec = (gtp_ie_recovery_t *) cp;
		rec->recovery = daemon_data->restart_counter;
	}

	h->type = GTP_ECHO_RESPONSE_TYPE;

	return 0;
}

static int
gtpc_create_session_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_msg_t *msg;
	gtp_msg_ie_t *msg_ie;
	gtp_server_t *srv = w->srv;
	gtp_router_t *ctx = srv->ctx;
	gtp_conn_t *c;
	gtp_session_t *s = NULL;
	gtp_teid_t *teid;
	gtp_apn_t *apn;
	char apn_str[64];
	uint64_t imsi;
	int ret, rc = -1;

	msg = gtp_msg_alloc(w->buffer, w->buffer_size);
	if (!msg)
		return -1;

	/* IMSI */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_IMSI_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no IMSI IE present. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	imsi = bcd_to_int64(msg_ie->data, ntohs(msg_ie->h->length));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c)
		c = gtp_conn_alloc(imsi, ctx);

	/* APN */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_APN_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no Access-Point-Name IE present. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	memset(apn_str, 0, 63);
	ret = gtp_ie_apn_extract_ni((gtp_ie_apn_t *) msg_ie->h, apn_str, 63);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error parsing Access-Point-Name IE. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	apn = gtp_apn_get(apn_str);
	if (!apn) {
		log_message(LOG_INFO, "%s(): Unknown Access-Point-Name:%s. ignoring..."
				    , __FUNCTION__, apn_str);
		goto end;
	}

	/* At least F-TEID present for create session */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	s = gtpc_msg_retransmit(ctx, msg->h, (uint8_t *) msg_ie->h);
	if (!s)
		s = gtp_session_alloc(c, apn, gtp_router_gtpc_teid_destroy
					    , gtp_router_gtpu_teid_destroy);
	teid = gtpc_session_create(w, msg, s);
	if (!teid) {
		log_message(LOG_INFO, "%s(): Cant create session. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	gtp_teid_update_sgw(teid, addr);

	/* Update last sGW visited */
	c->sgw_addr = *((struct sockaddr_in *) addr);





	rc = 0;
  end:
	gtp_msg_destroy(msg);
	return rc;
}

static int
gtpc_delete_session_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{

	return 0;
}

static int
gtpc_modify_bearer_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{

	return 0;
}


/*
 *	GTP-C Message handle
 */
static const struct {
	int (*hdl) (gtp_server_worker_t *, struct sockaddr_storage *);
} gtpc_msg_hdl[0xff] = {
	[GTP_ECHO_REQUEST_TYPE]			= { gtpc_echo_request_hdl },
	[GTP_CREATE_SESSION_REQUEST_TYPE]	= { gtpc_create_session_request_hdl },
	[GTP_DELETE_SESSION_REQUEST_TYPE]	= { gtpc_delete_session_request_hdl },
	[GTP_MODIFY_BEARER_REQUEST_TYPE]	= { gtpc_modify_bearer_request_hdl },
	[GTP_CHANGE_NOTIFICATION_REQUEST]	= { NULL },
	[GTP_REMOTE_UE_REPORT_NOTIFICATION]	= { NULL },
	[GTP_RESUME_NOTIFICATION]		= { NULL },
	[GTP_MODIFY_BEARER_COMMAND]		= { NULL },
	[GTP_DELETE_BEARER_COMMAND]		= { NULL },
	[GTP_BEARER_RESSOURCE_COMMAND]		= { NULL },
	[GTP_DELETE_PDN_CONNECTION_SET_REQUEST]	= { NULL },
	[GTP_SUSPEND_NOTIFICATION]		= { NULL },
	[GTP_UPDATE_PDN_CONNECTION_SET_REQUEST]	= { NULL },
};

int
gtpc_router_handle(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;

	if (*(gtpc_msg_hdl[gtph->type].hdl))
		return (*(gtpc_msg_hdl[gtph->type].hdl)) (w, addr);

	/* In router mode, silently ignore message we do not support */
	return -1;
}



/*
 *	GTP-U Message handle
 */
static int
gtpu_echo_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp1_hdr_t *h = (gtp1_hdr_t *) w->buffer;
	gtp1_ie_recovery_t *rec;

	/* 3GPP.TS.129.060 7.2.2 : IE Recovery is mandatory in response message */
	h->type = GTPU_ECHO_RSP_TYPE;
	h->length = htons(ntohs(h->length) + sizeof(gtp1_ie_recovery_t));
	w->buffer_size += sizeof(gtp1_ie_recovery_t);

	rec = (gtp1_ie_recovery_t *) (w->buffer + gtp1_get_header_len(h));
	rec->type = GTP1_IE_RECOVERY_TYPE;
	rec->recovery = 0;

	return 0;
}

static int
gtpu_error_indication_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	return 0;
}

static int
gtpu_end_marker_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	return 0;
}

static const struct {
	int (*hdl) (gtp_server_worker_t *, struct sockaddr_storage *);
} gtpu_msg_hdl[0xff] = {
	[GTPU_ECHO_REQ_TYPE]			= { gtpu_echo_request_hdl },
	[GTPU_ERR_IND_TYPE]			= { gtpu_error_indication_hdl },
	[GTPU_END_MARKER_TYPE]			= { gtpu_end_marker_hdl	},
};

int
gtpu_router_handle(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;
	ssize_t len;

	len = gtpu_get_header_len(w->buffer, w->buffer_size);
	if (len < 0)
		return -1;

	if (*(gtpu_msg_hdl[gtph->type].hdl))
		return (*(gtpu_msg_hdl[gtph->type].hdl)) (w, addr);

	/* Not supported */
	log_message(LOG_INFO, "%s(): GTP-U/path-mgt msg_type:0x%.2x from %s not supported..."
			    , __FUNCTION__
			    , gtph->type
			    , inet_sockaddrtos(addr));
	return -1;
}
