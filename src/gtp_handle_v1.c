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
#include "gtp_dlock.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_session.h"
#include "gtp_handle.h"
#include "gtp_teid.h"
#include "gtp_sqn.h"
#include "gtp_utils.h"
#include "gtp_xdp.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
extern gtp_teid_t dummy_teid;



static gtp_teid_t *
gtp1_create_teid(uint8_t type, gtp_srv_worker_t *w, gtp_htab_t *h, gtp_htab_t *vh,
		gtp_ie_f_teid_t *ie, gtp_session_t *s)
{
	gtp_teid_t *teid;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	int direction = GTP_TEID_DIRECTION_INGRESS;

	/* Determine if this is related to an existing VTEID.
	 * If so need to restore original TEID related, otherwise
	 * create a new VTEID */
	if (ie->ipv4 == ((struct sockaddr_in *) &srv->addr)->sin_addr.s_addr) {
		teid = gtp_vteid_get(&ctx->track[0].vteid_tab, ntohl(ie->teid_grekey));
		if (!teid)
			return NULL;

		gtp_teid_restore(teid, ie);
		return teid;
	}

	teid = gtp_teid_get(h, ie);
	if (teid)
		goto masq;

	/* Allocate and bind this new teid */
	teid = gtp_teid_alloc(h, ie, NULL);
	teid->type = type;
	teid->session = s;
	gtp_vteid_alloc(vh, teid, &w->seed);

	/* Add to list */
	if (type == GTP_TEID_C) {
		gtp_session_gtpc_teid_add(s, teid);
	} else if (type == GTP_TEID_U) {
		gtp_session_gtpu_teid_add(s, teid);

		if (__test_bit(GTP_FL_EGRESS_BIT, &srv->flags))
			direction = GTP_TEID_DIRECTION_EGRESS;

		/* Fast-Path setup */
		gtp_xdpfwd_teid_action(XDPFWD_RULE_ADD, teid, direction);
	}

  masq:
	/* Keep sqn track */
	gtp_sqn_update(w, teid);

	/* TEID masquarade */
	gtp_teid_masq(ie, &srv->addr, teid->vid);

	return teid;
}

static int
gtp1_session_xlat_recovery(gtp_srv_worker_t *w)
{
	gtp1_ie_recovery_t *rec;
	uint8_t *cp;

	cp = gtp_get_ie(GTP1_IE_RECOVERY_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		rec = (gtp1_ie_recovery_t *) cp;
		rec->recovery = daemon_data->restart_counter;
	}
	return 0;
}

static gtp_teid_t *
gtp1_session_xlat(gtp_srv_worker_t *w, gtp_session_t *s)
{
	gtp_ie_f_teid_t *ie_f_teid;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL;
	gtp1_ie_teid_t *teid_c = NULL, *teid_u = NULL;
	uint32_t *gsn_address_c = NULL, *gsn_address_u = NULL;
	gtp1_ie_t *ie;
	uint8_t *cp;

	gtp1_session_xlat_recovery(w);

	/* Control & Data Plane IE */
	cp = gtp1_get_ie(GTP1_IE_TEID_CONTROL_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		teid_c = (gtp1_ie_teid_t *) cp;
	}

	cp = gtp1_get_ie(GTP1_IE_TEID_DATA_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		teid_u = (gtp1_ie_teid_t *) cp;
	}

	/* GSN Address for Control-Plane & Data-Plane */
	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gsn_address_c = (uint32_t *) (cp + sizeof(gtp1_ie_t));
		ie = (gtp1_ie_t *) cp;
		cp = gtp1_get_ie_offset(GTP1_IE_GSN_ADDRESS_TYPE, cp+sizeof(gtp1_ie_t)+ntohs(ie->length)
								, w->buffer + w->buffer_size);
		if (cp) {
			gsn_address_u = (uint32_t *) (cp + sizeof(gtp1_ie_t));
		}
	}

	PMALLOC(ie_f_teid);

	/* Control-Plane */
	ie_f_teid->teid_grekey = teid_c->id;
	ie_f_teid->v4 = 1;
	ie_f_teid->ipv4 = *gsn_address_c;
	teid = gtp1_create_teid(GTP_TEID_C, w
					  , &ctx->track[0].gtpc_teid_tab
					  , &ctx->track[0].vteid_tab
					  , ie_f_teid, s);

	/* User-Plane */
	if (teid_u && gsn_address_u) {
		ie_f_teid->teid_grekey = teid_u->id;
		ie_f_teid->v4 = 1;
		ie_f_teid->ipv4 = *gsn_address_u;
		gtp1_create_teid(GTP_TEID_U, w
					, &ctx->track[0].gtpc_teid_tab
					, &ctx->track[0].vteid_tab
					, ie_f_teid, s);
	}

	FREE(ie_f_teid);
	return teid;
}


static gtp_teid_t *
gtp1_echo_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp1_ie_recovery_t *rec;
	uint8_t *cp;

	cp = gtp_get_ie(GTP1_IE_RECOVERY_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		rec = (gtp1_ie_recovery_t *) cp;
		rec->recovery = daemon_data->restart_counter;
	}

	h->type = GTP_ECHO_RESPONSE_TYPE;

	return &dummy_teid;
}

static gtp_teid_t *
gtp1_create_pdp_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp1_ie_apn_t *ie_apn;
	gtp1_ie_imsi_t *ie_imsi;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL;
	gtp_conn_t *c;
	gtp_session_t *s = NULL;
	gtp_apn_t *apn;
	bool new_conn = false, retransmit = false;
	uint64_t imsi;
	uint8_t *cp;
	char apn_str[64];
	int ret;

	/* Retransmission detection */
	s = gtpc_retransmit_detected(w);
	if (s)
		retransmit = true;

	/* At least TEID CONTROL for creation */
	cp = gtp1_get_ie(GTP1_IE_TEID_CONTROL_TYPE, w->buffer, w->buffer_size);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no TEID-Control IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	/* At least GSN Address for Control-Plane */
	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, w->buffer, w->buffer_size);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no C-Plane GSN-Address present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	/* APN selection */
	cp = gtp1_get_ie(GTP1_IE_APN_TYPE, w->buffer, w->buffer_size);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no APN IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}
	ie_apn = (gtp1_ie_apn_t *) cp;
	memset(apn_str, 0, 64);
	ret = gtp1_ie_apn_extract(ie_apn, apn_str, 63);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error parsing Access-Point-Name IE. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	apn = gtp_apn_get(apn_str);
	if (!apn) {
		log_message(LOG_INFO, "%s(): Unknown Access-Point-Name:%s. ignoring..."
				    , __FUNCTION__, apn_str);
		return NULL;
	}

	/* IMSI */
	cp = gtp1_get_ie(GTP1_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no IMSI IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	ie_imsi = (gtp1_ie_imsi_t *) cp;
	imsi = bcd_to_int64(ie_imsi->imsi, sizeof(ie_imsi->imsi));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		c = gtp_conn_alloc(imsi, ctx);
		new_conn = true; /* preserve refcnt */
	}

	/* Rewrite IMSI if needed */
	gtp_imsi_rewrite(apn, ie_imsi->imsi);

	/* Create a new session object */
	if (!retransmit)
		s = gtp_session_alloc(c, apn);

	/* Performing session translation */
	teid = gtp1_session_xlat(w, s);
	if (!teid) {
		log_message(LOG_INFO, "%s(): Error while xlat. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	log_message(LOG_INFO, "Create-PDP-Req:={IMSI:%ld APN:%s TEID-C:0x%.8x}%s"
			    , imsi, apn_str, ntohl(teid->id)
			    , (retransmit) ? " (retransmit)" : "");
	if (retransmit) {
		gtp_sqn_masq(w, teid);
		goto end;
	}

	/* Create a vSQN */
	gtp_vsqn_alloc(w, teid);
	gtp_sqn_masq(w, teid);

	/* Set addr tunnel endpoint */
	teid->sgw_addr = *((struct sockaddr_in *) addr);

	/* Update last sGW visited */
	c->sgw_addr = *((struct sockaddr_in *) addr);

	/* pGW selection */
	if (__test_bit(GTP_FL_FORCE_PGW_BIT, &ctx->flags)) {
		teid->pgw_addr = *(struct sockaddr_in *) &ctx->pgw_addr;
		goto end;
	}

	ret = gtp_resolv_schedule_pgw(apn, &teid->pgw_addr, &teid->sgw_addr);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Unable to schedule pGW for apn:%s"
				    , __FUNCTION__
				    , apn->name);
	}

  end:
	if (!new_conn)
		gtp_conn_put(c);
	return teid;
}

static gtp_teid_t *
gtp1_create_pdp_response_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp1_hdr_t *h = (gtp1_hdr_t *) w->buffer;
	gtp1_ie_cause_t *ie_cause = NULL;
	gtp1_ie_imsi_t *ie_imsi;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL, *t, *teid_u, *t_u;
	uint8_t *cp;

	t = gtp_vteid_get(&ctx->track[0].vteid_tab, ntohl(h->teid));
	if (!t) {
		/* No TEID present try by SQN */
		t = gtp_vsqn_get(&ctx->track[1].vsqn_tab, ntohl(h->sqn));
		if (!t) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.4x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohs(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* IMSI rewrite if needed */
		cp = gtp1_get_ie(GTP1_IE_IMSI_TYPE, w->buffer, w->buffer_size);
		if (cp) {
			ie_imsi = (gtp1_ie_imsi_t *) cp;
			gtp_imsi_rewrite(t->session->apn, ie_imsi->imsi);
		}

		/* SQN masq */
		gtp_sqn_restore(w, t);

		/* Force delete session */
		teid->session->action = GTP_ACTION_DELETE_SESSION;

		return t;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP1_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		ie_imsi = (gtp1_ie_imsi_t *) cp;
		gtp_imsi_rewrite(t->session->apn, ie_imsi->imsi);
	}

	/* Restore TEID at sGW */
	h->teid = t->id;

	/* Performing session translation */
	teid = gtp1_session_xlat(w, t->session);
	if (!teid) {
		teid = t;

		/* SQN masq */
		gtp_sqn_restore(w, t);

		/* Force delete session */
		t->session->action = GTP_ACTION_DELETE_SESSION;

		goto end;
	}

	/* Create teid binding */
	gtp_teid_bind(teid, t);

	/* create related GTP-U binding */
	teid_u = gtp_session_gtpu_teid_get_by_sqn(t->session, teid->sqn);
	t_u = gtp_session_gtpu_teid_get_by_sqn(t->session, t->sqn);
	gtp_teid_bind(teid_u, t_u);

	/* GTP-C <-> GTP-U ref */
	t->bearer_teid = t_u;
	teid->bearer_teid = teid_u;

	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	/* Set addr tunnel endpoint */
	teid->pgw_addr = *((struct sockaddr_in *) addr);
	teid->sgw_addr = t->sgw_addr;

	/* Test cause code, destroy if <> success.
	 * 3GPP.TS.129.060 7.7.1 */
	cp = gtp_get_ie(GTP1_IE_CAUSE_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		ie_cause = (gtp1_ie_cause_t *) cp;
		if (!(ie_cause->value >= 128 && ie_cause->value <= 191)) {
			teid->session->action = GTP_ACTION_DELETE_SESSION;
		}
	}

  end:
	gtp_teid_put(t);
	return teid;
}

static gtp_teid_t *
gtp1_update_pdp_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	dump_buffer("GTPv1 Update-Req ", (char *) w->buffer, w->buffer_size);
	return NULL;
}

static gtp_teid_t *
gtp1_update_pdp_response_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	dump_buffer("GTPv1 Update-Resp ", (char *) w->buffer, w->buffer_size);
	return NULL;
}

static gtp_teid_t *
gtp1_delete_pdp_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	dump_buffer("GTPv1 Delete-Req ", (char *) w->buffer, w->buffer_size);
	return NULL;
}

static gtp_teid_t *
gtp1_delete_pdp_response_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	dump_buffer("GTPv1 Delete-Resp ", (char *) w->buffer, w->buffer_size);
	return NULL;
}


/*
 *	GTP-C Message handle
 */
static const struct {
	gtp_teid_t * (*hdl) (gtp_srv_worker_t *, struct sockaddr_storage *);
} gtpc_msg_hdl[0xff] = {
	[GTP_ECHO_REQUEST_TYPE]			= { gtp1_echo_request_hdl },
	[GTP_CREATE_PDP_CONTEXT_REQUEST]	= { gtp1_create_pdp_request_hdl },
	[GTP_CREATE_PDP_CONTEXT_RESPONSE]	= { gtp1_create_pdp_response_hdl },
	[GTP_UPDATE_PDP_CONTEXT_REQUEST]	= { gtp1_update_pdp_request_hdl },
	[GTP_UPDATE_PDP_CONTEXT_RESPONSE]	= { gtp1_update_pdp_response_hdl },
	[GTP_DELETE_PDP_CONTEXT_REQUEST]	= { gtp1_delete_pdp_request_hdl },
	[GTP_DELETE_PDP_CONTEXT_RESPONSE]	= { gtp1_delete_pdp_response_hdl },
};

gtp_teid_t *
gtpc_handle_v1(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;

	if (*(gtpc_msg_hdl[gtph->type].hdl))
		return (*(gtpc_msg_hdl[gtph->type].hdl)) (w, addr);

	dump_buffer("GTPv1 Unknown", (char *) w->buffer, w->buffer_size);
	return NULL;
}