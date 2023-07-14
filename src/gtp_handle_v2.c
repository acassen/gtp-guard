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
#include "gtp_teid.h"
#include "gtp_utils.h"
#include "gtp_xdp.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
extern gtp_teid_t dummy_teid;


/*
 *	Utilities
 */
static int
gtp_update_bearer_id(gtp_teid_t *teid, gtp_ie_eps_bearer_id_t *bearer_id)
{
	if (!bearer_id || teid->type != GTP_TEID_U)
		return -1;

	if (bearer_id->id != teid->bearer_id)
		teid->bearer_id = bearer_id->id;

	return 0;
}
static gtp_teid_t *
gtp_create_teid(uint8_t type, gtp_srv_worker_t *w, gtp_htab_t *h, gtp_htab_t *vh,
		gtp_ie_f_teid_t *ie, gtp_session_t *s, gtp_ie_eps_bearer_id_t *bearer_id)
{
	gtp_teid_t *teid;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	int direction = GTP_TEID_DIRECTION_INGRESS;

	/* Determine if this is related to an existing VTEID.
	 * If so need to restore original TEID related, otherwise
	 * create a new VTEID */
	if (ie->ipv4 == ((struct sockaddr_in *) &srv->addr)->sin_addr.s_addr) {
		teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(ie->teid_grekey));
		if (!teid)
			return NULL;

		gtp_teid_restore(teid, ie);
		gtp_update_bearer_id(teid, bearer_id);
		return teid;
	}

	teid = gtp_teid_get(h, ie);
	if (teid)
		goto masq;

	/* Allocate and bind this new teid */
	teid = gtp_teid_alloc(h, ie, bearer_id);
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

	/* Update bearer_id if needed */
	gtp_update_bearer_id(teid, bearer_id);

	/* TEID masquarade */
	gtp_teid_masq(ie, &srv->addr, teid->vid);

	return teid;
}

static gtp_teid_t *
gtp_append_gtpu(gtp_srv_worker_t *w, gtp_session_t *s, void *arg, uint8_t *ie_buffer)
{
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_ie_eps_bearer_id_t *bearer_id = arg;
	gtp_ie_f_teid_t *ie_f_teid = (gtp_ie_f_teid_t *) ie_buffer;

	return gtp_create_teid(GTP_TEID_U, w, &ctx->gtpu_teid_tab, &ctx->vteid_tab,
			       ie_f_teid, s, bearer_id);
}

static int
gtpc_session_xlat_recovery(gtp_srv_worker_t *w)
{
	gtp_ie_recovery_t *rec;
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_RECOVERY_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		rec = (gtp_ie_recovery_t *) cp;
		rec->recovery = daemon_data->restart_counter;
	}
	return 0;
}

static gtp_teid_t *
gtpc_session_xlat(gtp_srv_worker_t *w, gtp_session_t *s)
{
	gtp_ie_f_teid_t *ie_f_teid = NULL;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL;
	uint8_t *cp, *cp_bid;
	gtp_ie_eps_bearer_id_t *bearer_id = NULL;
	size_t size;

	gtpc_session_xlat_recovery(w);

	cp = gtp_get_ie(GTP_IE_F_TEID_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		ie_f_teid = (gtp_ie_f_teid_t *) cp;
		teid = gtp_create_teid(GTP_TEID_C, w, &ctx->gtpc_teid_tab, &ctx->vteid_tab,
				       ie_f_teid, s, NULL);
	}

	/* Bearer Context handling */
	cp = gtp_get_ie(GTP_IE_BEARER_CONTEXT_TYPE, w->buffer, w->buffer_size);
	if (!cp)
		return teid;

	size = w->buffer_size - (cp - w->buffer);
	cp_bid = gtp_get_ie_offset(GTP_IE_EPS_BEARER_ID, cp, size, sizeof(gtp_ie_t));
	bearer_id = (cp_bid) ? (gtp_ie_eps_bearer_id_t *) cp_bid : NULL;
	gtp_foreach_ie(GTP_IE_F_TEID_TYPE, cp, sizeof(gtp_ie_t), w, s, bearer_id, gtp_append_gtpu);

	return teid;
}


/*
 *	GTP-C Protocol helpers
 */
static gtp_teid_t *
gtpc_echo_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
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

	return &dummy_teid;
}

static gtp_teid_t *
gtpc_create_session_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_ie_imsi_t *ie_imsi;
	gtp_ie_apn_t *ie_apn;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL;
	gtp_conn_t *c;
	gtp_session_t *s;
	gtp_apn_t *apn;
	bool new_conn = false;
	uint64_t imsi;
	uint8_t *cp;
	char apn_str[64];
	int ret;

	/* At least F-TEID present for create session */
	cp = gtp_get_ie(GTP_IE_F_TEID_TYPE, w->buffer, w->buffer_size);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	/* APN selection */
	cp = gtp_get_ie(GTP_IE_APN_TYPE, w->buffer, w->buffer_size);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no Access-Point-Name IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	ie_apn = (gtp_ie_apn_t *) cp;
	memset(apn_str, 0, 64);
	ret = gtp_ie_apn_extract_ni(ie_apn, apn_str, 63);
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

	/* Rewrite APN if needed */
	gtp_ie_apn_rewrite(apn, ie_apn, strlen(apn_str));

	/* TODO: Maybe optimize this stuff by creating a mapping offset table
	 * to avoid a global walking from the buffer begining */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no IMSI IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	ie_imsi = (gtp_ie_imsi_t *) cp;
	imsi = bcd_to_int64(ie_imsi->imsi, ntohs(ie_imsi->h.length));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		c = gtp_conn_alloc(imsi, ctx);
		new_conn = true; /* preserve refcnt */
	}

	/* Rewrite IMSI if needed */
	gtp_ie_imsi_rewrite(apn, cp);

	/* Create a new session object */
	s = gtp_session_alloc(c, apn);

	/* Performing session translation */
	teid = gtpc_session_xlat(w, s);
	if (!teid) {
		log_message(LOG_INFO, "%s(): Error while xlat. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	gtp_vsqn_alloc(w, teid);
	gtp_sqn_masq(w, teid);

	/* Create a vSQN */
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

	log_message(LOG_INFO, "Create-Session-Req:={IMSI:%ld APN:%s F-TEID:%d}"
			    , imsi, apn_str, ntohl(teid->id));

  end:
	if (!new_conn)
		gtp_conn_put(c);
	return teid;
}

static gtp_teid_t *
gtpc_create_session_response_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_ie_cause_t *ie_cause = NULL;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL, *t, *teid_u, *t_u;
	uint8_t *cp;

	t = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!t) {
		/* No TEID present try by SQN */
		t = gtp_vsqn_get(&ctx->vsqn_tab, ntohl(h->sqn));
		if (!t) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.8x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohl(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* IMSI rewrite if needed */
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
		if (cp) {
			gtp_ie_imsi_rewrite(t->session->apn, cp);
		}

		/* SQN masq */
		gtp_sqn_restore(w, t);

		/* Force delete session */
		teid->session->action = GTP_ACTION_DELETE_SESSION;

		return t;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(t->session->apn, cp);
	}

	/* Restore TEID at sGW */
	h->teid = t->id;

	/* Performing session translation */
	teid = gtpc_session_xlat(w, t->session);
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
	 * 3GPP.TS.29.274 8.4 */
	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		ie_cause = (gtp_ie_cause_t *) cp;
		if (!(ie_cause->value >= 16 && ie_cause->value <= 63)) {
			teid->session->action = GTP_ACTION_DELETE_SESSION;
		}
	}

  end:
	gtp_teid_put(t);
	return teid;
}

static gtp_teid_t *
gtpc_delete_session_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_session_t *s;
	gtp_teid_t *teid, *t;
	uint8_t *cp;

	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Set pGW TEID */
	h->teid = teid->id;
	s = teid->session;

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_update(w, teid);
	gtp_sqn_masq(w, teid);

	/* Performing session translation */
	t = gtpc_session_xlat(w, s);
	if (t)
		gtp_teid_put(t);

	return teid;
}

static gtp_teid_t *
gtpc_delete_session_response_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_ie_cause_t *ie_cause = NULL;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid;
	uint8_t *cp;

	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		/* No TEID present try by SQN */
		teid = gtp_vsqn_get(&ctx->vsqn_tab, ntohl(h->sqn));
		if (!teid) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.8x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohl(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* IMSI rewrite if needed */
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
		if (cp) {
			gtp_ie_imsi_rewrite(teid->session->apn, cp);
		}

		/* SQN masq */
		gtp_sqn_restore(w, teid->peer_teid);

		/* Force delete session */
		teid->session->action = GTP_ACTION_DELETE_SESSION;

		return teid;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Set sGW TEID */
	h->teid = teid->id;

	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	/* Test cause code, destroy if <> success.
	 * 3GPP.TS.29.274 8.4 */
	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		ie_cause = (gtp_ie_cause_t *) cp;
		if (ie_cause->value >= 16 && ie_cause->value <= 63) {
			teid->session->action = GTP_ACTION_DELETE_SESSION;
		}
	}

	return teid;
}

static gtp_teid_t *
gtpc_modify_bearer_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL, *t, *t_u = NULL, *pteid;
	gtp_session_t *s;
	uint8_t *cp;

	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Set pGW TEID */
	h->teid = teid->id;
	s = teid->session;

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_update(w, teid);
	gtp_sqn_masq(w, teid);

	/* Performing session translation */
	t = gtpc_session_xlat(w, s);
	if (!t) {
		/* There is no GTP-C update, so just forward */
		return teid;
	}

	/* No peer teid so new teid */
	if (!t->peer_teid) {
		/* Set tunnel endpoint */
		t->sgw_addr = *((struct sockaddr_in *) addr);
		t->pgw_addr = teid->pgw_addr;

		/* GTP-C old */
		pteid = teid->peer_teid;
		t->old_teid = pteid;

		/* GTP-U old */
		t_u = gtp_session_gtpu_teid_get_by_sqn(s, t->sqn);
		if (t_u) {
			t->bearer_teid = t_u;
			t_u->old_teid = (pteid) ? pteid->bearer_teid : NULL;
		}
	}
	gtp_teid_put(t);

	return teid;
}

static gtp_teid_t *
gtpc_modify_bearer_response_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_ie_cause_t *ie_cause = NULL;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL, *teid_u, *oteid;
	uint8_t *cp;

	/* Virtual TEID mapping */
	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		/* No TEID present try by SQN */
		teid = gtp_vsqn_get(&ctx->vsqn_tab, ntohl(h->sqn));
		if (!teid) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.8x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohl(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* IMSI rewrite if needed */
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
		if (cp) {
			gtp_ie_imsi_rewrite(teid->session->apn, cp);
		}

		/* SQN masq */
		gtp_sqn_restore(w, teid->peer_teid);

		return teid;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* TEID set */
	h->teid = teid->id;

	/* Recovery xlat */
	gtpc_session_xlat_recovery(w);

	/* If binding already exist then bearer update already done */
	if (teid->peer_teid)
		goto end;

	/* Test cause code, destroy if <> success.
	 * 3GPP.TS.29.274 8.4 */
	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		ie_cause = (gtp_ie_cause_t *) cp;
		if (ie_cause->value >= 16 && ie_cause->value <= 63) {
			oteid = teid->old_teid;
			if (oteid) {
				gtp_teid_bind(oteid->peer_teid, teid);
				gtp_session_gtpc_teid_destroy(ctx, oteid);
			}
		} else {
			oteid = teid->old_teid;
			if (oteid) {
				/* SQN masq */
				gtp_sqn_restore(w, oteid->peer_teid);
			}
			return teid;
		}
	}

	/* Bearer cause handling */
	teid_u = teid->bearer_teid;
	if (teid_u->old_teid) {
		oteid = teid_u->old_teid;
		if (oteid) {
			gtp_teid_bind(oteid->peer_teid, teid_u);
			gtp_session_gtpu_teid_destroy(ctx, oteid);
		}
	}

  end:
	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	return teid;
}

static gtp_teid_t *
gtpc_delete_bearer_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL;
	gtp_session_t *s;
	gtp_ie_eps_bearer_id_t *bearer_id = NULL;
	uint8_t *cp;

	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_update(w, teid);
	gtp_sqn_masq(w, teid);

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	cp = gtp_get_ie(GTP_IE_EPS_BEARER_ID, w->buffer, w->buffer_size);
	if (!cp)
		return teid;

	bearer_id = (gtp_ie_eps_bearer_id_t *) cp;

	/* Flag related TEID */
	teid->action = GTP_ACTION_DELETE_BEARER;
	gtp_session_set_delete_bearer(ctx, s, bearer_id->id);

	return teid;
}

static int
gtpc_generic_setaddr(gtp_srv_worker_t *w, struct sockaddr_storage *addr,
		     gtp_teid_t *teid, gtp_teid_t *t)
{
	gtp_srv_t *srv = w->srv;

	if (__test_bit(GTP_FL_INGRESS_BIT, &srv->flags)) {
		if (!t->sgw_addr.sin_addr.s_addr)
			t->sgw_addr = *((struct sockaddr_in *) addr);
		if (!t->pgw_addr.sin_addr.s_addr)
			t->pgw_addr = teid->pgw_addr;
	} else  if (__test_bit(GTP_FL_EGRESS_BIT, &srv->flags)) {
		if (!t->sgw_addr.sin_addr.s_addr)
			t->sgw_addr = teid->sgw_addr;
		if (!t->pgw_addr.sin_addr.s_addr)
			t->pgw_addr = *((struct sockaddr_in *) addr);
	}

	return 0;
}

static gtp_teid_t *
gtpc_generic_xlat_request_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid, *t;
	gtp_session_t *s;
	uint8_t *cp;

	/* Virtual TEID mapping */
	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_update(w, teid);
	gtp_sqn_masq(w, teid);

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Performing session translation */
	t = gtpc_session_xlat(w, s);
	if (t) {
		gtpc_generic_setaddr(w, addr, teid, t);
		gtp_teid_put(t);
	}

	return teid;
}

static gtp_teid_t *
gtpc_generic_xlat_response_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid, *t;
	gtp_session_t *s;
	uint8_t *cp;

	/* Virtual TEID mapping */
	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		/* No TEID present try by SQN */
		teid = gtp_vsqn_get(&ctx->vsqn_tab, ntohl(h->sqn));
		if (!teid) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.8x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohl(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* IMSI rewrite if needed */
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
		if (cp) {
			gtp_ie_imsi_rewrite(teid->session->apn, cp);
		}

		/* SQN masq */
		gtp_sqn_restore(w, teid->peer_teid);

		return teid;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Performing session translation */
	t = gtpc_session_xlat(w, s);
	if (t) {
		gtpc_generic_setaddr(w, addr, teid, t);
		gtp_teid_put(t);
	}

	return teid;
}

static gtp_teid_t *
gtpc_generic_xlat_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid, *t;
	gtp_session_t *s;
	uint8_t *cp;

	/* Virtual TEID mapping */
	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->buffer, w->buffer_size);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Performing session translation */
	t = gtpc_session_xlat(w, s);
	if (t) {
		gtpc_generic_setaddr(w, addr, teid, t);
		gtp_teid_put(t);
	}

	return teid;
}

/*
 *	GTP-C Message handle
 */
static const struct {
	gtp_teid_t * (*hdl) (gtp_srv_worker_t *, struct sockaddr_storage *);
} gtpc_msg_hdl[0xff] = {
	[GTP_ECHO_REQUEST_TYPE]			= { gtpc_echo_request_hdl },
	[GTP_CREATE_SESSION_REQUEST_TYPE]	= { gtpc_create_session_request_hdl },
	[GTP_CREATE_SESSION_RESPONSE_TYPE]	= { gtpc_create_session_response_hdl },
	[GTP_DELETE_SESSION_REQUEST_TYPE]	= { gtpc_delete_session_request_hdl },
	[GTP_DELETE_SESSION_RESPONSE_TYPE]	= { gtpc_delete_session_response_hdl },
	[GTP_MODIFY_BEARER_REQUEST_TYPE]	= { gtpc_modify_bearer_request_hdl },
	[GTP_MODIFY_BEARER_RESPONSE_TYPE]	= { gtpc_modify_bearer_response_hdl },
	[GTP_DELETE_BEARER_REQUEST]		= { gtpc_delete_bearer_request_hdl },
	/* Generic request xlat */
	[GTP_CHANGE_NOTIFICATION_REQUEST_REQUEST] = { gtpc_generic_xlat_request_hdl },
	[GTP_RESUME_NOTIFICATION]		= { gtpc_generic_xlat_request_hdl },
	[GTP_MODIFY_BEARER_COMMAND]		= { gtpc_generic_xlat_request_hdl },
	[GTP_DELETE_BEARER_COMMAND]		= { gtpc_generic_xlat_request_hdl },
	[GTP_BEARER_RESSOURCE_COMMAND]		= { gtpc_generic_xlat_request_hdl },
	[GTP_CREATE_BEARER_REQUEST]		= { gtpc_generic_xlat_request_hdl },
	[GTP_UPDATE_BEARER_REQUEST]		= { gtpc_generic_xlat_request_hdl },
	[GTP_UPDATE_PDN_CONNECTION_SET_REQUEST]	= { gtpc_generic_xlat_request_hdl },
	/* Generic response xlat */
	[GTP_CHANGE_NOTIFICATION_REQUEST_RESPONSE] = { gtpc_generic_xlat_response_hdl },
	[GTP_RESUME_ACK]			= { gtpc_generic_xlat_response_hdl },
	[GTP_MODIFY_BEARER_FAILURE_IND]		= { gtpc_generic_xlat_response_hdl },
	[GTP_DELETE_BEARER_FAILURE_IND]		= { gtpc_generic_xlat_response_hdl },
	[GTP_BEARER_RESSOURCE_FAILURE_IND]	= { gtpc_generic_xlat_response_hdl },
	[GTP_CREATE_BEARER_RESPONSE]		= { gtpc_generic_xlat_response_hdl },
	[GTP_UPDATE_BEARER_RESPONSE]		= { gtpc_generic_xlat_response_hdl },
	[GTP_DELETE_BEARER_RESPONSE]		= { gtpc_generic_xlat_response_hdl },
	[GTP_UPDATE_PDN_CONNECTION_SET_RESPONSE] = { gtpc_generic_xlat_response_hdl },
};

gtp_teid_t *
gtpc_handle_v2(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;

	/* Special care to create and delete session */
	if (*(gtpc_msg_hdl[gtph->type].hdl))
		return (*(gtpc_msg_hdl[gtph->type].hdl)) (w, addr);

	/* We are into transparent mode so the only important
	 * matter here is to xlat F-TEID for both GTP-C and
	 * GTP-U in order to force tunnel endpoint to be
	 * our GTP Proxy... just like the lyrics: nothing else matters
	 */
	return gtpc_generic_xlat_hdl(w, addr);
}
