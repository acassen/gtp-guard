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

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


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
gtp_create_teid(uint8_t type, int direction, gtp_server_worker_t *w, gtp_htab_t *h, gtp_htab_t *vh,
		gtp_f_teid_t *f_teid, gtp_session_t *s, gtp_ie_eps_bearer_id_t *bearer_id)
{
	gtp_teid_t *teid;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_server_t *srv_gtpc_ingress = &ctx->gtpc;
	gtp_server_t *srv_gtpc_egress = &ctx->gtpc_egress;
	gtp_server_t *srv_gtpu = &ctx->gtpu;

	/* Determine if this is related to an existing VTEID.
	 * If so need to restore original TEID related, otherwise
	 * create a new VTEID */
	if ((*f_teid->ipv4 == ((struct sockaddr_in *) &srv_gtpc_ingress->addr)->sin_addr.s_addr) ||
	    (*f_teid->ipv4 == ((struct sockaddr_in *) &srv_gtpc_egress->addr)->sin_addr.s_addr)) {
		teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(*f_teid->teid_grekey));
		if (!teid)
			return NULL;

		gtp_teid_restore(teid, f_teid);
		gtp_update_bearer_id(teid, bearer_id);
		return teid;
	}

	teid = gtp_teid_get(h, f_teid);
	if (teid)
		goto masq;

	/* Allocate and bind this new teid */
	teid = gtp_teid_alloc(h, f_teid, bearer_id);
	teid->type = type;
	__set_bit(direction ? GTP_TEID_FL_EGRESS : GTP_TEID_FL_INGRESS, &teid->flags);
	teid->session = s;
	__set_bit(GTP_TEID_FL_FWD, &teid->flags);
	gtp_vteid_alloc(vh, teid, &w->seed);

	/* Add to list */
	if (type == GTP_TEID_C)
		gtp_session_gtpc_teid_add(s, teid);
	else if (type == GTP_TEID_U)
		gtp_session_gtpu_teid_add(s, teid);

  masq:
	/* Keep sqn track */
	gtp_sqn_update(w, teid);

	/* Update bearer_id if needed */
	gtp_update_bearer_id(teid, bearer_id);

	/* TEID masquarade */
	srv = srv_gtpu;
	if (type == GTP_TEID_C) {
		srv = srv_gtpc_ingress;
		if (__test_bit(GTP_FL_CTL_BIT, &srv_gtpc_egress->flags) &&
		    __test_bit(GTP_TEID_FL_INGRESS, &teid->flags))
			srv = srv_gtpc_egress;
	}
	gtp_teid_masq(f_teid, &srv->addr, teid->vid);

	return teid;
}

static gtp_teid_t *
gtp_append_gtpu(gtp_server_worker_t *w, gtp_session_t *s, int direction, void *arg, uint8_t *ie_buffer)
{
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_ie_eps_bearer_id_t *bearer_id = arg;
	gtp_f_teid_t f_teid;

	f_teid.version = 2;
	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));

	return gtp_create_teid(GTP_TEID_U, direction, w
					 , &ctx->gtpu_teid_tab
					 , &ctx->vteid_tab
					 , &f_teid, s, bearer_id);
}

static int
gtpc_session_xlat_recovery(gtp_server_worker_t *w)
{
	gtp_ie_recovery_t *rec;
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_RECOVERY_TYPE, w->pbuff);
	if (cp) {
		rec = (gtp_ie_recovery_t *) cp;
		rec->recovery = daemon_data->restart_counter;
	}
	return 0;
}

static gtp_teid_t *
gtpc_session_xlat(gtp_server_worker_t *w, gtp_session_t *s, int direction)
{
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_f_teid_t f_teid;
	gtp_teid_t *teid = NULL;
	uint8_t *cp, *cp_bid, *end;
	gtp_ie_eps_bearer_id_t *bearer_id = NULL;
	gtp_ie_t *ie;
	size_t size;

	gtpc_session_xlat_recovery(w);

	cp = gtp_get_ie(GTP_IE_F_TEID_TYPE, w->pbuff);
	if (cp) {
		f_teid.version = 2;
		f_teid.teid_grekey = (uint32_t *) (cp + offsetof(gtp_ie_f_teid_t, teid_grekey));
		f_teid.ipv4 = (uint32_t *) (cp + offsetof(gtp_ie_f_teid_t, ipv4));
		teid = gtp_create_teid(GTP_TEID_C, direction, w
						 , &ctx->gtpc_teid_tab
						 , &ctx->vteid_tab
						 , &f_teid, s, NULL);
	}

	/* Bearer Context handling */
	cp = gtp_get_ie(GTP_IE_BEARER_CONTEXT_TYPE, w->pbuff);
	if (!cp)
		return teid;

	size = pkt_buffer_size(w->pbuff) - (cp - w->pbuff->head);
	cp_bid = gtp_get_ie_offset(GTP_IE_EPS_BEARER_ID_TYPE, cp, size, sizeof(gtp_ie_t));
	bearer_id = (cp_bid) ? (gtp_ie_eps_bearer_id_t *) cp_bid : NULL;
	ie = (gtp_ie_t *) cp;
	end = cp + sizeof(gtp_ie_t) + ntohs(ie->length);
	gtp_foreach_ie(GTP_IE_F_TEID_TYPE, cp, sizeof(gtp_ie_t), end,
		       w, s, direction, bearer_id, gtp_append_gtpu);

	return teid;
}

/*
 *	GTP-C Protocol helpers
 */
static gtp_teid_t *
gtpc_echo_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_ie_recovery_t *rec;
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_RECOVERY_TYPE, w->pbuff);
	if (cp) {
		rec = (gtp_ie_recovery_t *) cp;
		rec->recovery = daemon_data->restart_counter;
	}

	h->type = GTP_ECHO_RESPONSE_TYPE;

	return &dummy_teid;
}

static gtp_teid_t *
gtpc_create_session_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_ie_imsi_t *ie_imsi;
	gtp_ie_apn_t *ie_apn;
	gtp_ie_serving_network_t *ie_serving_network;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL;
	gtp_conn_t *c;
	gtp_session_t *s = NULL;
	gtp_apn_t *apn;
	bool retransmit = false;
	uint64_t imsi;
	uint8_t *cp, *serving_network;
	char apn_str[64];
	char apn_plmn[64];
	int err;

	/* Retransmission detection: Operating in a tranparent
	 * way in order to preserve transitivity of messages, so
	 * that if we get a retransmission, simply retransmit this
	 * to remote previously elected pGW.
	 *
	 * TODO: maybe implements a flood detection by maintaining a dyn
	 *       map keeping track of remote sGW request-rate by
	 *       message type in order to detect any changing trend */
	s = gtpc_retransmit_detected(w);
	if (s)
		retransmit = true;

	/* At least F-TEID present for create session */
	cp = gtp_get_ie(GTP_IE_F_TEID_TYPE, w->pbuff);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	/* Serving Network */
	serving_network = gtp_get_ie(GTP_IE_SERVING_NETWORK_TYPE, w->pbuff);
	if (!serving_network) {
		log_message(LOG_INFO, "%s(): no Serving Netwokr IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	/* APN selection */
	cp = gtp_get_ie(GTP_IE_APN_TYPE, w->pbuff);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no Access-Point-Name IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	ie_apn = (gtp_ie_apn_t *) cp;
	memset(apn_str, 0, 64);
	err = gtp_ie_apn_extract_ni(ie_apn, apn_str, 63);
	if (err) {
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
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no IMSI IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	ie_imsi = (gtp_ie_imsi_t *) cp;
	imsi = bcd_to_int64(ie_imsi->imsi, ntohs(ie_imsi->h.length));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		c = gtp_conn_alloc(imsi);
	}

	/* Rewrite IMSI if needed */
	gtp_ie_imsi_rewrite(apn, cp);

	/* Create a new session object */
	if (!retransmit) {
		s = gtp_session_alloc(c, apn, gtp_proxy_gtpc_teid_destroy
					    , gtp_proxy_gtpu_teid_destroy);
		s->w = w;
	}

	/* Performing session translation */
	teid = gtpc_session_xlat(w, s, direction);
	if (!teid) {
		log_message(LOG_INFO, "%s(): Error while xlat. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	/* Set Serving PLMN */
	ie_serving_network = (gtp_ie_serving_network_t *) serving_network;
	memcpy(s->serving_plmn.plmn, ie_serving_network->mcc_mnc, GTP_PLMN_MAX_LEN);

	/* Set session roaming status */
	err = gtp_session_roaming_status_set(s);
	if (err) {
		log_message(LOG_INFO, "%s(): unable to set Roaming Status for IMSI:%ld"
				    , __FUNCTION__
				    , c->imsi);
	}

	/* ULI tag */
	if (__test_bit(GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4, &apn->flags) &&
	    __test_bit(GTP_SESSION_FL_ROAMING_OUT, &s->flags))
		gtp_ie_uli_update(w->pbuff, &apn->egci_plmn, (struct sockaddr_in *) addr);

	log_message(LOG_INFO, "Create-Session-Req:={IMSI:%ld APN:%s F-TEID:0x%.8x Roaming-Status:%s}%s"
			    , imsi, apn_str, ntohl(teid->id)
			    , gtp_session_roaming_status_str(s)
			    , (retransmit) ? " (retransmit)" : "");
	if (retransmit) {
		gtp_sqn_masq(w, teid);
		goto end;
	}

	/* Create a vSQN */
	gtp_vsqn_alloc(w, teid, false);
	gtp_sqn_masq(w, teid);

	/* Set addr tunnel endpoint */
	gtp_teid_update_sgw(teid, addr);

	/* Update last sGW visited */
	c->sgw_addr = *((struct sockaddr_in *) addr);

	/* pGW selection */
	if (__test_bit(GTP_FL_FORCE_PGW_BIT, &ctx->flags)) {
		teid->pgw_addr = *(struct sockaddr_in *) &ctx->pgw_addr;
		goto end;
	}

	if (__test_bit(GTP_APN_FL_REALM_DYNAMIC, &apn->flags)) {
		err = gtp_ie_apn_extract_plmn(ie_apn, apn_plmn, 63);
		if (err)
			goto end;

		err = gtp_sched_dynamic(apn, apn_str, apn_plmn, &teid->pgw_addr, &teid->sgw_addr, &s->flags);
		if (err) {
			log_message(LOG_INFO, "%s(): Unable to schedule pGW for apn:'%s.apn.epc.%s.3gppnetwork.org.'"
					    , __FUNCTION__
					    , apn_str, apn_plmn);
			gtp_teid_put(teid);
			gtp_session_destroy(s);
			teid = NULL;
		}

		goto end;
	}

	err = gtp_sched(apn, &teid->pgw_addr, &teid->sgw_addr, &s->flags);
	if (err) {
		log_message(LOG_INFO, "%s(): Unable to schedule pGW for apn:%s"
				    , __FUNCTION__
				    , apn->name);
		gtp_teid_put(teid);
		gtp_session_destroy(s);
		teid = NULL;
    }

  end:
	gtp_conn_put(c);
	return teid;
}

static gtp_teid_t *
gtpc_create_session_response_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_ie_cause_t *ie_cause = NULL;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
		if (cp) {
			gtp_ie_imsi_rewrite(t->session->apn, cp);
		}

		/* Recovery xlat */
		gtpc_session_xlat_recovery(w);

		/* SQN masq */
		gtp_sqn_restore(w, t);

		/* Force delete session */
		t->session->action = GTP_ACTION_DELETE_SESSION;

		return t;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(t->session->apn, cp);
	}

	/* Restore TEID at sGW */
	h->teid = t->id;

	/* Performing session translation */
	teid = gtpc_session_xlat(w, t->session, direction);
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
	inet_ip4tosockaddr(teid->ipv4, (struct sockaddr_storage *) &teid->pgw_addr);
	teid->pgw_addr.sin_port = htons(GTP_C_PORT);
	teid->sgw_addr = t->sgw_addr;

	/* Test cause code, destroy if <> success.
	 * 3GPP.TS.29.274 8.4 */
	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, w->pbuff);
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
gtpc_delete_session_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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

	log_message(LOG_INFO, "Delete-Session-Req:={F-TEID:0x%.8x}", ntohl(teid->id));

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Set pGW TEID */
	h->teid = teid->id;
	s = teid->session;

	/* Update addr tunnel endpoint */
	gtp_teid_update_sgw(teid, addr);
	gtp_teid_update_sgw(teid->peer_teid, addr);

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_alloc(w, teid, false);
	gtp_sqn_masq(w, teid);

	/* Performing session translation */
	t = gtpc_session_xlat(w, s, direction);
	if (t)
		gtp_teid_put(t);

	/* Finally set expiration timeout if used */
	if (__test_bit(GTP_FL_SESSION_EXPIRATION_DELETE_TO_BIT, &ctx->flags))
		gtp_session_mod_timer(s, ctx->session_delete_to);

	return teid;
}

static gtp_teid_t *
gtpc_delete_session_response_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_ie_cause_t *ie_cause = NULL;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
		if (cp) {
			gtp_ie_imsi_rewrite(teid->session->apn, cp);
		}

		/* Recovery xlat */
		gtpc_session_xlat_recovery(w);

		/* SQN masq */
		gtp_sqn_restore(w, teid->peer_teid);

		/* Force delete session */
		teid->session->action = GTP_ACTION_DELETE_SESSION;

		return teid;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Set sGW TEID */
	h->teid = teid->id;

	/* Recovery xlat */
	gtpc_session_xlat_recovery(w);

	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	/* Test cause code, destroy if == success.
	 * 3GPP.TS.29.274 8.4 */
	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, w->pbuff);
	if (cp) {
		ie_cause = (gtp_ie_cause_t *) cp;
		if ((ie_cause->value >= GTP_CAUSE_REQUEST_ACCEPTED &&
		     ie_cause->value <= GTP_CAUSE_CONTEXT_NOT_FOUND) ||
		    ie_cause->value == GTP_CAUSE_INVALID_PEER) {
			teid->session->action = GTP_ACTION_DELETE_SESSION;
		}
	}

	return teid;
}

static gtp_teid_t *
gtpc_modify_bearer_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_ie_serving_network_t *ie_serving_network;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL, *t, *t_u = NULL, *pteid;
	gtp_session_t *s;
	bool mobility = false;
	uint8_t *cp;
	int err;

	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	/* Mobility from 3G to 4G */
	if (teid->version == 1) {
		mobility = true;
		teid->version = 2;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Set pGW TEID */
	h->teid = teid->id;
	s = teid->session;

	/* Update GTP-C with current sGW */
	gtp_teid_update_sgw(teid, addr);
	gtp_teid_update_sgw(teid->peer_teid, addr);

	/* Update Serving Network */
	cp = gtp_get_ie(GTP_IE_SERVING_NETWORK_TYPE, w->pbuff);
	if (cp) {
		ie_serving_network = (gtp_ie_serving_network_t *) cp;
		memcpy(s->serving_plmn.plmn, ie_serving_network->mcc_mnc, GTP_PLMN_MAX_LEN);
	}

	/* Update session roaming status */
	err = gtp_session_roaming_status_set(s);
	if (err) {
		log_message(LOG_INFO, "%s(): unable to update Roaming Status for IMSI:%ld"
				    , __FUNCTION__
				    , s->conn->imsi);
	}

	/* ULI tag */
	if (__test_bit(GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4, &s->apn->flags) &&
	    __test_bit(GTP_SESSION_FL_ROAMING_OUT, &s->flags))
		gtp_ie_uli_update(w->pbuff, &s->apn->egci_plmn, (struct sockaddr_in *) addr);

	log_message(LOG_INFO, "Modify-Bearer-Req:={F-TEID:0x%.8x Roaming-Status:%s}%s"
			    , ntohl(teid->id)
			    , gtp_session_roaming_status_str(s)
			    , mobility ? " (3G Mobility)" : "");

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_alloc(w, teid, false);
	gtp_sqn_masq(w, teid);

	/* Performing session translation */
	t = gtpc_session_xlat(w, s, direction);
	if (!t) {
		/* There is no GTP-C update, so just forward */
		return teid;
	}

	if (t->peer_teid)
		goto end;

	/* No peer teid so new teid */
	/* Set tunnel endpoint */
	gtp_teid_update_sgw(t, addr);
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

  end:
	gtp_teid_put(t);
	return teid;
}

static gtp_teid_t *
gtpc_modify_bearer_response_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_ie_cause_t *ie_cause = NULL;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
		if (cp) {
			gtp_ie_imsi_rewrite(teid->session->apn, cp);
		}

		/* Recovery xlat */
		gtpc_session_xlat_recovery(w);

		/* SQN masq */
		gtp_sqn_restore(w, teid->peer_teid);

		return teid;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
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
	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, w->pbuff);
	if (!cp)
		return teid;

	oteid = teid->old_teid;
	ie_cause = (gtp_ie_cause_t *) cp;
	if (!(ie_cause->value >= GTP_CAUSE_REQUEST_ACCEPTED &&
	      ie_cause->value <= 63)) {
		if (oteid)
			gtp_sqn_restore(w, oteid->peer_teid);
		return teid;
	}

	if (oteid) {
		gtp_teid_bind(oteid->peer_teid, teid);
		gtp_session_gtpc_teid_destroy(oteid);
	}

	/* Bearer cause handling */
	teid_u = teid->bearer_teid;
	if (teid_u && teid_u->old_teid) {
		oteid = teid_u->old_teid;
		if (oteid->peer_teid)
			gtp_teid_bind(oteid->peer_teid, teid_u);
		gtp_session_gtpu_teid_destroy(oteid);
	}

  end:
	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	return teid;
}

static gtp_teid_t *
gtpc_delete_bearer_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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

	log_message(LOG_INFO, "Delete-Bearer-Req:={F-TEID:0x%.8x}", ntohl(teid->id));

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Recovery xlat */
	gtpc_session_xlat_recovery(w);

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_alloc(w, teid, false);
	gtp_sqn_masq(w, teid);

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Msg from pGW, update pGW addr */
	gtp_teid_update_pgw(teid, addr);
	gtp_teid_update_pgw(teid->peer_teid, addr);

	cp = gtp_get_ie(GTP_IE_EPS_BEARER_ID_TYPE, w->pbuff);
	if (!cp)
		return teid;

	bearer_id = (gtp_ie_eps_bearer_id_t *) cp;

	/* Flag related TEID */
	teid->action = GTP_ACTION_DELETE_BEARER;
	gtp_session_set_delete_bearer(s, bearer_id);

	return teid;
}

static gtp_teid_t *
gtpc_delete_bearer_response_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_ie_cause_t *ie_cause = NULL;
	gtp_teid_t *teid = NULL;
	gtp_session_t *s;
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
	}

	/* Recovery xlat */
	gtpc_session_xlat_recovery(w);

	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Test cause code, destroy if == success.
	 * 3GPP.TS.29.274 8.4 */
	cp = gtp_get_ie(GTP_IE_CAUSE_TYPE, w->pbuff);
	if (cp) {
		ie_cause = (gtp_ie_cause_t *) cp;
		if (ie_cause->value >= GTP_CAUSE_REQUEST_ACCEPTED &&
		    ie_cause->value <= GTP_CAUSE_CONTEXT_NOT_FOUND) {
			if (ie_cause->value == GTP_CAUSE_CONTEXT_NOT_FOUND)
				teid->session->action = GTP_ACTION_DELETE_SESSION;
			gtp_session_destroy_bearer(s);
		}
	}

	return teid;
}

static int
gtpc_generic_setaddr(struct sockaddr_storage *addr, int direction, gtp_teid_t *teid, gtp_teid_t *t)
{
	if (direction == GTP_INGRESS) {
		if (!t->sgw_addr.sin_addr.s_addr)
			gtp_teid_update_sgw(t, addr);
		if (!t->pgw_addr.sin_addr.s_addr)
			t->pgw_addr = teid->pgw_addr;
		return 0;
	}

	if (!t->sgw_addr.sin_addr.s_addr)
		t->sgw_addr = teid->sgw_addr;
	if (!t->pgw_addr.sin_addr.s_addr)
		gtp_teid_update_pgw(t, addr);
	return 0;
}

static int
gtpc_generic_updateaddr(int direction, gtp_teid_t *teid, struct sockaddr_storage *addr)
{
	if (direction == GTP_INGRESS) {
		gtp_teid_update_sgw(teid, addr);
		gtp_teid_update_sgw(teid->peer_teid, addr);
		return 0;
	}

	gtp_teid_update_pgw(teid, addr);
	gtp_teid_update_pgw(teid->peer_teid, addr);
	return 0;
}

static gtp_teid_t *
gtpc_generic_xlat_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_teid_t *teid, *t;
	gtp_session_t *s;
	uint8_t *cp;
	uint32_t sqn;

	/* Virtual TEID mapping */
	teid = gtp_vteid_get(&ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* 3GPP TS 29.274 section 7.6 : if MSB is set then simply
	 * be transitive to the message sqn since it is related to
	 * a previous Command message otherwise update SQN */
	sqn = (h->teid_presence) ? ntohl(h->sqn) : ntohl(h->sqn_only);
	if (sqn & (1 << 31)) {
		t = gtp_vsqn_get(&ctx->vsqn_tab, sqn);
		if (t) {
			gtp_sqn_restore(w, t);
		}
	} else {
		gtp_sqn_update(w, teid);
		gtp_vsqn_alloc(w, teid, false);
		gtp_sqn_masq(w, teid);
	}

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Update addr */
	gtpc_generic_updateaddr(direction, teid, addr);

	/* Performing session translation */
	t = gtpc_session_xlat(w, s, direction);
	if (t) {
		gtpc_generic_setaddr(addr, direction, teid, t);
		gtp_teid_put(t);
	}

	return teid;
}

static gtp_teid_t *
gtpc_generic_xlat_command_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_vsqn_alloc(w, teid, true);
	gtp_sqn_masq(w, teid);

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Update addr */
	gtpc_generic_updateaddr(direction, teid, addr);

	/* Performing session translation */
	t = gtpc_session_xlat(w, s, direction);
	if (t) {
		gtpc_generic_setaddr(addr, direction, teid, t);
		gtp_teid_put(t);
	} else {
		/* GTP-C F-TEID is not mandatory, but we need to
		 * update peer sqn for futur request */
		gtp_sqn_update(w, teid->peer_teid);
	}

	return teid;
}

static gtp_teid_t *
gtpc_generic_xlat_response_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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
		cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
		if (cp) {
			gtp_ie_imsi_rewrite(teid->session->apn, cp);
		}

		/* SQN masq */
		gtp_sqn_restore(w, teid->peer_teid);

		return teid;
	}

	/* IMSI rewrite if needed */
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* SQN masq */
	gtp_sqn_restore(w, teid->peer_teid);

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Performing session translation */
	t = gtpc_session_xlat(w, s, direction);
	if (t) {
		gtpc_generic_setaddr(addr, direction, teid, t);
		gtp_teid_put(t);
	}

	return teid;
}

static gtp_teid_t *
gtpc_generic_xlat_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr, int direction)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_proxy_t *ctx = srv->ctx;
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
	cp = gtp_get_ie(GTP_IE_IMSI_TYPE, w->pbuff);
	if (cp) {
		gtp_ie_imsi_rewrite(teid->session->apn, cp);
	}

	/* TEID set */
	h->teid = teid->id;
	s = teid->session;

	/* Update addr */
	gtpc_generic_updateaddr(direction, teid, addr);

	/* Performing session translation */
	t = gtpc_session_xlat(w, s, direction);
	if (t) {
		gtpc_generic_setaddr(addr, direction, teid, t);
		gtp_teid_put(t);
	}

	return teid;
}

/*
 *	GTP-C Message handle
 */
static const struct {
	uint8_t family;	/* GTP_INIT : Initial | GTP_TRIG : Triggered*/
	int direction;	/* GTP_INGRESS : sGW -> pGW | GTP_EGRESS  : pGW -> sGW */
	gtp_teid_t * (*hdl) (gtp_server_worker_t *, struct sockaddr_storage *, int);
} gtpc_msg_hdl[0xff + 1] = {
	[GTP_ECHO_REQUEST_TYPE]			= { GTP_INIT, GTP_INGRESS, gtpc_echo_request_hdl },
	[GTP_CREATE_SESSION_REQUEST_TYPE]	= { GTP_INIT, GTP_INGRESS, gtpc_create_session_request_hdl },
	[GTP_CREATE_SESSION_RESPONSE_TYPE]	= { GTP_TRIG, GTP_EGRESS, gtpc_create_session_response_hdl },
	[GTP_DELETE_SESSION_REQUEST_TYPE]	= { GTP_INIT, GTP_INGRESS, gtpc_delete_session_request_hdl },
	[GTP_DELETE_SESSION_RESPONSE_TYPE]	= { GTP_TRIG, GTP_EGRESS, gtpc_delete_session_response_hdl },
	[GTP_MODIFY_BEARER_REQUEST_TYPE]	= { GTP_INIT, GTP_INGRESS, gtpc_modify_bearer_request_hdl },
	[GTP_MODIFY_BEARER_RESPONSE_TYPE]	= { GTP_TRIG, GTP_EGRESS, gtpc_modify_bearer_response_hdl },
	[GTP_DELETE_BEARER_REQUEST]		= { GTP_INIT, GTP_EGRESS, gtpc_delete_bearer_request_hdl },
	[GTP_DELETE_BEARER_RESPONSE]		= { GTP_TRIG, GTP_INGRESS, gtpc_delete_bearer_response_hdl },
	/* Generic command xlat */
	[GTP_MODIFY_BEARER_COMMAND]		= { GTP_INIT, GTP_INGRESS, gtpc_generic_xlat_command_hdl },
	[GTP_DELETE_BEARER_COMMAND]		= { GTP_INIT, GTP_INGRESS, gtpc_generic_xlat_command_hdl },
	[GTP_BEARER_RESSOURCE_COMMAND]		= { GTP_INIT, GTP_INGRESS, gtpc_generic_xlat_command_hdl },
	/* Generic request xlat */
	[GTP_CHANGE_NOTIFICATION_REQUEST]	= { GTP_INIT, GTP_INGRESS, gtpc_generic_xlat_request_hdl },
	[GTP_RESUME_NOTIFICATION]		= { GTP_INIT, GTP_INGRESS, gtpc_generic_xlat_request_hdl },
	[GTP_CREATE_BEARER_REQUEST]		= { GTP_INIT, GTP_EGRESS, gtpc_generic_xlat_request_hdl },
	[GTP_UPDATE_BEARER_REQUEST]		= { GTP_INIT, GTP_EGRESS, gtpc_generic_xlat_request_hdl },
	[GTP_UPDATE_PDN_CONNECTION_SET_REQUEST]	= { GTP_INIT, GTP_INGRESS, gtpc_generic_xlat_request_hdl },
	/* Generic response xlat */
	[GTP_CHANGE_NOTIFICATION_RESPONSE]	= { GTP_TRIG, GTP_EGRESS, gtpc_generic_xlat_response_hdl },
	[GTP_RESUME_ACK]			= { GTP_TRIG, GTP_EGRESS, gtpc_generic_xlat_response_hdl },
	[GTP_MODIFY_BEARER_FAILURE_IND]		= { GTP_TRIG, GTP_EGRESS, gtpc_generic_xlat_response_hdl },
	[GTP_DELETE_BEARER_FAILURE_IND]		= { GTP_TRIG, GTP_EGRESS, gtpc_generic_xlat_response_hdl },
	[GTP_BEARER_RESSOURCE_FAILURE_IND]	= { GTP_TRIG, GTP_EGRESS, gtpc_generic_xlat_response_hdl },
	[GTP_CREATE_BEARER_RESPONSE]		= { GTP_TRIG, GTP_INGRESS, gtpc_generic_xlat_response_hdl },
	[GTP_UPDATE_BEARER_RESPONSE]		= { GTP_TRIG, GTP_INGRESS, gtpc_generic_xlat_response_hdl },
	[GTP_UPDATE_PDN_CONNECTION_SET_RESPONSE] = { GTP_TRIG, GTP_EGRESS, gtpc_generic_xlat_response_hdl },
};

gtp_teid_t *
gtpc_proxy_handle_v2(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;
	gtp_teid_t *teid;

	/* Ignore echo-response messages */
	if (gtph->type == GTP_ECHO_RESPONSE_TYPE)
		return NULL;

	/* Special care to create and delete session */
	if (*(gtpc_msg_hdl[gtph->type].hdl)) {
		teid = (*(gtpc_msg_hdl[gtph->type].hdl)) (w, addr, gtpc_msg_hdl[gtph->type].direction);
		if (teid)
			teid->family = gtpc_msg_hdl[gtph->type].family;
		return teid;
	}

	/* We are into transparent mode so the only important
	 * matter here is to xlat F-TEID for both GTP-C and
	 * GTP-U in order to force tunnel endpoint to be
	 * our GTP Proxy... just like the lyrics: nothing else matters
	 */
	teid = gtpc_generic_xlat_hdl(w, addr, GTP_INGRESS);
	if (teid)
		teid->family = GTP_INIT;
	return teid;
}
