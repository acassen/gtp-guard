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

#include "gtp_data.h"
#include "gtp_teid.h"
#include "gtp_proxy.h"
#include "gtp_proxy_hdl.h"
#include "gtp_utils.h"
#include "gtp_utils_uli.h"
#include "gtp_sched.h"
#include "gtp_sqn.h"
#include "bitops.h"
#include "logger.h"
#include "inet_utils.h"


/* Extern data */
extern struct data *daemon_data;

/* Local data */
extern struct gtp_teid dummy_teid;


static int
gtp1_gsn_address_get(struct pkt_buffer *pbuff, uint32_t **gsn_c, uint32_t **gsn_u)
{
	struct gtp1_ie *ie;
	uint8_t *cp;

	/* GSN Address for Control-Plane & Data-Plane */
	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, pbuff);
	if (!cp)
		return -1;

	*gsn_c = (uint32_t *) (cp + sizeof(struct gtp1_ie));
	ie = (struct gtp1_ie *) cp;
	cp = gtp1_get_ie_offset(GTP1_IE_GSN_ADDRESS_TYPE, cp+sizeof(struct gtp1_ie)+ntohs(ie->length)
							, pkt_buffer_end(pbuff));
	if (!cp)
		return -1;

	*gsn_u = (uint32_t *) (cp + sizeof(struct gtp1_ie));
	return 0;
}

static int
gtp1_gsn_address_masq(struct gtp_server *srv, int direction)
{
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_server *srv_gtpc_ingress = &ctx->gtpc;
	struct gtp_server *srv_gtpc_egress = &ctx->gtpc_egress;
	struct gtp_server *s = srv_gtpc_ingress;
	uint32_t *gsn_address_c;
	uint8_t *cp;

	if (__test_bit(GTP_FL_CTL_BIT, &srv_gtpc_egress->flags) &&
	    direction == GTP_INGRESS)
		s = srv_gtpc_egress;

	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, srv->s.pbuff);
	if (!cp)
		return -1;

	gsn_address_c = (uint32_t *) (cp + sizeof(struct gtp1_ie));
	*gsn_address_c = ((struct sockaddr_in *) &s->s.addr)->sin_addr.s_addr;
	return 0;
}

static struct gtp_teid *
gtp1_create_teid(uint8_t type, int direction, struct gtp_server *srv, struct hlist_head *h,
		 struct hlist_head *vh, struct gtp_f_teid *f_teid, struct gtp_session *s)
{
	struct gtp_teid *teid;
	struct gtp_server *ssrv = srv;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_server *srv_gtpc_ingress = &ctx->gtpc;
	struct gtp_server *srv_gtpc_egress = &ctx->gtpc_egress;
	struct gtp_server *srv_gtpu = &ctx->gtpu;

	/* Determine if this is related to an existing VTEID.
	 * If so need to restore original TEID related, otherwise
	 * create a new VTEID */
	if ((*f_teid->ipv4 == ((struct sockaddr_in *) &srv_gtpc_ingress->s.addr)->sin_addr.s_addr) ||
	    (*f_teid->ipv4 == ((struct sockaddr_in *) &srv_gtpc_egress->s.addr)->sin_addr.s_addr)) {
		teid = gtp_vteid_get(ctx->vteid_tab, ntohl(*f_teid->teid_grekey));
		if (!teid)
			return NULL;

		gtp_teid_restore(teid, f_teid);
		return teid;
	}

	teid = gtp_teid_get(h, f_teid);
	if (teid)
		goto masq;

	/* Allocate and bind this new teid */
	teid = gtp_teid_alloc(h, f_teid, NULL);
	teid->type = type;
	__set_bit(direction ? GTP_TEID_FL_EGRESS : GTP_TEID_FL_INGRESS, &teid->flags);
	teid->session = s;
	__set_bit(GTP_TEID_FL_FWD, &teid->flags);
	gtp_vteid_alloc(vh, teid, &srv->s.seed);

	/* Add to list */
	if (type == GTP_TEID_C)
		gtp_session_gtpc_teid_add(s, teid);
	else if (type == GTP_TEID_U)
		gtp_session_gtpu_teid_add(s, teid);

  masq:
	/* exclusive sqn tracking for ingress messages */
	if (direction == GTP_INGRESS)
		gtp_sqn_update(srv, teid);

	/* TEID masquarade */
	ssrv = srv_gtpu;
	if (type == GTP_TEID_C) {
		ssrv = srv_gtpc_ingress;
		if (__test_bit(GTP_FL_CTL_BIT, &srv_gtpc_egress->flags) &&
		    __test_bit(GTP_TEID_FL_INGRESS, &teid->flags))
			ssrv = srv_gtpc_egress;
	}
	gtp_teid_masq(f_teid, &ssrv->s.addr, teid->vid);

	return teid;
}

static int
gtp1_session_xlat_recovery(struct gtp_server *srv)
{
	struct gtp1_ie_recovery *rec;
	uint8_t *cp;

	cp = gtp1_get_ie(GTP1_IE_RECOVERY_TYPE, srv->s.pbuff);
	if (cp) {
		rec = (struct gtp1_ie_recovery *) cp;
		rec->recovery = daemon_data->restart_counter;
	}
	return 0;
}

static struct gtp_teid *
gtp1_session_xlat(struct gtp_server *srv, struct gtp_session *s, int direction)
{
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid = NULL;
	struct gtp_f_teid f_teid_c, f_teid_u;
	struct gtp1_ie_teid *teid_c = NULL, *teid_u = NULL;
	uint32_t *gsn_address_c = NULL, *gsn_address_u = NULL;
	uint8_t *cp;

	gtp1_session_xlat_recovery(srv);

	/* Control & Data Plane IE */
	cp = gtp1_get_ie(GTP1_IE_TEID_CONTROL_TYPE, srv->s.pbuff);
	if (cp) {
		teid_c = (struct gtp1_ie_teid *) cp;
		f_teid_c.version = 1;
		f_teid_c.teid_grekey = (uint32_t *) (cp + offsetof(struct gtp1_ie_teid, id));
	}

	cp = gtp1_get_ie(GTP1_IE_TEID_DATA_TYPE, srv->s.pbuff);
	if (cp) {
		teid_u = (struct gtp1_ie_teid *) cp;
		f_teid_u.version = 1;
		f_teid_u.teid_grekey = (uint32_t *) (cp + offsetof(struct gtp1_ie_teid, id));
	}

	/* GSN Address for Control-Plane & Data-Plane */
	gtp1_gsn_address_get(srv->s.pbuff, &gsn_address_c, &gsn_address_u);

	/* Control-Plane */
	if (teid_c && gsn_address_c) {
		f_teid_c.ipv4 = gsn_address_c;
		teid = gtp1_create_teid(GTP_TEID_C, direction, srv
						  , ctx->gtpc_teid_tab
						  , ctx->vteid_tab
						  , &f_teid_c, s);
	}

	/* User-Plane */
	if (teid_u && gsn_address_u) {
		f_teid_u.ipv4 = gsn_address_u;
		gtp1_create_teid(GTP_TEID_U, direction, srv
					   , ctx->gtpu_teid_tab
					   , ctx->vteid_tab
					   , &f_teid_u, s);
	}

	return teid;
}


static struct gtp_teid *
gtp1_echo_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp1_ie_recovery *rec;

	/* 3GPP.TS.129.060 7.2.2 : IE Recovery is mandatory in response message */
	h->type = GTP_ECHO_RESPONSE_TYPE;
	h->length = htons(ntohs(h->length) + sizeof(*rec));
	pkt_buffer_set_end_pointer(srv->s.pbuff, gtp1_get_header_len(h));
	pkt_buffer_set_data_pointer(srv->s.pbuff, gtp1_get_header_len(h));

	gtp1_ie_add_tail(srv->s.pbuff, sizeof(*rec));
	rec = (struct gtp1_ie_recovery *) srv->s.pbuff->data;
	rec->type = GTP1_IE_RECOVERY_TYPE;
	rec->recovery = daemon_data->restart_counter;
	pkt_buffer_put_data(srv->s.pbuff, sizeof(*rec));

	return &dummy_teid;
}

static struct gtp_teid *
gtp1_create_pdp_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_ie_apn *ie_apn;
	struct gtp1_ie_imsi *ie_imsi;
	struct gtp1_ie_rai *ie_rai;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid = NULL;
	struct gtp_conn *c;
	struct gtp_session *s = NULL;
	struct gtp_apn *apn;
	bool retransmit = false;
	uint64_t imsi;
	uint8_t *cp;
	char apn_str[64];
	int err;

	/* Retransmission detection */
	s = gtpc_retransmit_detected(srv);
	if (s)
		retransmit = true;

	/* At least TEID CONTROL for creation */
	cp = gtp1_get_ie(GTP1_IE_TEID_CONTROL_TYPE, srv->s.pbuff);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no TEID-Control IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	/* At least GSN Address for Control-Plane */
	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, srv->s.pbuff);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no C-Plane GSN-Address present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	/* APN selection */
	cp = gtp1_get_ie(GTP1_IE_APN_TYPE, srv->s.pbuff);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no APN IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}
	ie_apn = (struct gtp1_ie_apn *) cp;
	memset(apn_str, 0, 64);
	err = gtp1_ie_apn_extract(ie_apn, apn_str, 63);
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

	/* IMSI */
	cp = gtp1_get_ie(GTP1_IE_IMSI_TYPE, srv->s.pbuff);
	if (!cp) {
		log_message(LOG_INFO, "%s(): no IMSI IE present. ignoring..."
				    , __FUNCTION__);
		return NULL;
	}

	ie_imsi = (struct gtp1_ie_imsi *) cp;
	imsi = bcd_to_int64(ie_imsi->imsi, sizeof(ie_imsi->imsi));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		c = gtp_conn_alloc(imsi);
	}

	/* Rewrite IMSI if needed */
	gtp_imsi_rewrite(apn, ie_imsi->imsi);

	/* Create a new session object */
	if (!retransmit) {
		s = gtp_session_alloc(c, apn, gtp_proxy_gtpc_teid_destroy
					    , gtp_proxy_gtpu_teid_destroy);
		s->srv = srv;
	}

	/* Performing session translation */
	teid = gtp1_session_xlat(srv, s, GTP_INGRESS);
	if (!teid) {
		log_message(LOG_INFO, "%s(): Error while xlat. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	/* RAI */
	cp = gtp1_get_ie(GTP1_IE_RAI_TYPE, srv->s.pbuff);
	if (cp) {
		ie_rai = (struct gtp1_ie_rai *) cp;
		memcpy(s->serving_plmn.plmn, ie_rai->plmn, GTP_PLMN_MAX_LEN);
	}

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
		gtp1_ie_uli_update(srv->s.pbuff, &apn->egci_plmn, (struct sockaddr_in *) addr);

	log_message(LOG_INFO, "Create-PDP-Req:={IMSI:%ld APN:%s TEID-C:0x%.8x Roaming-Status:%s}%s"
			    , imsi, apn_str, ntohl(teid->id)
			    , gtp_session_roaming_status_str(s)
			    , (retransmit) ? " (retransmit)" : "");
	if (retransmit) {
		gtp_sqn_masq(srv, teid);
		goto end;
	}

	/* Create a vSQN */
	gtp_vsqn_alloc(srv, teid, false);
	gtp_sqn_masq(srv, teid);

	/* Set addr tunnel endpoint */
	teid->sgw_addr = *((struct sockaddr_in *) addr);

	/* Update last sGW visited */
	c->sgw_addr = *((struct sockaddr_in *) addr);

	/* pGW selection */
	if (__test_bit(GTP_FL_FORCE_PGW_BIT, &ctx->flags)) {
		teid->pgw_addr = *(struct sockaddr_in *) &ctx->pgw_addr;
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

static struct gtp_teid *
gtp1_create_pdp_response_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp1_ie_cause *ie_cause = NULL;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid = NULL, *t, *teid_u, *t_u;
	uint8_t *cp;

	t = gtp_vteid_get(ctx->vteid_tab, ntohl(h->teid));
	if (!t) {
		if (!h->seq) {
			log_message(LOG_INFO, "%s(): No seqnum provided for TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohl(h->teid));
			return NULL;
		}

		/* No TEID present try by SQN */
		t = gtp_vsqn_get(ctx->vsqn_tab, ntohs(h->sqn));
		if (!t) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.4x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohs(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* Recovery xlat */
		gtp1_session_xlat_recovery(srv);

		/* SQN masq */
		gtp_sqn_restore(srv, t);

		/* Force delete session */
		t->session->action = GTP_ACTION_DELETE_SESSION;

		return t;
	}

	/* Restore TEID at sGW */
	h->teid = t->id;

	/* Performing session translation */
	teid = gtp1_session_xlat(srv, t->session, GTP_EGRESS);
	if (!teid) {
		teid = t;

		/* SQN masq */
		gtp_sqn_restore(srv, t);

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
	gtp_sqn_restore(srv, teid->peer_teid);

	/* Set addr tunnel endpoint */
	inet_ip4tosockaddr(teid->ipv4, (struct sockaddr_storage *) &teid->pgw_addr);
	teid->pgw_addr.sin_port = htons(GTP_C_PORT);
	teid->sgw_addr = t->sgw_addr;

	/* Test cause code, destroy if <> success.
	 * 3GPP.TS.129.060 7.7.1 */
	cp = gtp1_get_ie(GTP1_IE_CAUSE_TYPE, srv->s.pbuff);
	if (cp) {
		ie_cause = (struct gtp1_ie_cause *) cp;
		if (!(ie_cause->value >= GTP1_CAUSE_REQUEST_ACCEPTED &&
		      ie_cause->value <= 191)) {
			teid->session->action = GTP_ACTION_DELETE_SESSION;
		}
	}

  end:
	gtp_teid_put(t);
	return teid;
}

static int
gtp1_update_bearer(struct pkt_buffer *pbuff, struct gtp_session *s, struct gtp_teid *t)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) pbuff->head;
	struct gtp_teid *t_u = NULL, *t_u_old;
	uint32_t *gsn_c = NULL, *gsn_u = NULL;
	int err;

	if (!t)
		return -1;

	err = gtp1_gsn_address_get(pbuff, &gsn_c, &gsn_u);
	if (err) {
		log_message(LOG_INFO, "%s(): missing GSN Address...ignoring..."
				    , __FUNCTION__);
		return -1;
	}

	t_u_old = t->bearer_teid;
	if (!t_u_old || t_u_old->ipv4 == *gsn_u)
		return -1;

	t_u = gtp_session_gtpu_teid_get_by_sqn(s, h->sqn);
	if (t_u) {
		t->bearer_teid = t_u;
		t_u->old_teid = t_u_old;
	}

	return 0;
}

static struct gtp_teid *
gtp1_update_pdp_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp1_ie_imsi *ie_imsi;
	struct gtp1_ie_rai *ie_rai;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid = NULL, *t, *t_u = NULL, *pteid;
	struct gtp_session *s;
	bool mobility = false;
	uint8_t *cp;
	int err;

	teid = gtp_vteid_get(ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;

	}

	/* Mobility from 4G to 3G, incoming TEID is related to a
	 * previously allocated VTEID. We need to fetch it and
	 * forward this update request accordingly to remote pGW
	 * supporting x-Gn interface. We are making assumption here
	 * that all pGW are supporting x-Gn interface */
	if (teid->version == 2) {
		mobility = true;
		teid->version = 1;
	}

	/* Update GTP-C with current SGSN */
	teid->sgw_addr = *((struct sockaddr_in *) addr);

	/* IMSI rewrite if needed */
	cp = gtp1_get_ie(GTP1_IE_IMSI_TYPE, srv->s.pbuff);
	if (cp) {
		ie_imsi = (struct gtp1_ie_imsi *) cp;
		gtp_imsi_rewrite(teid->session->apn, ie_imsi->imsi);
	}

	/* Set GGSN TEID */
	h->teid = teid->id;
	s = teid->session;

	/* Update GTP-C with current sGW */
	gtp_teid_update_sgw(teid, addr);
	gtp_teid_update_sgw(teid->peer_teid, addr);

	/* Update serving PLMN */
	cp = gtp1_get_ie(GTP1_IE_RAI_TYPE, srv->s.pbuff);
	if (cp) {
		ie_rai = (struct gtp1_ie_rai *) cp;
		memcpy(s->serving_plmn.plmn, ie_rai->plmn, GTP_PLMN_MAX_LEN);
	}

	/* Set session roaming status */
	err = gtp_session_roaming_status_set(s);
	if (err) {
		log_message(LOG_INFO, "%s(): unable to update Roaming Status for IMSI:%ld"
				    , __FUNCTION__
				    , s->conn->imsi);
	}

	/* ULI tag */
	if (__test_bit(GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4, &s->apn->flags) &&
	    __test_bit(GTP_SESSION_FL_ROAMING_OUT, &s->flags))
		gtp1_ie_uli_update(srv->s.pbuff, &s->apn->egci_plmn, (struct sockaddr_in *) addr);

	log_message(LOG_INFO, "Update-PDP-Req:={F-TEID:0x%.8x Roaming-Status:%s}%s"
			    , ntohl(h->teid)
			    , gtp_session_roaming_status_str(s)
			    , mobility ? " (4G Mobility)" : "");

	/* Update SQN */
	gtp_sqn_update(srv, teid);
	gtp_vsqn_alloc(srv, teid, false);
	gtp_sqn_masq(srv, teid);

	/* Update last sGW visited */
	s->conn->sgw_addr = *((struct sockaddr_in *) addr);

	/* Performing session translation */
	t = gtp1_session_xlat(srv, s, GTP_INGRESS);
	if (!t) {
		/* GTP-U may has changed */
		gtp1_update_bearer(srv->s.pbuff, s, teid->peer_teid);

		/* No GTP-C IE, if related GSN Address is present then xlat it */
		gtp1_gsn_address_masq(srv, GTP_INGRESS);

		/* There is no GTP-C update, so just forward */
		return teid;
	}

	if (t->peer_teid) {
		/* GTP-U may has changed */
		gtp1_update_bearer(srv->s.pbuff, s, t->peer_teid);

		goto end;
	}

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

static struct gtp_teid *
gtp1_update_pdp_response_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp1_ie_cause *ie_cause = NULL;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid = NULL, *t, *teid_u, *oteid;
	uint8_t *cp;

	/* Virtual TEID mapping */
	teid = gtp_vteid_get(ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		if (!h->seq) {
			log_message(LOG_INFO, "%s(): No seqnum provided for TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohl(h->teid));
			return NULL;
		}

		/* No TEID present try by SQN */
		teid = gtp_vsqn_get(ctx->vsqn_tab, ntohs(h->sqn));
		if (!teid) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.4x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohs(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* Recovery xlat */
		gtp1_session_xlat_recovery(srv);

		/* SQN masq */
		gtp_sqn_restore(srv, teid->peer_teid);

		return teid;
	}

	/* TEID set */
	h->teid = teid->id;

	/* Performing session translation */
	t = gtp1_session_xlat(srv, teid->session, GTP_EGRESS);
	if (!t) {
		/* No GTP-C IE, if related GSN Address is present then xlat it */
		gtp1_gsn_address_masq(srv, GTP_EGRESS);
	}

	/* If binding already exist then bearer update already done */
	if (teid->peer_teid)
		goto end;

	/* Test cause code, destroy if <> success.
	 * 3GPP.TS.29.274 8.4 */
	cp = gtp1_get_ie(GTP1_IE_CAUSE_TYPE, srv->s.pbuff);
	if (!cp)
		return teid;

	oteid = teid->old_teid;
	ie_cause = (struct gtp1_ie_cause *) cp;
	if (!(ie_cause->value >= GTP1_CAUSE_REQUEST_ACCEPTED &&
	      ie_cause->value <= GTP1_CAUSE_NON_EXISTENT)) {
		if (oteid)
			gtp_sqn_restore(srv, oteid->peer_teid);
		return teid;
	}

	if (oteid) {
		gtp_teid_bind(oteid->peer_teid, teid);
		gtp_session_gtpc_teid_destroy(oteid);
	}

  end:
	/* Bearer cause handling */
	teid_u = teid->bearer_teid;
	if (teid_u && teid_u->old_teid) {
		oteid = teid_u->old_teid;
		if (oteid->peer_teid)
			gtp_teid_bind(oteid->peer_teid, teid_u);
		gtp_session_gtpu_teid_destroy(oteid);
	}

	/* SQN masq */
	gtp_sqn_restore(srv, teid->peer_teid);

	return teid;
}

static struct gtp_teid *
gtp1_delete_pdp_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid;

	teid = gtp_vteid_get(ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x from gtp header. ignoring..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		return NULL;
	}

	log_message(LOG_INFO, "Delete-PDP-Req:={TEID-C:0x%.8x}%s"
			    , ntohl(h->teid)
			    , (teid->version == 2) ? " (4G Mobility)" : "");

	/* Set GGSN TEID */
	h->teid = teid->id;

	/* Recovery xlat */
	gtp1_session_xlat_recovery(srv);

	/* Update addr tunnel endpoint */
	gtp_teid_update_sgw(teid, addr);
	gtp_teid_update_sgw(teid->peer_teid, addr);

	/* Update SQN */
	gtp_sqn_update(srv, teid);
	gtp_vsqn_alloc(srv, teid, false);
	gtp_sqn_masq(srv, teid);

	/* Finally set expiration timeout if used */
	if (__test_bit(GTP_FL_SESSION_EXPIRATION_DELETE_TO_BIT, &ctx->flags))
		gtp_session_mod_timer(teid->session, ctx->session_delete_to);

	return teid;
}

static struct gtp_teid *
gtp1_delete_pdp_response_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp1_ie_cause *ie_cause = NULL;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid;
	uint8_t *cp;

	teid = gtp_vteid_get(ctx->vteid_tab, ntohl(h->teid));
	if (!teid) {
		if (!h->seq) {
			log_message(LOG_INFO, "%s(): No seqnum provided for TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohl(h->teid));
			return NULL;
		}

		/* No TEID present try by SQN */
		teid = gtp_vsqn_get(ctx->vsqn_tab, ntohs(h->sqn));
		if (!teid) {
			log_message(LOG_INFO, "%s(): unknown SQN:0x%.4x or TEID:0x%.8x from gtp header. ignoring..."
					    , __FUNCTION__
					    , ntohs(h->sqn)
					    , ntohl(h->teid));
			return NULL;
		}

		/* Recovery xlat */
		gtp1_session_xlat_recovery(srv);

		/* SQN masq */
		gtp_sqn_restore(srv, teid);

		/* Force delete session */
		teid->session->action = GTP_ACTION_DELETE_SESSION;

		return teid;
	}

	/* Restore TEID at SGSN */
	h->teid = teid->id;

	/* Recovery xlat */
	gtp1_session_xlat_recovery(srv);

	/* SQN masq */
	gtp_sqn_restore(srv, teid->peer_teid);

	/* Test cause code, destroy if == success.
	 * 3GPP.TS.129.060 7.7.1 */
	cp = gtp1_get_ie(GTP1_IE_CAUSE_TYPE, srv->s.pbuff);
	if (cp) {
		ie_cause = (struct gtp1_ie_cause *) cp;
		if (ie_cause->value >= GTP1_CAUSE_REQUEST_ACCEPTED &&
		    ie_cause->value <= GTP1_CAUSE_NON_EXISTENT) {
			teid->session->action = GTP_ACTION_DELETE_SESSION;
		}
	}

	return teid;
}


/*
 *	GTP-C Message handle
 */
static const struct {
	uint8_t family; /* GTP_INIT : Initial | GTP_TRIG : Triggered*/
	struct gtp_teid * (*hdl) (struct gtp_server *, struct sockaddr_storage *);
} gtpc_msg_hdl[0xff + 1] = {
	[GTP_ECHO_REQUEST_TYPE]			= { GTP_INIT, gtp1_echo_request_hdl },
	[GTP_CREATE_PDP_CONTEXT_REQUEST]	= { GTP_INIT, gtp1_create_pdp_request_hdl },
	[GTP_CREATE_PDP_CONTEXT_RESPONSE]	= { GTP_TRIG, gtp1_create_pdp_response_hdl },
	[GTP_UPDATE_PDP_CONTEXT_REQUEST]	= { GTP_INIT, gtp1_update_pdp_request_hdl },
	[GTP_UPDATE_PDP_CONTEXT_RESPONSE]	= { GTP_TRIG, gtp1_update_pdp_response_hdl },
	[GTP_DELETE_PDP_CONTEXT_REQUEST]	= { GTP_INIT, gtp1_delete_pdp_request_hdl },
	[GTP_DELETE_PDP_CONTEXT_RESPONSE]	= { GTP_TRIG, gtp1_delete_pdp_response_hdl },
};

struct gtp_teid *
gtpc_proxy_handle_v1(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) srv->s.pbuff->head;
	struct gtp_teid *teid;

	/* Ignore echo-response messages */
	if (gtph->type == GTP_ECHO_RESPONSE_TYPE)
		return NULL;

	if (*(gtpc_msg_hdl[gtph->type].hdl)) {
		teid = (*(gtpc_msg_hdl[gtph->type].hdl)) (srv, addr);
		if (teid)
			teid->family = gtpc_msg_hdl[gtph->type].family;
		return teid;
	}

	log_message(LOG_INFO, "%s(): GTPv1 msg_type:0x%.2x not supported. Ignoring..."
			    , __FUNCTION__
			    , gtph->type);
	return NULL;
}
