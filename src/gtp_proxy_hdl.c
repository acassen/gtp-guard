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

#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_proxy.h"
#include "gtp_proxy_hdl_v1.h"
#include "gtp_proxy_hdl_v2.h"
#include "gtp_utils.h"
#include "logger.h"
#include "inet_utils.h"


/* Local data */
gtp_teid_t dummy_teid = { .type = 0xff };


/*
 *	GTP-C Message handle
 */
gtp_session_t *
gtpc_retransmit_detected(gtp_server_t *srv)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) srv->s.pbuff->head;
	gtp1_hdr_t *gtph1 = (gtp1_hdr_t *) srv->s.pbuff->head;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_f_teid_t f_teid;
	gtp_session_t *s = NULL;
	gtp_teid_t *teid;
	uint8_t *cp;

	if (gtph->version == 2) {
		cp = gtp_get_ie(GTP_IE_F_TEID_TYPE, srv->s.pbuff);
		if (!cp)
			return NULL;
		f_teid.teid_grekey = (uint32_t *) (cp + offsetof(gtp_ie_f_teid_t, teid_grekey));
		f_teid.ipv4 = (uint32_t *) (cp + offsetof(gtp_ie_f_teid_t, ipv4));
		teid = gtp_teid_get(&ctx->gtpc_teid_tab, &f_teid);
		if (!teid)
			return NULL;

		/* same SQN too ?*/
		if (gtph->teid_presence)
			s = (gtph->sqn == teid->sqn) ? teid->session : NULL;
		else if (gtph->sqn_only == teid->sqn)
			s = teid->session;

		gtp_teid_put(teid);
		return s;
	}

	cp = gtp1_get_ie(GTP1_IE_TEID_CONTROL_TYPE, srv->s.pbuff);
	if (!cp)
		return NULL;
	f_teid.teid_grekey = (uint32_t *) (cp + offsetof(gtp1_ie_teid_t, id));
	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, srv->s.pbuff);
	if (!cp)
		return NULL;
	f_teid.ipv4 = (uint32_t *) (cp + sizeof(gtp1_ie_t));
	teid = gtp_teid_get(&ctx->gtpc_teid_tab, &f_teid);
	if (!teid)
		return NULL;

	/* same SQN too ?*/
	if (gtph1->seq)
		s = (gtph1->sqn == teid->sqn) ? teid->session : NULL;

	gtp_teid_put(teid);
	return s;
}

/*
 *	GTP-C Message handle
 */
static const struct {
	gtp_teid_t * (*hdl) (gtp_server_t *, struct sockaddr_storage *);
} gtpc_msg_hdl[7] = {
	[1]	= { gtpc_proxy_handle_v1 },
	[2]	= { gtpc_proxy_handle_v2 },
};

gtp_teid_t *
gtpc_proxy_handle(gtp_server_t *srv, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) srv->s.pbuff->head;

	/* Only support GTPv1 & GTPv2 */
	if (*(gtpc_msg_hdl[gtph->version].hdl))
		return (*(gtpc_msg_hdl[gtph->version].hdl)) (srv, addr);

	log_message(LOG_INFO, "%s(): GTP Version %d not supported."
			      " Ignoring ingress datagram from [%s]:%d"
			    , __FUNCTION__
			    , gtph->version
			    , inet_sockaddrtos(addr)
			    , ntohs(inet_sockaddrport(addr)));

	return NULL;
}

int
gtpc_proxy_handle_post(gtp_server_t *srv, gtp_teid_t *teid)
{
	gtp_session_t *s;

	if (!teid || teid->type == 0xff)
		return -1;

	s = teid->session;
	switch (s->action) {
	case GTP_ACTION_DELETE_SESSION:
		gtp_session_destroy(s);
		return 0;
	case GTP_ACTION_DELETE_BEARER:
		gtp_session_destroy_bearer(s);
		return 0;
	}

	gtp_teid_put(teid);
	return 0;
}


/*
 *	GTP-U Message handle
 */
static gtp_teid_t *
gtpu_echo_request_hdl(gtp_server_t *srv, struct sockaddr_storage *addr)
{
	gtp1_hdr_t *h = (gtp1_hdr_t *) srv->s.pbuff->head;
	gtp1_ie_recovery_t *rec;

	/* 3GPP.TS.129.060 7.2.2 : IE Recovery is mandatory in response message */
	h->type = GTPU_ECHO_RSP_TYPE;
	h->length = htons(ntohs(h->length) + sizeof(gtp1_ie_recovery_t));
	pkt_buffer_set_end_pointer(srv->s.pbuff, gtp1_get_header_len(h));
	pkt_buffer_set_data_pointer(srv->s.pbuff, gtp1_get_header_len(h));

	gtp1_ie_add_tail(srv->s.pbuff, sizeof(gtp1_ie_recovery_t));
	rec = (gtp1_ie_recovery_t *) srv->s.pbuff->data;
	rec->type = GTP1_IE_RECOVERY_TYPE;
	rec->recovery = 0;
	pkt_buffer_put_data(srv->s.pbuff, sizeof(gtp1_ie_recovery_t));

	return &dummy_teid;
}

static gtp_teid_t *
gtpu_error_indication_hdl(gtp_server_t *srv, struct sockaddr_storage *addr)
{
	gtp_proxy_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL, *pteid = NULL;
	gtp_f_teid_t f_teid;
	uint8_t *cp;

	/* Data Plane IE */
	cp = gtp1_get_ie(GTP1_IE_TEID_DATA_TYPE, srv->s.pbuff);
	if (!cp)
		return NULL;
	f_teid.teid_grekey = (uint32_t *) (cp + offsetof(gtp1_ie_teid_t, id));

	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, srv->s.pbuff);
	if (!cp)
		return NULL;
	f_teid.ipv4 = (uint32_t *) (cp + sizeof(gtp1_ie_t));

	teid = gtp_teid_get(&ctx->gtpu_teid_tab, &f_teid);
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x. Ignoring"
				    , __FUNCTION__
				    , ntohl(*f_teid.teid_grekey));
		return NULL;
	}

	pteid = teid->peer_teid;
	if (!pteid) {
		log_message(LOG_INFO, "%s(): orphaned TEID:={vteid:0x%.8x, teid:0x%.8x, ipaddr:%u.%u.%u.%u}."
				      " Ignoring"
				    , __FUNCTION__
				    , teid->vid, ntohl(teid->id)
				    , NIPQUAD(teid->ipv4));
		return NULL;
	}

	/* xlat TEID */
	*f_teid.teid_grekey = htonl(teid->vid);
	*f_teid.ipv4 = ((struct sockaddr_in *) &srv->s.addr)->sin_addr.s_addr;

	/* Finaly set addr back to linked peer */
	((struct sockaddr_in *) addr)->sin_addr.s_addr = pteid->ipv4;

	return teid;
}

static gtp_teid_t *
gtpu_end_marker_hdl(gtp_server_t *srv, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) srv->s.pbuff->head;
	gtp_proxy_t *ctx = srv->ctx;
	gtp_teid_t *teid = NULL, *pteid = NULL;
	gtp_f_teid_t f_teid;
	uint32_t field = gtph->teid;

	/* TEID playground */
	f_teid.teid_grekey = &field;
	f_teid.ipv4 = &((struct sockaddr_in *) addr)->sin_addr.s_addr;

	teid = gtp_teid_get(&ctx->gtpu_teid_tab, &f_teid);
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x. Ignoring"
				    , __FUNCTION__
				    , ntohl(gtph->teid));
		return NULL;
	}

	pteid = teid->peer_teid;
	if (!pteid) {
		log_message(LOG_INFO, "%s(): orphaned TEID:={vteid:0x%.8x, teid:0x%.8x, ipaddr:%u.%u.%u.%u}."
				      " Ignoring"
				    , __FUNCTION__
				    , teid->vid, ntohl(teid->id)
				    , NIPQUAD(teid->ipv4));
		return NULL;
	}

	/* TEID xlat */
	gtph->teid = htonl(teid->vid);

	/* Peer address xlat */
	((struct sockaddr_in *) addr)->sin_addr.s_addr = pteid->ipv4;

	return teid;
}

static const struct {
	gtp_teid_t * (*hdl) (gtp_server_t *, struct sockaddr_storage *);
} gtpu_msg_hdl[0xff + 1] = {
	[GTPU_ECHO_REQ_TYPE]			= { gtpu_echo_request_hdl },
	[GTPU_ERR_IND_TYPE]			= { gtpu_error_indication_hdl },
	[GTPU_END_MARKER_TYPE]			= { gtpu_end_marker_hdl	},
};

gtp_teid_t *
gtpu_proxy_handle(gtp_server_t *srv, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) srv->s.pbuff->head;
	ssize_t len;

	len = gtpu_get_header_len(srv->s.pbuff);
	if (len < 0)
		return NULL;

	/* Special care to create and delete session */
	if (*(gtpu_msg_hdl[gtph->type].hdl))
		return (*(gtpu_msg_hdl[gtph->type].hdl)) (srv, addr);

	/* Not supported */
	log_message(LOG_INFO, "%s(): GTP-U/path-mgt msg_type:0x%.2x from %s not supported..."
			    , __FUNCTION__
			    , gtph->type
			    , inet_sockaddrtos(addr));
	return NULL;
}
