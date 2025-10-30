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
struct gtp_teid dummy_teid = { .type = 0xff };


/*
 *	GTP-C Message handle
 */
struct gtp_session *
gtpc_retransmit_detected(struct gtp_server *srv)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) srv->s.pbuff->head;
	struct gtp1_hdr *gtph1 = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_f_teid f_teid;
	struct gtp_session *s = NULL;
	struct gtp_teid *teid;
	uint8_t *cp;

	if (gtph->version == 2) {
		cp = gtp_get_ie(GTP_IE_F_TEID_TYPE, srv->s.pbuff);
		if (!cp)
			return NULL;
		f_teid.teid_grekey = (uint32_t *) (cp + offsetof(struct gtp_ie_f_teid, teid_grekey));
		f_teid.ipv4 = (uint32_t *) (cp + offsetof(struct gtp_ie_f_teid, ipv4));
		teid = gtp_teid_get(ctx->gtpc_teid_tab, &f_teid);
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
	f_teid.teid_grekey = (uint32_t *) (cp + offsetof(struct gtp1_ie_teid, id));
	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, srv->s.pbuff);
	if (!cp)
		return NULL;
	f_teid.ipv4 = (uint32_t *) (cp + sizeof(struct gtp1_ie));
	teid = gtp_teid_get(ctx->gtpc_teid_tab, &f_teid);
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
	struct gtp_teid * (*hdl) (struct gtp_server *, struct sockaddr_storage *);
} gtpc_msg_hdl[7] = {
	[1]	= { gtpc_proxy_handle_v1 },
	[2]	= { gtpc_proxy_handle_v2 },
};

struct gtp_teid *
gtpc_proxy_handle(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) srv->s.pbuff->head;

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
gtpc_proxy_handle_post(struct gtp_server *srv, struct gtp_teid *teid)
{
	struct gtp_session *s;

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
static struct gtp_teid *
gtpu_echo_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct gtp1_ie_recovery *rec;

	/* 3GPP.TS.129.060 7.2.2 : IE Recovery is mandatory in response message */
	h->type = GTPU_ECHO_RSP_TYPE;
	h->length = htons(ntohs(h->length) + sizeof(*rec));
	pkt_buffer_set_end_pointer(srv->s.pbuff, gtp1_get_header_len(h));
	pkt_buffer_set_data_pointer(srv->s.pbuff, gtp1_get_header_len(h));

	gtp1_ie_add_tail(srv->s.pbuff, sizeof(*rec));
	rec = (struct gtp1_ie_recovery *) srv->s.pbuff->data;
	rec->type = GTP1_IE_RECOVERY_TYPE;
	rec->recovery = 0;
	pkt_buffer_put_data(srv->s.pbuff, sizeof(*rec));

	return &dummy_teid;
}

static struct gtp_teid *
gtpu_error_indication_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid = NULL, *pteid = NULL;
	struct gtp_f_teid f_teid;
	uint8_t *cp;

	/* Data Plane IE */
	cp = gtp1_get_ie(GTP1_IE_TEID_DATA_TYPE, srv->s.pbuff);
	if (!cp)
		return NULL;
	f_teid.teid_grekey = (uint32_t *) (cp + offsetof(struct gtp1_ie_teid, id));

	cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, srv->s.pbuff);
	if (!cp)
		return NULL;
	f_teid.ipv4 = (uint32_t *) (cp + sizeof(struct gtp1_ie));

	teid = gtp_teid_get(ctx->gtpu_teid_tab, &f_teid);
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

static struct gtp_teid *
gtpu_end_marker_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) srv->s.pbuff->head;
	struct gtp_proxy *ctx = srv->ctx;
	struct gtp_teid *teid = NULL, *pteid = NULL;
	struct gtp_f_teid f_teid;
	uint32_t field = gtph->teid;

	/* TEID playground */
	f_teid.teid_grekey = &field;
	f_teid.ipv4 = &((struct sockaddr_in *) addr)->sin_addr.s_addr;

	teid = gtp_teid_get(ctx->gtpu_teid_tab, &f_teid);
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
	struct gtp_teid * (*hdl) (struct gtp_server *, struct sockaddr_storage *);
} gtpu_msg_hdl[0xff + 1] = {
	[GTPU_ECHO_REQ_TYPE]			= { gtpu_echo_request_hdl },
	[GTPU_ERR_IND_TYPE]			= { gtpu_error_indication_hdl },
	[GTPU_END_MARKER_TYPE]			= { gtpu_end_marker_hdl	},
};

struct gtp_teid *
gtpu_proxy_handle(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) srv->s.pbuff->head;
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
