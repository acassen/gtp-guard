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
#include "gtp_handle_v1.h"
#include "gtp_handle_v2.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
gtp_teid_t dummy_teid = { .type = 0xff };


/*
 *	GTP-C Message handle
 */
gtp_session_t *
gtpc_retransmit_detected(gtp_srv_worker_t *w)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_ie_f_teid_t *ie_f_teid = NULL;
	gtp1_ie_teid_t *ie_teid = NULL;
	uint32_t *gsn_address_c = NULL;
	gtp_session_t *s = NULL;
	gtp_teid_t *teid;
	uint8_t *cp;

	if (gtph->version == 2) {
		cp = gtp_get_ie(GTP_IE_F_TEID_TYPE, w->buffer, w->buffer_size);
		if (!cp)
			return NULL;
		ie_f_teid = (gtp_ie_f_teid_t *) cp;
		teid = gtp_teid_get(&ctx->track[1].gtpc_teid_tab, ie_f_teid);
	} else {
		cp = gtp1_get_ie(GTP1_IE_TEID_CONTROL_TYPE, w->buffer, w->buffer_size);
		if (!cp)
			return NULL;
		ie_teid = (gtp1_ie_teid_t *) cp;

		cp = gtp1_get_ie(GTP1_IE_GSN_ADDRESS_TYPE, w->buffer, w->buffer_size);
		if (!cp)
			return NULL;
		gsn_address_c = (uint32_t *) (cp + sizeof(gtp1_ie_t));

		PMALLOC(ie_f_teid);
		ie_f_teid->teid_grekey = ie_teid->id;
		ie_f_teid->v4 = 1;
		ie_f_teid->ipv4 = *gsn_address_c;
		teid = gtp_teid_get(&ctx->track[0].gtpc_teid_tab, ie_f_teid);
		FREE(ie_f_teid);
	}

	if (teid) {
		/* same SQN too ?*/
		if (gtph->teid_presence)
			s = (gtph->sqn == teid->sqn) ? teid->session : NULL;
		else if (gtph->sqn_only == teid->sqn)
			s = teid->session;

		gtp_teid_put(teid);
		return s;
	}

	return NULL;
}

gtp_teid_t *
gtpc_handle(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;

	if (gtph->version == 1)
		return gtpc_handle_v1(w, addr);

	if (gtph->version == 2)
		return gtpc_handle_v2(w, addr);

	return NULL;
}

int
gtpc_handle_post(gtp_srv_worker_t *w, gtp_teid_t *teid)
{
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_session_t *s;

	if (!teid || teid->type == 0xff)
		return -1;

	s = teid->session;
	if (s->action == GTP_ACTION_DELETE_SESSION) {
		gtp_teid_put(teid);
		gtp_session_destroy(ctx, s);
		return 0;
	}

	gtp_teid_put(teid);
	return 0;
}


/*
 *	GTP-U Message handle
 */
static gtp_teid_t *
gtpu_error_indication_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;
	ssize_t len = gtpu_get_header_len(w->buffer, w->buffer_size);
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid, *pteid = NULL;
	gtp_ie_f_teid_t *f_teid;
	gtp_htab_t *htab;
	uint8_t *cp;
	uint32_t *field;
	uint16_t *length;

	/* Tunnel Endpoint Identifier Data I */
	cp = w->buffer + len;
	if (*cp != GTP_IE_TUNNEL_ENDPOINT_ID_DATA_I)
		return NULL;
	field = (uint32_t *) (++cp);

	PMALLOC(f_teid);
	f_teid->teid_grekey = *field;
	f_teid->v4 = 1;
	f_teid->ipv4 = ((struct sockaddr_in *) addr)->sin_addr.s_addr;

	htab = (gtph->version == 1) ? &ctx->track[0].gtpu_teid_tab :
				      &ctx->track[1].gtpu_teid_tab;
	teid = gtp_teid_get(htab, f_teid);
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x. Ignoring"
				    , __FUNCTION__
				    , ntohl(*field));
		FREE(f_teid);
		return NULL;
	}

	FREE(f_teid);

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
	*field = htonl(teid->vid);

	/* Continue with GTP-U Peer Address */
	cp += 4;
	if (*cp != GTP_IE_GTPU_PEER_ADDRESS)
		return NULL;
	length = (uint16_t *) (++cp);

	/* Hard coded for IPv4... ugly... */
	if (ntohs(*length) != 4)
		return NULL;

	field = (uint32_t *) (cp + 2);
	*field = ((struct sockaddr_in *) &srv->addr)->sin_addr.s_addr;

	/* Finaly set addr back to linked peer */
	((struct sockaddr_in *) addr)->sin_addr.s_addr = pteid->ipv4;

	return teid;
}

static gtp_teid_t *
gtpu_end_marker_hdl(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;
	gtp_srv_t *srv = w->srv;
	gtp_ctx_t *ctx = srv->ctx;
	gtp_teid_t *teid, *pteid = NULL;
	gtp_ie_f_teid_t *f_teid;
	gtp_htab_t *htab;

	/* TEID playground */
	PMALLOC(f_teid);
	f_teid->teid_grekey = gtph->teid;
	f_teid->v4 = 1;
	f_teid->ipv4 = ((struct sockaddr_in *) addr)->sin_addr.s_addr;

	htab = (gtph->version == 1) ? &ctx->track[0].gtpu_teid_tab :
				      &ctx->track[1].gtpu_teid_tab;
	teid = gtp_teid_get(htab, f_teid);
	if (!teid) {
		log_message(LOG_INFO, "%s(): unknown TEID:0x%.8x. Ignoring"
				    , __FUNCTION__
				    , ntohl(gtph->teid));
		FREE(f_teid);
		return NULL;
	}

	FREE(f_teid);

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
	gtp_teid_t * (*hdl) (gtp_srv_worker_t *, struct sockaddr_storage *);
} gtpu_msg_hdl[0xff] = {
	[GTPU_ERR_IND_TYPE]			= { gtpu_error_indication_hdl },
	[GTPU_END_MARKER_TYPE]			= { gtpu_end_marker_hdl },
};

gtp_teid_t *
gtpu_handle(gtp_srv_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->buffer;
	ssize_t len;

	len = gtpu_get_header_len(w->buffer, w->buffer_size);
	if (len < 0)
		return NULL;

	/* Special care to create and delete session */
	if (*(gtpu_msg_hdl[gtph->type].hdl))
		return (*(gtpu_msg_hdl[gtph->type].hdl)) (w, addr);

	/* Not supported */
	log_message(LOG_INFO, "%s(): GTP-U/path-mgt msg_type:0x%.2x not supported..."
			    , __FUNCTION__
			    , gtph->type);
	return NULL;
}
