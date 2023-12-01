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
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_session.h"
#include "gtp_router_hdl.h"
#include "gtp_sqn.h"
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

	return 0;
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
