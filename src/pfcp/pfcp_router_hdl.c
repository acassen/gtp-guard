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

#include "pfcp.h"
#include "pfcp_router.h"
#include "pfcp_router_hdl.h"
#include "pfcp_msg.h"
#include "pfcp_utils.h"
#include "pkt_buffer.h"
#include "utils.h"
#include "logger.h"


/*
 *	PFCP Protocol helpers
 */
static int
pfcp_heartbeat_response(struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_router *c = srv->ctx;
	struct pfcp_heartbeat_request req;
	struct pfcp_hdr *hdr = (struct pfcp_hdr *) pbuff->head;
	int err;

	/* Parse the request */
	err = pfcp_msg_parse(srv->s.pbuff, &req);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while parsing [%s] Request"
				    , __FUNCTION__
				    , pfcp_msgtype2str(req.h->type));
		return -1;
	}

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	hdr->type = PFCP_HEARTBEAT_RESPONSE;

	/* Append mandatory IE */
	err = pfcp_ie_put_recovery_ts(pbuff, c->recovery_ts);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant append recovery_ts IE"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
pfcp_assoc_setup_response(struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pfcp_association_setup_request req;
	int err;

	err = pfcp_msg_parse(srv->s.pbuff, &req);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while parsing [%s] Request"
				    , __FUNCTION__
				    , pfcp_msgtype2str(req.h->type));
		return -1;
	}



	return -1;
}





/*
 *	PFCP Message handle
 */
static const struct {
	int (*hdl) (struct pfcp_server *, struct sockaddr_storage *);
} pfcp_msg_hdl[1 << 8] = {
	/* PFCP Node related */
	[PFCP_HEARTBEAT_REQUEST]		= { pfcp_heartbeat_response },
	[PFCP_PFD_MANAGEMENT_REQUEST]		= { NULL },
	[PFCP_ASSOCIATION_SETUP_REQUEST]	= { pfcp_assoc_setup_response },
	[PFCP_ASSOCIATION_UPDATE_REQUEST]	= { NULL },
	[PFCP_ASSOCIATION_RELEASE_REQUEST]	= { NULL },
	[PFCP_NODE_REPORT_REQUEST]		= { NULL },
	[PFCP_SESSION_SET_DELETION_REQUEST]	= { NULL },
	[PFCP_SESSION_SET_MODIFICATION_REQUEST]	= { NULL },

	/* PFCP Session related */
	[PFCP_SESSION_ESTABLISHMENT_REQUEST]	= { NULL },
	[PFCP_SESSION_MODIFICATION_REQUEST]	= { NULL },
	[PFCP_SESSION_DELETION_REQUEST]		= { NULL },
	[PFCP_SESSION_REPORT_REQUEST]		= { NULL },
};

int
pfcp_router_handle(struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;

	printf("---[ incoming packet ]---\n");
	dump_buffer("PFCP ", (char *) pbuff->head, pkt_buffer_len(pbuff));

	if (*(pfcp_msg_hdl[pfcph->type].hdl)) {
		pfcp_metrics_rx(&srv->msg_metrics, pfcph->type);

		return (*(pfcp_msg_hdl[pfcph->type].hdl)) (srv, addr);
	}

	pfcp_metrics_rx_notsup(&srv->msg_metrics, pfcph->type);
	return -1;
}
