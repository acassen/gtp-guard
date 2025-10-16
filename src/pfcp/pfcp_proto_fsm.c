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
#include "pfcp_assoc.h"
#include "pfcp_msg.h"
#include "pfcp_proto_dump.h"
#include "pfcp_utils.h"
#include "pkt_buffer.h"
#include "bitops.h"
#include "logger.h"


/*
 *	PFCP Protocol helpers
 */
static int
pfcp_heartbeat_response(struct pfcp_msg *msg, struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *c = srv->ctx;
	int err;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_HEARTBEAT_RESPONSE;

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
pfcp_pfd_management_response(struct pfcp_msg *msg, struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *c = srv->ctx;
	int err;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_PFD_MANAGEMENT_RESPONSE;

	/* Append IEs */
	err = pfcp_ie_put_cause(pbuff, PFCP_CAUSE_REQUEST_ACCEPTED);
	err = (err) ? : pfcp_ie_put_node_id(pbuff, c->node_id, strlen(c->node_id));
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
pfcp_assoc_setup_response(struct pfcp_msg *msg, struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *c = srv->ctx;
	struct pfcp_assoc *assoc;
	struct pfcp_association_setup_request *req;
	uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;
	int err;

	req = msg->association_setup_request;

	/* 3GPP.TS.29.244 6.2.6.2.2 : Already exist ? */
	assoc = pfcp_assoc_get_by_ie(req->node_id);
	if (assoc) {
		if (!req->session_retention_info) {
			/* TODO: release all related Sessions */
		}

		assoc->recovery_ts = req->recovery_time_stamp->ts;
	} else {
		assoc = pfcp_assoc_alloc(req->node_id, req->recovery_time_stamp);
		if (!assoc) {
			cause = PFCP_CAUSE_REQUEST_REJECTED;
		}
	}

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_ASSOCIATION_SETUP_RESPONSE;

	/* Append IEs */
	err = pfcp_ie_put_node_id(pbuff, c->node_id, strlen(c->node_id));
	err = (err) ? : pfcp_ie_put_cause(pbuff, cause);
	err = (err) ? : pfcp_ie_put_recovery_ts(pbuff, c->recovery_ts);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}


/*
 *	PFCP FSM
 */
static const struct {
	int (*fsm) (struct pfcp_msg *, struct pfcp_server *, struct sockaddr_storage *);
} pfcp_fsm_msg[1 << 8] = {
	/* PFCP Node related */
	[PFCP_HEARTBEAT_REQUEST]		= { pfcp_heartbeat_response },
	[PFCP_PFD_MANAGEMENT_REQUEST]		= { pfcp_pfd_management_response },
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
pfcp_proto_fsm(struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pfcp_router *c = srv->ctx;
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_msg *msg;
	int err;

	msg = pfcp_msg_alloc();
	if (!msg) {
		log_message(LOG_INFO, "%s(): Error while parsing [%s] Request (%s)"
				    , __FUNCTION__
				    , pfcp_msgtype2str(pfcph->type)
				    , strerror(ENOMEM));
		return -1;
	}

	err = pfcp_msg_parse(srv->s.pbuff, msg);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while parsing [%s] Request"
				    , __FUNCTION__
				    , pfcp_msgtype2str(pfcph->type));
		err = -1;
		goto end;
	}

	if (__test_bit(PFCP_DEBUG_FL_INGRESS_MSG_BIT, &c->debug))
		pfcp_proto_dump(srv, msg, addr, PFCP_DIRECTION_INGRESS);

	if (!*(pfcp_fsm_msg[pfcph->type].fsm)) {
		pfcp_metrics_rx_notsup(&srv->msg_metrics, pfcph->type);
		err = -1;
		goto end;
	}

	pfcp_metrics_rx(&srv->msg_metrics, pfcph->type);
	err = (*(pfcp_fsm_msg[pfcph->type].fsm)) (msg, srv, addr);

	if (__test_bit(PFCP_DEBUG_FL_EGRESS_MSG_BIT, &c->debug))
		pfcp_proto_dump(srv, NULL, addr, PFCP_DIRECTION_EGRESS);

end:
	pfcp_msg_free(msg);
	return err;
}
