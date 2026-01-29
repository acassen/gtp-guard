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

#include <inttypes.h>
#include <sys/socket.h>
#include <errno.h>
#include "gtp.h"
#include "gtp_utils.h"
#include "pfcp.h"
#include "pfcp_router.h"
#include "pfcp_assoc.h"
#include "pfcp_session.h"
#include "pfcp_session_report.h"
#include "pfcp_msg.h"
#include "pfcp_proto_dump.h"
#include "pfcp_utils.h"
#include "gtp_conn.h"
#include "gtp_apn.h"
#include "gtp_bpf_utils.h"
#include "inet_utils.h"
#include "pkt_buffer.h"
#include "bitops.h"
#include "logger.h"


/*
 *	PFCP Protocol helpers
 */

/* Heartbeat */
static int
pfcp_heartbeat_request(struct pfcp_msg *msg, struct pfcp_server *srv,
		       struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
	int err;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_HEARTBEAT_RESPONSE;

	/* Append mandatory IE */
	err = pfcp_ie_put_recovery_ts(pbuff, ctx->recovery_ts);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant append recovery_ts IE"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}


/* pfd management */
static int
pfcp_pfd_management_request(struct pfcp_msg *msg, struct pfcp_server *srv,
			    struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
	int err;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_PFD_MANAGEMENT_RESPONSE;

	/* Append IEs */
	err = pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
				      PFCP_CAUSE_REQUEST_ACCEPTED);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}


/* Association setup */
static int
pfcp_assoc_setup_request(struct pfcp_msg *msg, struct pfcp_server *srv,
			 struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
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
	err = pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len, cause);
	err = (err) ? : pfcp_ie_put_recovery_ts(pbuff, ctx->recovery_ts);
	err = (err) ? : pfcp_ie_put_up_function_features(pbuff, ctx->supported_features);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
pfcp_assoc_setup_response(struct pfcp_msg *msg, struct pfcp_server *srv,
			  struct sockaddr_storage *addr)
{
	struct pfcp_association_setup_response *rsp;
	struct pfcp_assoc *assoc;
	char assoc_str[GTP_NAME_MAX_LEN];

	rsp = msg->association_setup_response;

	if (rsp->cause->value != PFCP_CAUSE_REQUEST_ACCEPTED) {
		log_message(LOG_INFO, "%s(): remote PFCP peer:'%s' rejection (%s)"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , pfcp_cause2str(rsp->cause->value));
		return -1;
	}

	/* Already exit... ignore... */
	assoc = pfcp_assoc_get_by_ie(rsp->node_id);
	if (assoc)
		return -1;

	/* Create this brand new one ! */
	assoc = pfcp_assoc_alloc(rsp->node_id, rsp->recovery_time_stamp);
	log_message(LOG_INFO, "%s(): %s Creating PFCP association:'%s'"
			    , __FUNCTION__
			    , (assoc) ? "Success" : "Error"
			    , pfcp_assoc_stringify(assoc, assoc_str, GTP_NAME_MAX_LEN));

	return -1;
}

void
pfcp_assoc_setup_request_send(struct thread *t)
{
	struct pfcp_router *ctx = THREAD_ARG(t);
	struct pfcp_peer_list *plist = ctx->peer_list;
	struct pkt_buffer *pbuff;
	struct pfcp_hdr *pfcph;
	int err = 0, i;

	/* Prepare pkt */
	pbuff = pkt_buffer_alloc(DEFAULT_PKT_BUFFER_SIZE);
	pfcph = (struct pfcp_hdr *) pbuff->head;
	pfcph->version = 1;
	pfcph->type = PFCP_ASSOCIATION_SETUP_REQUEST;
	pfcph->sqn_only = htonl(1 << 8);
	pfcp_msg_reset_hlen(pbuff);

	err = pfcp_ie_put_node_id(pbuff, ctx->node_id, ctx->node_id_len);
	err = (err) ? : pfcp_ie_put_recovery_ts(pbuff, ctx->recovery_ts);
	err = (err) ? : pfcp_ie_put_up_function_features(pbuff, ctx->supported_features);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		goto end;
	}

	/* Broadcast pkt to peer list */
	for (i = 0; i < plist->nr_addr; i++) {
		/* TODO: only support IPv4 peer from now */
		if (plist->addr[i].family != AF_INET)
			continue;

		inet_server_snd(&ctx->s.s, ctx->s.s.fd, pbuff, &plist->addr[i].sin);
	}

end:
	pkt_buffer_free(pbuff);
}


/* Session Establishment */
static struct gtp_apn *
pfcp_session_get_apn(struct pfcp_ie_apn_dnn *apn_dnn)
{
	struct gtp_apn *apn;
	char apn_str[64];
	int err;

	if (!apn_dnn)
		return NULL;

	err = pfcp_ie_decode_apn_dnn_ni(apn_dnn, apn_str, sizeof(apn_str) - 1);
	if (err) {
		log_message(LOG_INFO, "%s(): malformed IE APN-DNN... rejecting..."
				    , __FUNCTION__);
		return NULL;
	}

	apn = gtp_apn_get(apn_str);
	if (!apn) {
		log_message(LOG_INFO, "%s(): Unknown Access-Point-Name:'%s'. rejecting..."
				    , __FUNCTION__, apn_str);
		return NULL;
	}

	return apn;
}

static int
pfcp_session_establishment_request(struct pfcp_msg *msg, struct pfcp_server *srv,
				   struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
	struct pfcp_assoc *assoc;
	struct pfcp_session *s;
	struct gtp_conn *c;
	struct gtp_apn *apn = NULL;
	struct pfcp_session_establishment_request *req;
	uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;
	uint64_t imsi, imei, msisdn;
	int err;

	req = msg->session_establishment_request;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_SESSION_ESTABLISHMENT_RESPONSE;

	assoc = pfcp_assoc_get_by_ie(req->node_id);
	if (!assoc)
		return pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
					       PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION);

	/* APN selection */
	if (__test_bit(PFCP_ROUTER_FL_STRICT_APN, &ctx->flags)) {
		apn = pfcp_session_get_apn(req->apn_dnn);
		if (!apn)
			return pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
						       PFCP_CAUSE_REQUEST_REJECTED);
	}

	/* User infos */
	if (!req->user_id) {
		log_message(LOG_INFO, "%s(): IE User-ID not present... rejecting..."
				    , __FUNCTION__);
		return pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
					       PFCP_CAUSE_REQUEST_REJECTED);
	}

	err = pfcp_ie_decode_user_id(req->user_id, &imsi, &imei, &msisdn);
	if (err) {
		log_message(LOG_INFO, "%s(): malformed IE User-ID... rejecting..."
				    , __FUNCTION__);
		return pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
					       PFCP_CAUSE_REQUEST_REJECTED);
	}

	c = gtp_conn_get_by_imsi(imsi);
	if (!c)
		c = gtp_conn_alloc(imsi, imei, msisdn);

	/* Create new session */
	s = pfcp_session_alloc(c, apn, ctx);
	if (!s) {
		log_message(LOG_INFO, "%s(): Unable to create new session... rejecting..."
				    , __FUNCTION__);
		return pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
					       PFCP_CAUSE_REQUEST_REJECTED);
	}

	err = pfcp_session_create(s, req, addr);
	if (err) {
		log_message(LOG_INFO, "%s(): malformed IE Create-PDR... rejecting..."
				    , __FUNCTION__);
		return pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
					       PFCP_CAUSE_REQUEST_REJECTED);
	}

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_SESSION_ESTABLISHMENT_RESPONSE;
	pfcph->seid = s->remote_seid.id;

	/* Append IEs */
	err = pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len, cause);
	err = (err) ? : pfcp_ie_put_f_seid(pbuff, htobe64(s->seid), &srv->s.addr);
	err = (err) ? : pfcp_session_put_created_pdr(pbuff, s);
	err = (err) ? : pfcp_session_put_created_traffic_endpoint(pbuff, s);
	if (err) {
		if (errno == ENOSPC)
			return pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
						       PFCP_CAUSE_ALL_DYNAMIC_ADDRESS_ARE_OCCUPIED);

		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	/* Data-Path setup */
	err = pfcp_bpf_session_action(s, RULE_ADD);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Setting eBPF rules"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}

/* Session modification */
static int
pfcp_session_modification_request(struct pfcp_msg *msg, struct pfcp_server *srv,
				  struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_session_modification_request *req;
	uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;
	struct pfcp_session *s;
	int err;

	req = msg->session_modification_request;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_SESSION_MODIFICATION_RESPONSE;

	if (!pfcph->s) {
		log_message(LOG_INFO, "%s(): Session-ID is not present... rejecting..."
				    , __FUNCTION__);
		return pfcp_ie_put_cause(pbuff, PFCP_CAUSE_REQUEST_REJECTED);
	}

	s = pfcp_session_get(be64toh(pfcph->seid));
	if (!s) {
		log_message(LOG_INFO, "%s(): Unknown Session-ID:0x%" PRIx64 "... rejecting..."
				    , __FUNCTION__, be64toh(pfcph->seid));
		return pfcp_ie_put_cause(pbuff, PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND);
	}
	pfcph->seid = s->remote_seid.id;

	err = pfcp_session_modify(s, req);
	if (err) {
		log_message(LOG_INFO, "%s(): malformed Modification request... rejecting..."
				    , __FUNCTION__);
		return pfcp_ie_put_cause(pbuff, PFCP_CAUSE_REQUEST_REJECTED);
	}

	/* Append IEs */
	err = pfcp_ie_put_cause(pbuff, cause);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	/* URR query ? */
	if ((req->pfcpsmreq_flags && req->pfcpsmreq_flags->qaurr) || req->nr_query_urr) {
		err = pfcp_ie_put_additional_usage_reports_info(pbuff, true, 0);
		if (err) {
			log_message(LOG_INFO, "%s(): Error while adding AURI IE"
					    , __FUNCTION__);
			return -1;
		}

		pfcp_session_report(s, req, addr);
	}

	/* Data-Path setup */
	err = pfcp_bpf_session_action(s, RULE_ADD);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Setting eBPF rules"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}

/* Session deletion */
static int
pfcp_session_deletion_request(struct pfcp_msg *msg, struct pfcp_server *srv,
			      struct sockaddr_storage *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;
	struct pfcp_session *s;
	int err;

	if (!pfcph->s) {
		log_message(LOG_INFO, "%s(): Session-ID is not present... rejecting..."
				    , __FUNCTION__);
		return pfcp_ie_put_cause(pbuff, PFCP_CAUSE_REQUEST_REJECTED);
	}

	s = pfcp_session_get(be64toh(pfcph->seid));
	if (!s) {
		log_message(LOG_INFO, "%s(): Unknown Session-ID:0x%" PRIx64 "... rejecting..."
				    , __FUNCTION__, be64toh(pfcph->seid));
		return pfcp_ie_put_cause(pbuff, PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND);
	}

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_SESSION_DELETION_RESPONSE;
	pfcph->seid = s->remote_seid.id;

	/* Append IEs */
	err = pfcp_ie_put_cause(pbuff, cause);
	err = (err) ? : pfcp_session_put_usage_report_deletion(pbuff, s);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	pfcp_session_destroy(s);
	return 0;
}


/*
 *	PFCP FSM
 */
static const struct {
	int (*hdl) (struct pfcp_msg *, struct pfcp_server *, struct sockaddr_storage *);
} pfcp_msg_hdl[1 << 8] = {
	/* PFCP Node related */
	[PFCP_HEARTBEAT_REQUEST]		= { pfcp_heartbeat_request },
	[PFCP_PFD_MANAGEMENT_REQUEST]		= { pfcp_pfd_management_request },
	[PFCP_ASSOCIATION_SETUP_REQUEST]	= { pfcp_assoc_setup_request },
	[PFCP_ASSOCIATION_SETUP_RESPONSE]	= { pfcp_assoc_setup_response },
	[PFCP_ASSOCIATION_UPDATE_REQUEST]	= { NULL },
	[PFCP_ASSOCIATION_RELEASE_REQUEST]	= { NULL },
	[PFCP_NODE_REPORT_REQUEST]		= { NULL },
	[PFCP_SESSION_SET_DELETION_REQUEST]	= { NULL },
	[PFCP_SESSION_SET_MODIFICATION_REQUEST]	= { NULL },

	/* PFCP Session related */
	[PFCP_SESSION_ESTABLISHMENT_REQUEST]	= { pfcp_session_establishment_request },
	[PFCP_SESSION_MODIFICATION_REQUEST]	= { pfcp_session_modification_request },
	[PFCP_SESSION_DELETION_REQUEST]		= { pfcp_session_deletion_request },
	[PFCP_SESSION_REPORT_REQUEST]		= { NULL },
};

int
pfcp_proto_hdl(struct pfcp_server *srv, struct sockaddr_storage *addr)
{
	struct pfcp_router *c = srv->ctx;
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_msg *msg = srv->msg;
	int err;

	err = pfcp_msg_parse(msg, srv->s.pbuff);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while parsing [%s] Request"
				    , __FUNCTION__
				    , pfcp_msgtype2str(pfcph->type));
		err = -1;
		goto end;
	}

	if (__test_bit(PFCP_DEBUG_FL_INGRESS_MSG, &c->debug))
		pfcp_proto_dump(srv, msg, addr, PFCP_DIR_INGRESS);

	if (!*(pfcp_msg_hdl[pfcph->type].hdl)) {
		pfcp_metrics_rx_notsup(&srv->msg_metrics, pfcph->type);
		err = -1;
		goto end;
	}

	pfcp_metrics_rx(&srv->msg_metrics, pfcph->type);
	err = (*(pfcp_msg_hdl[pfcph->type].hdl)) (msg, srv, addr);

	if (__test_bit(PFCP_DEBUG_FL_EGRESS_MSG, &c->debug))
		pfcp_proto_dump(srv, NULL, addr, PFCP_DIR_EGRESS);

end:
	return err;
}


/*
 *	GTP-U Message handle
 */
int
gtpu_send_end_marker(struct gtp_server *srv, struct pfcp_teid *t)
{
	struct gtp1_hdr *h = (struct gtp1_hdr *) srv->s.pbuff->head;
	struct sockaddr_in addr_to = {
		.sin_family = AF_INET,
		.sin_addr = t->ipv4,
		.sin_port = htons(GTP_U_PORT),
	};

	memset(h, 0, sizeof(*h));
	h->flags = 0x30; /* GTP-Rel99 + GTPv1 */
	h->type = GTPU_END_MARKER_TYPE;
	h->teid_only = t->id;
	pkt_buffer_set_end_pointer(srv->s.pbuff, gtp1_get_header_len(h));
	pkt_buffer_set_data_pointer(srv->s.pbuff, gtp1_get_header_len(h));

	return inet_server_snd(&srv->s, srv->s.fd, srv->s.pbuff, &addr_to);
}

static int
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
	return 0;
}

static int
gtpu_error_indication_hdl(struct gtp_server *s, struct sockaddr_storage *addr)
{
	return 0;
}

static int
gtpu_end_marker_hdl(struct gtp_server *s, struct sockaddr_storage *addr)
{
	/* TODO: Release related TEID */
	return 0;
}

static const struct {
	int (*hdl) (struct gtp_server *, struct sockaddr_storage *);
} gtpu_msg_hdl[1 << 8] = {
	[GTPU_ECHO_REQ_TYPE]			= { gtpu_echo_request_hdl },
	[GTPU_ERR_IND_TYPE]			= { gtpu_error_indication_hdl },
	[GTPU_END_MARKER_TYPE]			= { gtpu_end_marker_hdl	},
};

int
pfcp_gtpu_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) srv->s.pbuff->head;
	ssize_t len;

	len = gtpu_get_header_len(srv->s.pbuff);
	if (len < 0)
		return -1;

	if (*(gtpu_msg_hdl[gtph->type].hdl)) {
		gtp_metrics_rx(&srv->msg_metrics, gtph->type);

		return (*(gtpu_msg_hdl[gtph->type].hdl)) (srv, addr);
	}

	/* Not supported */
	log_message(LOG_INFO, "%s(): GTP-U/path-mgt msg_type:0x%.2x from %s not supported..."
			    , __FUNCTION__
			    , gtph->type
			    , inet_sockaddrtos(addr));

	gtp_metrics_rx_notsup(&srv->msg_metrics, gtph->type);
	return -1;
}



