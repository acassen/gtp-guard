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
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
extern gtp_teid_t dummy_teid;


/*
 *	Utilities
 */
static gtp_teid_t *
gtpc_msg_retransmit(gtp_router_t *ctx, gtp_hdr_t *h, uint8_t *ie_buffer)
{
	gtp_teid_t *teid;
	gtp_f_teid_t f_teid;

	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));
	teid = gtp_teid_get(&ctx->gtpc_teid_tab, &f_teid);
	if (!teid)
		return NULL;

	if (h->teid_presence)
		return (h->sqn == teid->sqn) ? teid : NULL;
	if (h->sqn_only == teid->sqn)
		return teid;

	return NULL;
}

static gtp_teid_t *
gtp_teid_set(gtp_teid_t *teid, uint8_t type, int direction, gtp_session_t *s, uint32_t sqn)
{
	if (!teid)
		return NULL;

	teid->type = type;
	teid->session = s;
	teid->sqn = sqn;

	/* Add to list */
	if (type == GTP_TEID_C) {
		gtp_session_gtpc_teid_add(s, teid);
	} else if (type == GTP_TEID_U) {
		gtp_session_gtpu_teid_add(s, teid);

		/* Fast-Path setup */
//		gtp_xdp_rt_teid_action(RULE_ADD, teid, direction);
	}

	return teid;
}

static gtp_teid_t *
gtp_teid_create(uint8_t type, int direction, gtp_session_t *s, gtp_htab_t *h,
		uint32_t sqn, gtp_f_teid_t *f_teid, gtp_ie_eps_bearer_id_t *bearer_id)
{
	gtp_teid_t *teid = NULL;

	teid = gtp_teid_get(h, f_teid);
	if (teid) {
		/* update sqn */
		teid->sqn = sqn;
		return teid;
	}

	teid = gtp_teid_alloc(h, f_teid, bearer_id);
	return gtp_teid_set(teid, type, direction, s, sqn);
}

static gtp_teid_t *
gtp_session_append_gtpu(gtp_server_worker_t *w, gtp_session_t *s, int direction, void *arg, uint8_t *ie_buffer)
{
	gtp_server_t *srv = w->srv;
	gtp_router_t *ctx = srv->ctx;
	gtp_ie_eps_bearer_id_t *bearer_id = arg;
	gtp_f_teid_t f_teid;
	gtp_teid_t *teid, *pteid;

	f_teid.version = 2;
	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));

	teid = gtp_teid_create(GTP_TEID_U, direction, s
					 , &ctx->gtpu_teid_tab
					 , 0, &f_teid, bearer_id);
	pteid = gtp_teid_alloc_peer(&ctx->gtpu_teid_tab, teid,
				    inet_sockaddrip4(&w->srv->addr), &w->seed);
	gtp_teid_set(pteid, GTP_TEID_U, !direction, s, 0);
	return teid;
}

static gtp_teid_t *
gtpc_session_create(gtp_server_worker_t *w, gtp_msg_t *msg, gtp_session_t *s)
{
	gtp_hdr_t *h = msg->h;
	gtp_conn_t *c = s->conn;
	gtp_router_t *ctx = c->ctx;
	gtp_teid_t *teid = NULL, *pteid;
	gtp_msg_ie_t *msg_ie;
	gtp_f_teid_t f_teid;
	gtp_ie_eps_bearer_id_t *bearer_id = NULL;
	uint8_t *ie_buffer, *cp_bid;
	uint32_t sqn;

	/* GTP-C create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (msg_ie) {
		ie_buffer = (uint8_t *) msg_ie->h;
		f_teid.version = 2;
		f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
		f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));
		sqn = (h->teid_presence) ? h->sqn : h->sqn_only;
		teid = gtp_teid_create(GTP_TEID_C, GTP_INGRESS, s
						 , &ctx->gtpc_teid_tab
						 , sqn, &f_teid, NULL);
		pteid = gtp_teid_alloc_peer(&ctx->gtpc_teid_tab, teid,
					    inet_sockaddrip4(&w->srv->addr), &w->seed);
		gtp_teid_set(pteid, GTP_TEID_C, GTP_EGRESS, s, 0);
	}

	/* GTP-U create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_BEARER_CONTEXT_TYPE);
	if (!msg_ie)
		return teid;

	cp_bid = gtp_get_ie_offset(GTP_IE_EPS_BEARER_ID,(uint8_t *) msg_ie->data, ntohs(msg_ie->h->length), 0);
	bearer_id = (cp_bid) ? (gtp_ie_eps_bearer_id_t *) cp_bid : NULL;
	gtp_foreach_ie(GTP_IE_F_TEID_TYPE, (uint8_t *) msg_ie->data, 0
					 , (uint8_t *) msg_ie->data + ntohs(msg_ie->h->length)
					 , w, s, GTP_INGRESS
					 , bearer_id, gtp_session_append_gtpu);
	return teid;
}


/*
 *	Packet factory
 */
static int
gtpc_pkt_put_ie(pkt_buffer_t *pbuff, uint8_t type, uint16_t length)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	gtp_ie_t *ie;

	if (pkt_buffer_put_zero(pbuff, length) < 0)
		return 1;

	ie = (gtp_ie_t *) pbuff->data;
	ie->type = type;
	ie->length = htons(length - sizeof(gtp_ie_t));
	h->length = htons(ntohs(h->length) + length);
	return 0;
}

static int
gtpc_pkt_put_pid(pkt_buffer_t *pbuff,  uint16_t type, uint8_t length)
{
	gtp_pco_pid_t *pid;

	if (pkt_buffer_put_zero(pbuff, length) < 0)
		return 1;

	pid = (gtp_pco_pid_t *) pbuff->data;
	pid->type = htons(type);
	return 0;
}

static int
gtpc_pkt_put_cause(pkt_buffer_t *pbuff, uint8_t cause)
{
	gtp_ie_cause_t *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_CAUSE_TYPE, sizeof(gtp_ie_cause_t)) < 0)
		return 1;

	ie = (gtp_ie_cause_t *) pbuff->data;
	ie->value = cause;
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_cause_t));
	return 0;
}

static int
gtpc_pkt_put_recovery(pkt_buffer_t *pbuff)
{
	gtp_ie_recovery_t *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_RECOVERY_TYPE, sizeof(gtp_ie_recovery_t)) < 0)
		return 1;

	ie = (gtp_ie_recovery_t *) pbuff->data;
	ie->recovery = daemon_data->restart_counter;
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_recovery_t));
	return 0;
}

static int
gtpc_pkt_put_indication(pkt_buffer_t *pbuff, uint32_t bits)
{
	gtp_ie_indication_t *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_INDICATION_TYPE, sizeof(gtp_ie_indication_t)) < 0)
		return 1;

	ie = (gtp_ie_indication_t *) pbuff->data;
	ie->bits = htonl(bits);
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_indication_t));
	return 0;
}

static int
gtpc_pkt_put_ppp_ipcp_ip4(pkt_buffer_t *pbuff, gtp_pco_pid_ipcp_t *pid,
			  struct sockaddr_storage *addr, uint8_t type)
{
	gtp_ppp_ipcp_option_ip4_t *ppp_ipcp_ip4;

	if (!addr->ss_family)
		return 0;

	if (pkt_buffer_put_zero(pbuff, sizeof(gtp_ppp_ipcp_option_ip4_t)) < 0)
		return 1;

	ppp_ipcp_ip4 = (gtp_ppp_ipcp_option_ip4_t *) pbuff->data;
	ppp_ipcp_ip4->type = type;
	ppp_ipcp_ip4->length = 6;
	ppp_ipcp_ip4->addr = inet_sockaddrip4(addr);
	pkt_buffer_put_data(pbuff, sizeof(gtp_ppp_ipcp_option_ip4_t));
	pid->length = htons(ntohs(pid->length) + sizeof(gtp_ppp_ipcp_option_ip4_t));
	return 0;
}

static int
gtpc_pkt_put_pco_pid_ipcp(pkt_buffer_t *pbuff, gtp_pco_t *pco, gtp_ie_pco_t *ie_pco)
{
	gtp_pco_pid_ipcp_t *pid;
	int err = 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_IPCP, sizeof(gtp_pco_pid_ipcp_t)) < 0)
		return 1;

	pid = (gtp_pco_pid_ipcp_t *) pbuff->data;
	pid->code = PPP_CONF_NAK;
	pid->id = 0;
	pid->length = htons(sizeof(gtp_pco_pid_ipcp_t)-sizeof(gtp_pco_pid_t));
	pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_ipcp_t));

	err = (err) ? : gtpc_pkt_put_ppp_ipcp_ip4(pbuff, pid, &pco->ipcp_primary_ns, PPP_IPCP_PRIMARY_NS);
	err = (err) ? : gtpc_pkt_put_ppp_ipcp_ip4(pbuff, pid, &pco->ipcp_secondary_ns, PPP_IPCP_SECONDARY_NS);
	if (err)
		return 1;

	pid->h.length = ntohs(pid->length); /* protocol encoding legacy stuff */
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) + ntohs(pid->length));
	return 0;
}

static int
gtpc_pkt_put_pco_pid_dns(pkt_buffer_t *pbuff, gtp_pco_t *pco, gtp_ie_pco_t *ie_pco)
{
	list_head_t *l = &pco->ns;
	gtp_ns_t *ns;
	gtp_pco_pid_dns_t *pid;

	list_for_each_entry(ns, l, next) {
		if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_DNS, sizeof(gtp_pco_pid_dns_t)) < 0)
			return 1;
		pid = (gtp_pco_pid_dns_t *) pbuff->data;
		pid->h.length = 4;
		pid->addr = inet_sockaddrip4(&ns->addr);
		pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_dns_t));
		ie_pco->h.length = htons(ntohs(ie_pco->h.length) + pid->h.length);
	}

	return 0;
}

static int
gtpc_pkt_put_pco_pid_mtu(pkt_buffer_t *pbuff, gtp_pco_t *pco, gtp_ie_pco_t *ie_pco)
{
	gtp_pco_pid_mtu_t *pid;

	if (!pco->link_mtu)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_MTU, sizeof(gtp_pco_pid_mtu_t)) < 0)
		return 1;

	pid = (gtp_pco_pid_mtu_t *) pbuff->data;
	pid->h.length = 2;
	pid->mtu = htons(pco->link_mtu);
	pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_mtu_t));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) + pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco_pid_sbcm(pkt_buffer_t *pbuff, gtp_pco_t *pco, gtp_ie_pco_t *ie_pco)
{
	gtp_pco_pid_sbcm_t *pid;

	if (!pco->selected_bearer_control_mode)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_SBCM, sizeof(gtp_pco_pid_sbcm_t)) < 0)
		return 1;

	pid = (gtp_pco_pid_sbcm_t *) pbuff->data;
	pid->h.length = 1;
	pid->sbcm = pco->selected_bearer_control_mode;
	pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_sbcm_t));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) + pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco(pkt_buffer_t *pbuff, gtp_pco_t *pco)
{
	gtp_ie_pco_t *ie_pco;
	int err = 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_PCO_TYPE, sizeof(gtp_ie_pco_t)) < 0)
		return 1;

	ie_pco = (gtp_ie_pco_t *) pbuff->data;
	ie_pco->ext = 1 << 7; /* Extension is TRUE */
	ie_pco->h.length = htons(1);
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_pco_t));

	/* Put Protocol or Container ID */
	err = (err) ? : gtpc_pkt_put_pco_pid_ipcp(pbuff, pco, ie_pco);
	err = (err) ? : gtpc_pkt_put_pco_pid_dns(pbuff, pco, ie_pco);
	err = (err) ? : gtpc_pkt_put_pco_pid_mtu(pbuff, pco, ie_pco);
	err = (err) ? : gtpc_pkt_put_pco_pid_sbcm(pbuff, pco, ie_pco);
	return err;
}

static int
gtpc_pkt_put_f_teid(pkt_buffer_t *pbuff, gtp_teid_t *teid)
{
	gtp_ie_f_teid_t *f_teid;
	uint16_t len = sizeof(gtp_ie_f_teid_t);

	len -= (teid->ipv4) ? 3*sizeof(uint32_t) : 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_F_TEID_TYPE, len) < 0)
		return 1;

	f_teid = (gtp_ie_f_teid_t *) pbuff->data;
	f_teid->h.instance = 1;
	f_teid->v4 = 1;
	f_teid->interface_type = GTP_TEID_INTERFACE_TYPE_SGW_GTPC;
	f_teid->teid_grekey = htonl(teid->id);
	f_teid->ipv4 = teid->ipv4;
	pkt_buffer_put_data(pbuff, len);
	return 0;
}

static int
gtpc_pkt_put_apn_restriction(pkt_buffer_t *pbuff, gtp_apn_t *apn)
{
	gtp_ie_apn_restriction_t *restriction;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_APN_RESTRICTION_TYPE, sizeof(gtp_ie_apn_restriction_t)) < 0)
		return 1;

	restriction = (gtp_ie_apn_restriction_t *) pbuff->data;
	restriction->value = apn->restriction;
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_apn_restriction_t));
	return 0;
}

static int
gtpc_pkt_put_paa(pkt_buffer_t *pbuff, uint32_t addr)
{
	gtp_ie_paa_t *paa;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_PAA_TYPE, sizeof(gtp_ie_paa_t)) < 0)
		return 1;

	paa = (gtp_ie_paa_t *) pbuff->data;
	paa->type = GTP_PAA_IPV4_TYPE;
	paa->addr = addr;
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_paa_t));
	return 0;
}

static int
gtpc_build_create_session_response(pkt_buffer_t *pbuff, gtp_session_t *s, gtp_teid_t *teid)
{
	gtp_apn_t *apn = s->apn;
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	int err = 0;

	/* Header update */
	h->type = GTP_CREATE_SESSION_RESPONSE_TYPE;
	h->length = 0;
	h->teid = htonl(teid->id);
	pkt_buffer_set_end_pointer(pbuff, sizeof(gtp_hdr_t));
	pkt_buffer_set_data_pointer(pbuff, sizeof(gtp_hdr_t));

	/* Put IE */
	err = (err) ? : gtpc_pkt_put_cause(pbuff, GTP_CAUSE_REQUEST_ACCEPTED);
	err = (err) ? : gtpc_pkt_put_recovery(pbuff);
	err = (err) ? : gtpc_pkt_put_indication(pbuff, apn->indication_flags);
	err = (err) ? : gtpc_pkt_put_pco(pbuff, apn->pco);
	err = (err) ? : gtpc_pkt_put_f_teid(pbuff, teid->peer_teid);
	err = (err) ? : gtpc_pkt_put_apn_restriction(pbuff, apn);
	err = (err) ? : gtpc_pkt_put_paa(pbuff, s->ipv4);
	if (err) {
		log_message(LOG_INFO, "%s(): Error building PKT !?");
		return -1;
	}

	dump_buffer("", (char *) pbuff->head, pkt_buffer_len(pbuff));

	return 0;
}


/*
 *	GTP-C Protocol helpers
 */
static int
gtpc_echo_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
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

	return 0;
}

static int
gtpc_create_session_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_msg_t *msg;
	gtp_msg_ie_t *msg_ie;
	gtp_server_t *srv = w->srv;
	gtp_router_t *ctx = srv->ctx;
	gtp_conn_t *c;
	gtp_session_t *s = NULL;
	gtp_teid_t *teid;
	gtp_apn_t *apn;
	char apn_str[64];
	uint64_t imsi;
	int ret, rc = -1;

	msg = gtp_msg_alloc(w->pbuff);
	if (!msg)
		return -1;

	/* IMSI */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_IMSI_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no IMSI IE present. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	imsi = bcd_to_int64(msg_ie->data, ntohs(msg_ie->h->length));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c)
		c = gtp_conn_alloc(imsi, ctx);

	/* APN */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_APN_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no Access-Point-Name IE present. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	memset(apn_str, 0, 63);
	ret = gtp_ie_apn_extract_ni((gtp_ie_apn_t *) msg_ie->h, apn_str, 63);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error parsing Access-Point-Name IE. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	apn = gtp_apn_get(apn_str);
	if (!apn) {
		log_message(LOG_INFO, "%s(): Unknown Access-Point-Name:%s. ignoring..."
				    , __FUNCTION__, apn_str);
		goto end;
	}

	/* At least F-TEID present for create session */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	teid = gtpc_msg_retransmit(ctx, msg->h, (uint8_t *) msg_ie->h);
	if (teid) {
		log_message(LOG_INFO, "Create-Session-Req:={IMSI:%ld APN:%s F-TEID:0x%.8x}%s"
				    , imsi, apn_str, ntohl(teid->id)
				    , "(retransmit)");
		goto end;
	}
	
	s = gtp_session_alloc(c, apn, gtp_router_gtpc_teid_destroy
				    , gtp_router_gtpu_teid_destroy);

	teid = gtpc_session_create(w, msg, s);
	if (!teid) {
		log_message(LOG_INFO, "%s(): Cant create session. ignoring..."
				    , __FUNCTION__);
		goto end;
	}

	log_message(LOG_INFO, "Create-Session-Req:={IMSI:%ld APN:%s F-TEID:0x%.8x}"
		    , imsi, apn_str, ntohl(teid->id));

	/* MEI */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_MEI_TYPE);
	if (msg_ie)
		s->mei = bcd_to_int64(msg_ie->data, ntohs(msg_ie->h->length));

	gtp_teid_update_sgw(teid, addr);

	/* Update last sGW visited */
	c->sgw_addr = *((struct sockaddr_in *) addr);

	/* Allocate IP Address from APN pool if configured */
	s->ipv4 = gtp_ip_pool_get(apn);

	/* Generate Charging-ID */
	s->charging_id = poor_prng(&w->seed) ^ c->sgw_addr.sin_addr.s_addr;

	gtpc_build_create_session_response(w->pbuff, s, teid);

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_PCO_TYPE);





	rc = 0;
  end:
	gtp_msg_destroy(msg);
	return rc;
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
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;

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
	gtp1_hdr_t *h = (gtp1_hdr_t *) w->pbuff->head;
	gtp1_ie_recovery_t *rec;

	/* 3GPP.TS.129.060 7.2.2 : IE Recovery is mandatory in response message */
	h->type = GTPU_ECHO_RSP_TYPE;
	h->length = htons(ntohs(h->length) + sizeof(gtp1_ie_recovery_t));
	pkt_buffer_set_end_pointer(w->pbuff, gtp1_get_header_len(h));
	pkt_buffer_set_data_pointer(w->pbuff, gtp1_get_header_len(h));

	gtp1_ie_add_tail(w->pbuff, sizeof(gtp1_ie_recovery_t));
	rec = (gtp1_ie_recovery_t *) w->pbuff->data;
	rec->type = GTP1_IE_RECOVERY_TYPE;
	rec->recovery = 0;
	pkt_buffer_put_data(w->pbuff, sizeof(gtp1_ie_recovery_t));

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
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;
	ssize_t len;

	len = gtpu_get_header_len(w->pbuff);
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
