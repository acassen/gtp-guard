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
static gtp_teid_t *
gtpc_msg_retransmit(gtp_hdr_t *h, uint8_t *ie_buffer)
{
	gtp_teid_t *teid;
	gtp_f_teid_t f_teid;

	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));
	teid = gtpc_teid_get(&f_teid);
	if (!teid)
		return NULL;

	if (h->teid_presence)
		return (h->sqn == teid->sqn) ? teid : NULL;
	if (h->sqn_only == teid->sqn)
		return teid;

	return NULL;
}

static gtp_teid_t *
gtp_teid_set(gtp_server_worker_t *w, gtp_session_t *s, gtp_teid_t *teid, uint8_t type, int direction)
{
	gtp_apn_t *apn = s->apn;
	ip_vrf_t *vrf = apn->vrf;

	if (!teid)
		return NULL;

	teid->type = type;
	__set_bit(direction ? GTP_TEID_FL_EGRESS : GTP_TEID_FL_INGRESS, &teid->flags);
	teid->session = s;
	gtp_sqn_update(w, teid);
	__set_bit(GTP_TEID_FL_RT, &teid->flags);

	/* Add to list */
	if (type == GTP_TEID_C)
		gtp_session_gtpc_teid_add(s, teid);
	else if (type == GTP_TEID_U) {
		/* If vrf forwarding is in use with PPPoE we need to
		 * delay GTP-U rules settings since part of configuration
		 * will be part of PPP negociation. Setting rules when
		 * IPCP negociation is completed */
		if (vrf && (__test_bit(IP_VRF_FL_PPPOE_BIT, &vrf->flags) ||
			    __test_bit(IP_VRF_FL_PPPOE_BUNDLE_BIT, &vrf->flags)))
			__set_bit(GTP_TEID_FL_XDP_DELAYED, &teid->flags);

		gtp_session_gtpu_teid_add(s, teid);
	}

	return teid;
}

static gtp_teid_t *
gtp_teid_create(gtp_server_worker_t *w, gtp_session_t *s, uint8_t type, int direction, 
		gtp_f_teid_t *f_teid, gtp_ie_eps_bearer_id_t *bearer_id)
{
	gtp_teid_t *teid = NULL;

	teid = (type == GTP_TEID_C) ? gtpc_teid_get(f_teid) :
				      gtpu_teid_get(f_teid);
	if (teid) {
		/* update sqn */
		gtp_sqn_update(w, teid);
		return teid;
	}

	teid = (type == GTP_TEID_C) ? gtpc_teid_alloc(f_teid, bearer_id) :
				      gtpu_teid_alloc(f_teid, bearer_id);
	return gtp_teid_set(w, s, teid, type, direction);
}

static gtp_teid_t *
gtpu_teid_add(gtp_server_worker_t *w, gtp_session_t *s, int direction, void *arg, uint8_t *ie_buffer)
{
	gtp_ie_eps_bearer_id_t *bearer_id = arg;
	gtp_f_teid_t f_teid;

	f_teid.version = 2;
	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));

	return gtp_teid_create(w, s, GTP_TEID_U, direction, &f_teid, bearer_id);
}

static gtp_teid_t *
gtpu_teid_create(gtp_server_worker_t *w, gtp_session_t *s, int direction, void *arg, uint8_t *ie_buffer)
{
	gtp_ie_eps_bearer_id_t *bearer_id = arg;
	gtp_teid_t *teid, *pteid;

	teid = gtpu_teid_add(w, s, direction, bearer_id, ie_buffer);
	pteid = gtpu_teid_alloc_peer(teid, inet_sockaddrip4(&w->srv->addr), bearer_id, &w->seed);
	gtp_teid_set(w, s, pteid, GTP_TEID_U, !direction);
	return teid;
}

static int
gtpc_teid_set_bearer(gtp_session_t *s)
{
	gtp_teid_t *teid_c, *teid_u;

	if (list_empty(&s->gtpc_teid) || list_empty(&s->gtpu_teid))
		return -1;

	/* Bearer settings. First teid in gtp-c reference first one in gtp_u.
	 * FIXME: At the time of coding, we only support one GTP-C F-TEID
	 *        which sound Ok for most use-cases.
	 *        So just keep it simple that way for now */
	teid_c = list_first_entry(&s->gtpc_teid, gtp_teid_t, next);
	teid_u = list_first_entry(&s->gtpu_teid, gtp_teid_t, next);
	teid_c->bearer_teid = teid_u;

	/* Peer setting */
	teid_c = (teid_c->peer_teid) ? teid_c->peer_teid : NULL;
	teid_u = (teid_u->peer_teid) ? teid_u->peer_teid : NULL;
	teid_c->bearer_teid = teid_u;
	return 0;
}

static gtp_teid_t *
gtpc_teid_create(gtp_server_worker_t *w, gtp_session_t *s, gtp_msg_t *msg, bool create_peer)
{
	gtp_teid_t *teid = NULL, *pteid;
	gtp_msg_ie_t *msg_ie;
	gtp_f_teid_t f_teid;
	gtp_ie_eps_bearer_id_t *bearer_id = NULL;
	uint8_t *ie_buffer, *cp_bid;

	/* GTP-C create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (msg_ie) {
		ie_buffer = (uint8_t *) msg_ie->h;
		f_teid.version = 2;
		f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
		f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));
		teid = gtp_teid_create(w, s, GTP_TEID_C, GTP_INGRESS, &f_teid, NULL);
		if (create_peer) {
			pteid = gtpc_teid_alloc_peer(teid,
						     inet_sockaddrip4(&w->srv->addr),
						     NULL, &w->seed);
			gtp_teid_set(w, s, pteid, GTP_TEID_C, GTP_EGRESS);
		}
	}

	/* GTP-U create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_BEARER_CONTEXT_TYPE);
	if (!msg_ie)
		return teid;

	cp_bid = gtp_get_ie_offset(GTP_IE_EPS_BEARER_ID_TYPE, (uint8_t *) msg_ie->data, ntohs(msg_ie->h->length), 0);
	bearer_id = (cp_bid) ? (gtp_ie_eps_bearer_id_t *) cp_bid : NULL;
	gtp_foreach_ie(GTP_IE_F_TEID_TYPE, (uint8_t *) msg_ie->data, 0
					 , (uint8_t *) msg_ie->data + ntohs(msg_ie->h->length)
					 , w, s, GTP_INGRESS
					 , bearer_id
					 , (create_peer) ? gtpu_teid_create : gtpu_teid_add);
	return teid;
}

static gtp_teid_t *
_gtpc_teid_get(uint32_t id, uint32_t ipv4)
{
	gtp_f_teid_t f_teid = { .version = 2, .teid_grekey = &id, .ipv4 = &ipv4 };

	return gtpc_teid_get(&f_teid);
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
gtpc_pkt_put_imsi(pkt_buffer_t *pbuff, uint64_t imsi)
{
	gtp_ie_imsi_t *ie;

	if (!imsi)
		return 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_IMSI_TYPE, sizeof(gtp_ie_imsi_t)) < 0)
		return 1;

	ie = (gtp_ie_imsi_t *) pbuff->data;
	int64_to_bcd_swap(imsi, ie->imsi, 8);
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_imsi_t));
	return 0;
}

static int
gtpc_pkt_put_mei(pkt_buffer_t *pbuff, uint64_t mei)
{
	gtp_ie_mei_t *ie;

	if (!mei)
		return 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_MEI_TYPE, sizeof(gtp_ie_mei_t)) < 0)
		return 1;

	ie = (gtp_ie_mei_t *) pbuff->data;
	int64_to_bcd_swap(mei, ie->mei, 8);
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_mei_t));
	return 0;
}

static int
gtpc_pkt_put_cause(pkt_buffer_t *pbuff, uint8_t cause, gtp_teid_t *teid)
{
	gtp_ie_cause_t *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_CAUSE_TYPE, sizeof(gtp_ie_cause_t)) < 0)
		return 1;

	/* a tx pkt */
	teid->session->w->cause_stats.tx[cause].count++;

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
gtpc_pkt_put_ppp_ipcp_ip4(pkt_buffer_t *pbuff, gtp_pco_pid_ipcp_t *pid, uint32_t ip4, uint8_t type)
{
	gtp_ppp_ipcp_option_ip4_t *ppp_ipcp_ip4;

	if (!ip4)
		return 0;

	if (pkt_buffer_put_zero(pbuff, sizeof(gtp_ppp_ipcp_option_ip4_t)) < 0)
		return 1;

	ppp_ipcp_ip4 = (gtp_ppp_ipcp_option_ip4_t *) pbuff->data;
	ppp_ipcp_ip4->type = type;
	ppp_ipcp_ip4->length = 6;
	ppp_ipcp_ip4->addr = ip4;
	pkt_buffer_put_data(pbuff, sizeof(gtp_ppp_ipcp_option_ip4_t));
	pid->length = htons(ntohs(pid->length) + sizeof(gtp_ppp_ipcp_option_ip4_t));
	return 0;
}

static int
gtpc_pkt_put_pco_pid_ipcp(pkt_buffer_t *pbuff, gtp_pco_t *pco, sipcp_t *ipcp, gtp_ie_pco_t *ie_pco)
{
	gtp_pco_pid_ipcp_t *pid;
	uint32_t pdns = 0, sdns = 0;
	int err = 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_IPCP, sizeof(gtp_pco_pid_ipcp_t)) < 0)
		return 1;

	pid = (gtp_pco_pid_ipcp_t *) pbuff->data;
	pid->code = PPP_CONF_NAK;
	pid->id = 0;
	pid->length = htons(sizeof(gtp_pco_pid_ipcp_t)-sizeof(gtp_pco_pid_t));
	pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_ipcp_t));

	if (ipcp) {
		pdns = ipcp->dns[0].s_addr;
		sdns = ipcp->dns[1].s_addr;
	} else {
		if (pco->ipcp_primary_ns.ss_family == AF_INET)
			pdns = inet_sockaddrip4(&pco->ipcp_primary_ns);
		if (pco->ipcp_secondary_ns.ss_family == AF_INET)
			sdns = inet_sockaddrip4(&pco->ipcp_secondary_ns);
	}
	err = err ? : gtpc_pkt_put_ppp_ipcp_ip4(pbuff, pid, pdns, PPP_IPCP_PRIMARY_NS);
	err = err ? : gtpc_pkt_put_ppp_ipcp_ip4(pbuff, pid, sdns, PPP_IPCP_SECONDARY_NS);
	if (err)
		return 1;

	pid->h.length = ntohs(pid->length); /* protocol encoding legacy stuff */
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) + sizeof(gtp_pco_pid_t) + pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco_pid_dns4(pkt_buffer_t *pbuff, uint32_t ip4, gtp_ie_pco_t *ie_pco)
{
	gtp_pco_pid_dns_t *pid;

	if (!ip4)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_DNS, sizeof(gtp_pco_pid_dns_t)) < 0)
		return 1;

	pid = (gtp_pco_pid_dns_t *) pbuff->data;
	pid->h.length = 4;
	pid->addr = ip4;
	pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_dns_t));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) + sizeof(gtp_pco_pid_t) + pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco_pid_dns(pkt_buffer_t *pbuff, gtp_pco_t *pco, sipcp_t *ipcp, gtp_ie_pco_t *ie_pco)
{
	list_head_t *l = &pco->ns;
	gtp_ns_t *ns;
	uint32_t ip4;
	int err = 0;

	if (ipcp) {
		err = err ? : gtpc_pkt_put_pco_pid_dns4(pbuff, ipcp->dns[0].s_addr, ie_pco);
		err = err ? : gtpc_pkt_put_pco_pid_dns4(pbuff, ipcp->dns[1].s_addr, ie_pco);
		return err;
	}

	list_for_each_entry(ns, l, next) {
		ip4 = (ns->addr.ss_family == AF_INET) ? inet_sockaddrip4(&ns->addr) : 0;
		if (gtpc_pkt_put_pco_pid_dns4(pbuff, ip4, ie_pco))
			return 1;
	}

	return 0;
}

static int
gtpc_pkt_put_pco_pid_mtu(pkt_buffer_t *pbuff, gtp_pco_t *pco, sipcp_t *ipcp, gtp_ie_pco_t *ie_pco)
{
	gtp_pco_pid_mtu_t *pid;

	if (!pco || !pco->link_mtu)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_MTU, sizeof(gtp_pco_pid_mtu_t)) < 0)
		return 1;

	pid = (gtp_pco_pid_mtu_t *) pbuff->data;
	pid->h.length = 2;
	pid->mtu = htons(pco->link_mtu);
	pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_mtu_t));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) + sizeof(gtp_pco_pid_t) + pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco_pid_sbcm(pkt_buffer_t *pbuff, gtp_pco_t *pco, gtp_ie_pco_t *ie_pco)
{
	gtp_pco_pid_sbcm_t *pid;

	if (!pco || !pco->selected_bearer_control_mode)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_SBCM, sizeof(gtp_pco_pid_sbcm_t)) < 0)
		return 1;

	pid = (gtp_pco_pid_sbcm_t *) pbuff->data;
	pid->h.length = 1;
	pid->sbcm = pco->selected_bearer_control_mode;
	pkt_buffer_put_data(pbuff, sizeof(gtp_pco_pid_sbcm_t));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) + sizeof(gtp_pco_pid_t) + pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco(pkt_buffer_t *pbuff, gtp_pco_t *pco, sipcp_t *ipcp)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	gtp_ie_pco_t *ie_pco;
	int err = 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_PCO_TYPE, sizeof(gtp_ie_pco_t)) < 0)
		return 1;

	ie_pco = (gtp_ie_pco_t *) pbuff->data;
	ie_pco->ext = 1 << 7; /* Extension is TRUE */
	ie_pco->h.length = htons(1);
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_pco_t));

	/* Put Protocol or Container ID */
	err = err ? : gtpc_pkt_put_pco_pid_ipcp(pbuff, pco, ipcp, ie_pco);
	err = err ? : gtpc_pkt_put_pco_pid_dns(pbuff, pco, ipcp, ie_pco);
	err = err ? : gtpc_pkt_put_pco_pid_mtu(pbuff, pco, ipcp, ie_pco);
	err = err ? : gtpc_pkt_put_pco_pid_sbcm(pbuff, pco, ie_pco);
	if (err)
		return 1;

	h->length = htons(ntohs(h->length) + ntohs(ie_pco->h.length) - 1);
	return 0;
}

static int
gtpc_pkt_put_f_teid(pkt_buffer_t *pbuff, gtp_teid_t *teid, uint8_t instance, uint8_t type)
{
	gtp_ie_f_teid_t *f_teid;
	uint16_t len = sizeof(gtp_ie_f_teid_t);

	if (!teid)
		return 1;

	len -= (teid->ipv4) ? 3*sizeof(uint32_t) : 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_F_TEID_TYPE, len) < 0)
		return 1;

	f_teid = (gtp_ie_f_teid_t *) pbuff->data;
	f_teid->h.instance = instance;
	f_teid->v4 = 1;
	f_teid->interface_type = type;
	f_teid->teid_grekey = teid->id;
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
gtpc_pkt_put_eps_bearer_id(pkt_buffer_t *pbuff, uint8_t id)
{
	gtp_ie_eps_bearer_id_t *bearer_id;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_EPS_BEARER_ID_TYPE, sizeof(gtp_ie_eps_bearer_id_t)) < 0)
		return 1;

	bearer_id = (gtp_ie_eps_bearer_id_t *) pbuff->data;
	bearer_id->id = id;
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_eps_bearer_id_t));
	return 0;
}

static int
gtpc_pkt_put_charging_id(pkt_buffer_t *pbuff, uint32_t id)
{
	gtp_ie_charging_id_t *charging_id;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_CHARGING_ID_TYPE, sizeof(gtp_ie_charging_id_t)) < 0)
		return 1;

	charging_id = (gtp_ie_charging_id_t *) pbuff->data;
	charging_id->id = htonl(id);
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_charging_id_t));
	return 0;
}

static int
gtpc_pkt_put_bearer_context(pkt_buffer_t *pbuff, gtp_session_t *s, gtp_teid_t *teid)
{
	gtp_ie_bearer_context_t *bearer_ctx;
	gtp_apn_t *apn = s->apn;
	int err = 0, len;

	if (!teid)
		return 1;
	teid = teid->bearer_teid;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_BEARER_CONTEXT_TYPE, sizeof(gtp_ie_bearer_context_t)) < 0)
		return 1;

	bearer_ctx = (gtp_ie_bearer_context_t *) pbuff->data;
	pkt_buffer_put_data(pbuff, sizeof(gtp_ie_bearer_context_t));

	err = err ? : gtpc_pkt_put_eps_bearer_id(pbuff, apn->eps_bearer_id);
	err = err ? : gtpc_pkt_put_cause(pbuff, GTP_CAUSE_REQUEST_ACCEPTED, teid);
	err = err ? : gtpc_pkt_put_f_teid(pbuff, teid, 2, GTP_TEID_INTERFACE_TYPE_SGW_GTPU);
	err = err ? : gtpc_pkt_put_charging_id(pbuff, s->charging_id);
	if (err)
		return 1;

	/* Update header length if no error */
	len = sizeof(gtp_ie_eps_bearer_id_t) +
	      sizeof(gtp_ie_cause_t) +
	      sizeof(gtp_ie_f_teid_t) +
	      sizeof(gtp_ie_charging_id_t);
	if (teid)
		len -= (teid->ipv4) ? 3*sizeof(uint32_t) : 0;
	bearer_ctx->h.length = htons(len);
	return 0;
}

static int
gtpc_build_header(pkt_buffer_t *pbuff, gtp_teid_t *teid, uint8_t type)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;

	/* a tx pkt */
	teid->session->w->msg_stats.tx[type].count++;

	h->version = 2;
	h->type = type;
	h->teid_presence = 1;
	h->length = 0;
	h->teid = (teid) ? teid->id : 0;
	h->sqn = (teid) ? teid->sqn : 0;
	pkt_buffer_set_end_pointer(pbuff, sizeof(gtp_hdr_t));
	pkt_buffer_set_data_pointer(pbuff, sizeof(gtp_hdr_t));
	return 0;
}

static int
gtpc_build_create_session_response(pkt_buffer_t *pbuff, gtp_session_t *s, gtp_teid_t *teid,
				   sipcp_t *ipcp)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	gtp_apn_t *apn = s->apn;
	int err = 0;

	/* Header update */
	gtpc_build_header(pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE);

	/* Put IE */
	err = err ? : gtpc_pkt_put_cause(pbuff, GTP_CAUSE_REQUEST_ACCEPTED, teid);
	err = err ? : gtpc_pkt_put_recovery(pbuff);
	err = err ? : gtpc_pkt_put_indication(pbuff, apn->indication_flags);
	err = err ? : gtpc_pkt_put_pco(pbuff, apn->pco, ipcp);
	err = err ? : gtpc_pkt_put_f_teid(pbuff, teid->peer_teid, 1, GTP_TEID_INTERFACE_TYPE_SGW_GTPC);
	err = err ? : gtpc_pkt_put_apn_restriction(pbuff, apn);
	err = err ? : gtpc_pkt_put_paa(pbuff, s->ipv4);
	err = err ? : gtpc_pkt_put_bearer_context(pbuff, s, teid->peer_teid);
	if (err) {
		log_message(LOG_INFO, "%s(): Error building PKT !?"
				    , __FUNCTION__);
		return -1;
	}

	/* 3GPP TS 129.274 Section 5.5.1 */
	h->length = htons(ntohs(h->length) + sizeof(gtp_hdr_t) - 4);
	return 0;
}

static int
gtpc_build_change_notification_response(pkt_buffer_t *pbuff, gtp_session_t *s, gtp_teid_t *teid)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	int err = 0;

	/* Header update */
	gtpc_build_header(pbuff, teid, GTP_CHANGE_NOTIFICATION_RESPONSE);

	/* Put IE */
	err = err ? : gtpc_pkt_put_imsi(pbuff, s->conn->imsi);
	err = err ? : gtpc_pkt_put_mei(pbuff, s->mei);
	err = err ? : gtpc_pkt_put_cause(pbuff, GTP_CAUSE_REQUEST_ACCEPTED, teid);
	if (err) {
		log_message(LOG_INFO, "%s(): Error building PKT !?"
				    , __FUNCTION__);
		return -1;
	}

	/* 3GPP TS 129.274 Section 5.5.1 */
	h->length = htons(ntohs(h->length) + sizeof(gtp_hdr_t) - 4);
	return 0;
}

static int
gtpc_build_errmsg(pkt_buffer_t *pbuff, gtp_teid_t *teid, uint8_t type, uint8_t cause)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	int err = 0;

	/* Header update */
	gtpc_build_header(pbuff, teid, type);

	/* Put IE */
	err = err ? : gtpc_pkt_put_cause(pbuff, cause, teid);
	err = err ? : gtpc_pkt_put_recovery(pbuff);
	if (err)
		return -1;

	/* 3GPP TS 129.274 Section 5.5.1 */
	h->length = htons(ntohs(h->length) + sizeof(gtp_hdr_t) - 4);
	return 0;
}

static int
gtpc_build_delete_bearer_request(pkt_buffer_t *pbuff, gtp_teid_t *teid, uint8_t cause)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	gtp_teid_t *bearer_teid = (teid) ? teid->bearer_teid : NULL;
	uint8_t bearer_id = (bearer_teid) ? bearer_teid->bearer_id : 0;
	int err = 0;

	if (!bearer_id)
		return -1;

	/* Header update */
	gtpc_build_header(pbuff, teid, GTP_DELETE_BEARER_REQUEST);

	/* Put IE */
	err = err ? : gtpc_pkt_put_eps_bearer_id(pbuff, bearer_id);
	if (cause)
		err = err ? : gtpc_pkt_put_cause(pbuff, cause, teid);
	if (err)
		return -1;

	/* 3GPP TS 129.274 Section 5.5.1 */
	h->length = htons(ntohs(h->length) + sizeof(gtp_hdr_t) - 4);
	return 0;
}

int
gtpc_send_delete_bearer_request(gtp_teid_t *teid)
{
	gtp_session_t *s = teid->session;
	gtp_server_worker_t *w = s->w;
	struct sockaddr_in addr;
	pkt_buffer_t *pbuff;
	int ret;

	pbuff = pkt_buffer_alloc(GTP_BUFFER_SIZE);
	ret = gtpc_build_delete_bearer_request(pbuff, teid, 0);
	if (ret < 0)
		return -1;

	addr = teid->sgw_addr;
	addr.sin_port = htons(GTP_C_PORT);
	pkt_buffer_send(w->fd, pbuff, (struct sockaddr_storage *) &addr);
	pkt_buffer_free(pbuff);
	return 0;
}

/*
 *	GTP-C PPP Callback
 */
void
gtpc_pppoe_tls(sppp_t *sp)
{
	spppoe_t *s = sp->s_pppoe;
	gtp_session_t *s_gtp = s->s_gtp;
	gtp_conn_t *c = s_gtp->conn;

	/* Session is starting */
	log_message(LOG_INFO, "PPPoE-Starting:={IMSI:%ld"
			      " Host-Uniq:0x%.8x"
			      " hw_src:" ETHER_FMT
			      " hw_dst:" ETHER_FMT
			      " username:%s}"
			    ,  c->imsi
			    , s->unique
			    , ETHER_BYTES(s->hw_src.ether_addr_octet)
			    , ETHER_BYTES(s->hw_dst.ether_addr_octet)
			    , s->gtp_username);
}

void
gtpc_pppoe_tlf(sppp_t *sp)
{
	spppoe_t *s = sp->s_pppoe;
	gtp_session_t *s_gtp = s->s_gtp;
	gtp_conn_t *c = s_gtp->conn;
	gtp_server_worker_t *w = s_gtp->w;
	gtp_teid_t *teid = s->teid;
	pkt_buffer_t *pbuff;

	log_message(LOG_INFO, "PPPoE-Stopping:={IMSI:%ld"
			      " Host-Uniq:0x%.8x}"
			    ,  c->imsi
			    , s->unique);

	if (__test_bit(GTP_PPPOE_FL_AUTH_FAILED, &s->flags)) {
		pbuff = pkt_buffer_alloc(GTP_BUFFER_SIZE);
		gtpc_build_errmsg(pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
					     , GTP_CAUSE_USER_AUTH_FAILED);
		pkt_buffer_send(w->fd, pbuff, &s->gtpc_peer_addr);
		pkt_buffer_free(pbuff);

		gtp_session_destroy(s->s_gtp);
		return;
	}

	/* Session has been already released */
	if (__test_bit(GTP_PPPOE_FL_DELETE_IGNORE, &s->flags))
		return;

	/* Session is released from GTP-C */
	if (__test_bit(GTP_PPPOE_FL_DELETE, &s->flags)) {
		gtp_session_destroy(s->s_gtp);
		return;
	}

	/* Session is released from remote BNG.
	 * Send delete-bearer-request */
	gtpc_send_delete_bearer_request(teid);

	/* Finally release teid and related. We are
	 * not waiting for remote response to trig deletion
	 * since remote can already have released */
	gtp_session_destroy_teid(teid);
}

void
gtpc_pppoe_create_session_response(sppp_t *sp)
{
	spppoe_t *s = sp->s_pppoe;
	gtp_session_t *s_gtp = s->s_gtp;
	gtp_conn_t *c = s_gtp->conn;
	gtp_teid_t *teid = s->teid;
	gtp_server_worker_t *w = s_gtp->w;
	pkt_buffer_t *pbuff;
	int ret;

	/* Called from PPP stack, at the end of PPP negiciation
	 * when IPCP is up and working. We are runing asyncrhonously
	 * from GTP stack workers so we need to alloc/build and
	 * send create-session-response to remote peer */

	/* Build and send response */
	pbuff = pkt_buffer_alloc(GTP_BUFFER_SIZE);

	s_gtp->ipv4 = htonl(sp->ipcp.req_myaddr);
	ret = gtpc_build_create_session_response(pbuff, s_gtp, teid, &sp->ipcp);
	if (ret < 0) {
		gtpc_build_errmsg(pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
					     , GTP_CAUSE_REQUEST_REJECTED);
		goto end;
	}

	/* Setup GTP-U Fast-Path */
	ret = gtp_session_gtpu_teid_xdp_add(s_gtp);
	if (ret < 0) {
		gtpc_build_errmsg(pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
					     , GTP_CAUSE_REQUEST_REJECTED);
	}

	log_message(LOG_INFO, "PPPoE-Started:={IMSI:%ld"
			      " Host-Uniq:0x%.8x"
			      " Circuit-ID:\"%s\""
			      " Remote-ID:\"%s\""
			      " IPv4:%u.%u.%u.%u}"
			    , c->imsi
			    , s->unique
			    , s->circuit_id
			    , s->remote_id
			    , NIPQUAD(s_gtp->ipv4));

  end:
	pkt_buffer_send(w->fd, pbuff, &s->gtpc_peer_addr);
	pkt_buffer_free(pbuff);
}

void
gtpc_pppoe_chg(sppp_t *sp, int state)
{
	/* Session is changing state */
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

	/* it does not use gtpc_build_header(), so count from here */
	w->msg_stats.tx[h->type].count++;

	return 0;
}

static int
gtpc_create_session_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_msg_t *msg;
	gtp_msg_ie_t *msg_ie;
	gtp_conn_t *c;
	gtp_session_t *s = NULL;
	spppoe_t *s_pppoe;
	gtp_pppoe_t *pppoe = NULL;
	gtp_teid_t *teid;
	gtp_id_ecgi_t *ecgi = NULL;
	gtp_ie_ambr_t *ambr = NULL;
	gtp_apn_t *apn;
	char apn_str[64];
	uint64_t imsi;
	uint8_t *ptype;
	int ret, rc = -1;
	bool retransmit = false;

	msg = gtp_msg_alloc(w->pbuff);
	if (!msg)
		return -1;

	/* At least F-TEID present for create session */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(w->pbuff, NULL, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_REQUEST_REJECTED);
		goto end;
	}

	teid = gtpc_msg_retransmit(msg->h, (uint8_t *) msg_ie->h);
	if (teid)
		retransmit = true;

	/* IMSI */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_IMSI_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no IMSI IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_REQUEST_REJECTED);
		goto end;
	}

	imsi = bcd_to_int64(msg_ie->data, ntohs(msg_ie->h->length));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c)
		c = gtp_conn_alloc(imsi);

	/* APN */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_APN_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no Access-Point-Name IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_MISSING_OR_UNKNOWN_APN);
		goto end;
	}

	memset(apn_str, 0, 63);
	ret = gtp_ie_apn_extract_ni((gtp_ie_apn_t *) msg_ie->h, apn_str, 63);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error parsing Access-Point-Name IE. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_MISSING_OR_UNKNOWN_APN);
		goto end;
	}

	apn = gtp_apn_get(apn_str);
	if (!apn) {
		log_message(LOG_INFO, "%s(): Unknown Access-Point-Name:%s. ignoring..."
				    , __FUNCTION__, apn_str);
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_MISSING_OR_UNKNOWN_APN);
		goto end;
	}

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_PDN_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no PDN-TYPE IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_REQUEST_REJECTED);
		goto end;
	}

	ptype = (uint8_t *) msg_ie->data;
	if (__test_bit(GTP_APN_FL_SESSION_UNIQ_PTYPE, &apn->flags)) {
		s = gtp_session_get_by_ptype(c, *ptype);
		if (s) {
			spppoe_disconnect(s->s_pppoe);
			s->action = GTP_ACTION_SEND_DELETE_BEARER_REQUEST;
			gtp_session_destroy(s);
			goto end;
		}
	}

	/* Session Handling */
	if (retransmit) {
		log_message(LOG_INFO, "Create-Session-Req:={IMSI:%ld APN:%s F-TEID:0x%.8x}%s"
				    , imsi, apn_str, ntohl(teid->id)
				    , " (retransmit)");
		goto end;
	}

	s = gtp_session_alloc(c, apn, gtpc_teid_unhash, gtpu_teid_unhash);
	s->ptype = *ptype;
	s->w = w;

	/* Allocate IP Address from APN pool if configured */
	s->ipv4 = gtp_ip_pool_get(apn);
	if (apn->ip_pool && !s->ipv4) {
		log_message(LOG_INFO, "%s(): APN:%s All IP Address occupied"
				    , __FUNCTION__
				    , apn_str);
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_ALL_DYNAMIC_ADDRESS_OCCUPIED);
		goto end;
	}

	teid = gtpc_teid_create(w, s, msg, true);
	if (!teid) {
		log_message(LOG_INFO, "%s(): No GTP-C F-TEID, cant create session. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_REQUEST_REJECTED);
		gtp_ip_pool_put(apn, s->ipv4);
		goto end;
	}

	log_message(LOG_INFO, "Create-Session-Req:={IMSI:%ld APN:%s F-TEID:0x%.8x}"
		    , imsi, apn_str, ntohl(teid->id));
	gtpc_teid_set_bearer(s);

	/* MEI */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_MEI_TYPE);
	if (msg_ie)
		s->mei = bcd_to_int64(msg_ie->data, ntohs(msg_ie->h->length));

	/* MSISDN */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_MSISDN_TYPE);
	if (msg_ie)
		s->msisdn = bcd_to_int64(msg_ie->data, ntohs(msg_ie->h->length));

	/* ULI */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_ULI_TYPE);
	if (msg_ie)
		ecgi = gtp_ie_uli_extract_ecgi((gtp_ie_uli_t *) msg_ie->h);

	/* AMBR */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_AMBR_TYPE);
	if (msg_ie)
		ambr = (gtp_ie_ambr_t *) msg_ie->h;

	/* Update last sGW visited */
	gtp_teid_update_sgw(teid, addr);

	/* Generate Charging-ID */
	s->charging_id = poor_prng(&w->seed) ^ c->sgw_addr.sin_addr.s_addr;

	/* IP VRF is in use and PPPoE session forwarding is configured */
	if (apn->vrf && (__test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags) ||
			 __test_bit(IP_VRF_FL_PPPOE_BUNDLE_BIT, &apn->vrf->flags))) {
		if (__test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags))
			pppoe = apn->vrf->pppoe;
		else
			pppoe = gtp_pppoe_bundle_get_active_instance(apn->vrf->pppoe_bundle);

		if (!pppoe) {
			log_message(LOG_INFO, "No active PPPoE Instance available to handle request");
			rc = gtpc_build_errmsg(w->pbuff, teid
						       , GTP_CREATE_SESSION_RESPONSE_TYPE
						       , GTP_CAUSE_REQUEST_REJECTED);
			goto end;
		}

		s_pppoe = spppoe_init(pppoe, c,
				      gtpc_pppoe_tls, gtpc_pppoe_tlf,
				      gtpc_pppoe_create_session_response, gtpc_pppoe_chg,
				      imsi, s->mei, apn_str, ecgi, ambr);
		if (!s_pppoe) {
			rc = gtpc_build_errmsg(w->pbuff, teid
						       , GTP_CREATE_SESSION_RESPONSE_TYPE
						       , GTP_CAUSE_REQUEST_REJECTED);
			goto end;
		}
		s_pppoe->s_gtp = s;
		s_pppoe->teid = teid;
		s_pppoe->gtpc_peer_addr = *addr;
		s->s_pppoe = s_pppoe;
		rc = GTP_ROUTER_DELAYED;
		goto end;
	}

	rc = gtpc_build_create_session_response(w->pbuff, s, teid, NULL);
  end:
	gtp_msg_destroy(msg);
	return rc;
}

static int
gtpc_delete_session_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_teid_t *teid, *pteid;
	gtp_msg_t *msg;
	gtp_msg_ie_t *msg_ie;
	uint32_t id, ipv4;
	uint8_t *ie_buffer;
	int rc = -1;

	msg = gtp_msg_alloc(w->pbuff);
	if (!msg)
		return -1;

	teid = _gtpc_teid_get(h->teid, inet_sockaddrip4(&srv->addr));
	if (!teid) {
		rc = gtpc_build_errmsg(w->pbuff, NULL, GTP_DELETE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_CONTEXT_NOT_FOUND);
		goto end;
	}

	log_message(LOG_INFO, "Delete-Session-Req:={F-TEID:0x%.8x}", ntohl(teid->peer_teid->id));

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(w->pbuff, NULL, GTP_CREATE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_INVALID_PEER);
		goto end;
	}

	ie_buffer = (uint8_t *) msg_ie->h;
	id = *(uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, teid_grekey));
	ipv4 = *(uint32_t *) (ie_buffer + offsetof(gtp_ie_f_teid_t, ipv4));
	pteid = _gtpc_teid_get(id, ipv4);
	if (!pteid) {
		rc = gtpc_build_errmsg(w->pbuff, teid, GTP_DELETE_SESSION_RESPONSE_TYPE
						     , GTP_CAUSE_INVALID_PEER);
		goto end;
	}

	if (teid->peer_teid && pteid != teid->peer_teid) {
		/* Information */
		log_message(LOG_INFO, "%s(): F-TEID 0x%.8x not binded F-TEID 0x%.8x"
				    , __FUNCTION__
				    , ntohl(pteid->id)
				    , ntohl(teid->peer_teid->id));
	}

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_sqn_update(w, pteid);

	rc = gtpc_build_errmsg(w->pbuff, pteid
				       , GTP_DELETE_SESSION_RESPONSE_TYPE
				       , GTP_CAUSE_REQUEST_ACCEPTED);

	gtp_teid_put(teid);
	gtp_teid_put(pteid);
	if (teid->session && teid->session->s_pppoe)
		spppoe_close(teid->session->s_pppoe);
	else
		gtp_session_destroy(teid->session);
  end:
	gtp_msg_destroy(msg);
	return rc;
}

static int
gtpc_modify_bearer_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_teid_t *teid, *pteid = NULL, *t, *t_u;
	gtp_session_t *s;
	ip_vrf_t *vrf;
	gtp_msg_t *msg;
	int rc = -1;

	msg = gtp_msg_alloc(w->pbuff);
	if (!msg)
		return -1;

	teid = _gtpc_teid_get(h->teid, inet_sockaddrip4(&srv->addr));
	if (!teid) {
		log_message(LOG_INFO, "%s(): Unknown TEID 0x%.8x..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		rc = gtpc_build_errmsg(w->pbuff, NULL, GTP_MODIFY_BEARER_RESPONSE_TYPE
						     , GTP_CAUSE_CONTEXT_NOT_FOUND);
		goto end;
	}

	/* Update sGW */
	gtp_teid_update_sgw(teid, addr);
	gtp_teid_update_sgw(teid->peer_teid, addr);
	s = teid->session;

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_sqn_update(w, teid->peer_teid);

	/* Create TEID */
	t = gtpc_teid_create(w, s, msg, false);
	if (!t)
		goto accept;

	/* GTP-C Update */
	pteid = teid->peer_teid;
	t->old_teid = pteid;
	gtp_teid_bind(teid, t);
	gtp_session_gtpc_teid_destroy(t->old_teid);

	/* GTP-U Update */
	t_u = gtp_session_gtpu_teid_get_by_sqn(s, t->sqn);
	if (t_u) {
		t->bearer_teid = t_u;
		t_u->old_teid = (pteid) ? pteid->bearer_teid : NULL;
		gtp_teid_bind(teid->bearer_teid, t_u);
		gtp_session_gtpu_teid_destroy(t_u->old_teid);
	}

	/* Add delayed XDP entries */
	vrf = (s->apn) ? s->apn->vrf : NULL;
	if (vrf && __test_bit(IP_VRF_FL_PPPOE_BIT, &vrf->flags))
		gtp_session_gtpu_teid_xdp_add(s);

  accept:
	rc = gtpc_build_errmsg(w->pbuff, teid->peer_teid, GTP_MODIFY_BEARER_RESPONSE_TYPE
							, GTP_CAUSE_REQUEST_ACCEPTED);
  end:
	gtp_msg_destroy(msg);
	return rc;
}

static int
gtpc_change_notification_request_hdl(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) w->pbuff->head;
	gtp_server_t *srv = w->srv;
	gtp_teid_t *teid;
	gtp_msg_t *msg;
	int rc = -1;

	msg = gtp_msg_alloc(w->pbuff);
	if (!msg)
		return -1;

	teid = _gtpc_teid_get(h->teid, inet_sockaddrip4(&srv->addr));
	if (!teid) {
		log_message(LOG_INFO, "%s(): Unknown TEID 0x%.8x..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		rc = gtpc_build_errmsg(w->pbuff, NULL, GTP_CHANGE_NOTIFICATION_RESPONSE
						     , GTP_CAUSE_IMSI_IMEI_NOT_KNOWN);
		goto end;
	}

	/* Update SQN */
	gtp_sqn_update(w, teid);
	gtp_sqn_update(w, teid->peer_teid);

	rc = gtpc_build_change_notification_response(w->pbuff, teid->session, teid->peer_teid);
  end:
	gtp_msg_destroy(msg);
	return rc;
}


/*
 *	GTP-C Message handle
 */
static const struct {
	int (*hdl) (gtp_server_worker_t *, struct sockaddr_storage *);
} gtpc_msg_hdl[0xff + 1] = {
	[GTP_ECHO_REQUEST_TYPE]			= { gtpc_echo_request_hdl },
	[GTP_CREATE_SESSION_REQUEST_TYPE]	= { gtpc_create_session_request_hdl },
	[GTP_DELETE_SESSION_REQUEST_TYPE]	= { gtpc_delete_session_request_hdl },
	[GTP_MODIFY_BEARER_REQUEST_TYPE]	= { gtpc_modify_bearer_request_hdl },
	[GTP_CHANGE_NOTIFICATION_REQUEST]	= { gtpc_change_notification_request_hdl },
	[GTP_MODIFY_BEARER_COMMAND]		= { NULL },
	[GTP_DELETE_BEARER_COMMAND]		= { NULL },
	[GTP_BEARER_RESSOURCE_COMMAND]		= { NULL },
	[GTP_UPDATE_BEARER_REQUEST]		= { NULL },
	[GTP_UPDATE_BEARER_RESPONSE]		= { NULL },
};

int
gtpc_router_handle(gtp_server_worker_t *w, struct sockaddr_storage *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) w->pbuff->head;

	if (*(gtpc_msg_hdl[gtph->type].hdl)) {
		w->msg_stats.rx[gtph->type].count++;
		return (*(gtpc_msg_hdl[gtph->type].hdl)) (w, addr);
	}

	/* In router mode, silently ignore message we do not support */
	w->msg_stats.rx[gtph->type].unsupported++;
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

	w->msg_stats.tx[h->type].count++;

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
} gtpu_msg_hdl[0xff + 1] = {
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

	if (*(gtpu_msg_hdl[gtph->type].hdl)) {
		w->msg_stats.rx[gtph->type].count++;
		return (*(gtpu_msg_hdl[gtph->type].hdl)) (w, addr);
	}

	/* Not supported */
	log_message(LOG_INFO, "%s(): GTP-U/path-mgt msg_type:0x%.2x from %s not supported..."
			    , __FUNCTION__
			    , gtph->type
			    , inet_sockaddrtos(addr));
	w->msg_stats.rx[gtph->type].unsupported++;
	return -1;
}
