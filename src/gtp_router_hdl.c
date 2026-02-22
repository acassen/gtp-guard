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
#include "gtp_router.h"
#include "gtp_server.h"
#include "gtp_sqn.h"
#include "gtp_utils.h"
#include "gtp_utils_uli.h"
#include "gtp_proxy_hdl.h"
#include "gtp.h"
#include "ppp_session.h"
#include "bitops.h"
#include "inet_utils.h"
#include "logger.h"
#include "utils.h"


/* Extern data */
extern struct data *daemon_data;

/* Local data */
extern struct gtp_teid dummy_teid;


/*
 *	Utilities
 */
static struct gtp_teid *
gtpc_msg_retransmit(struct gtp_hdr *h, uint8_t *ie_buffer)
{
	struct gtp_teid *teid;
	struct gtp_f_teid f_teid;

	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, ipv4));
	teid = gtpc_teid_get(&f_teid);
	if (!teid)
		return NULL;

	if (h->teid_presence)
		return (h->sqn == teid->sqn) ? teid : NULL;
	if (h->sqn_only == teid->sqn)
		return teid;

	return NULL;
}

static struct gtp_teid *
gtp_teid_set(struct gtp_server *srv, struct gtp_session *s, struct gtp_teid *teid, uint8_t type, int direction)
{
	struct gtp_apn *apn = s->apn;
	struct ip_vrf *vrf = apn->vrf;

	if (!teid)
		return NULL;

	teid->type = type;
	__set_bit(direction ? GTP_TEID_FL_EGRESS : GTP_TEID_FL_INGRESS, &teid->flags);
	teid->session = s;
	gtp_sqn_update(srv, teid);
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

static struct gtp_teid *
gtp_teid_create(struct gtp_server *srv, struct gtp_session *s, uint8_t type, int direction,
		struct gtp_f_teid *f_teid, struct gtp_ie_eps_bearer_id *bearer_id)
{
	struct gtp_teid *teid = NULL;

	teid = (type == GTP_TEID_C) ? gtpc_teid_get(f_teid) :
				      gtpu_teid_get(f_teid);
	if (teid) {
		/* update sqn */
		gtp_sqn_update(srv, teid);
		return teid;
	}

	teid = (type == GTP_TEID_C) ? gtpc_teid_alloc(f_teid, bearer_id) :
				      gtpu_teid_alloc(f_teid, bearer_id);
	return gtp_teid_set(srv, s, teid, type, direction);
}

static struct gtp_teid *
gtpu_teid_add(struct gtp_server *srv, struct gtp_session *s, int direction, void *arg, uint8_t *ie_buffer)
{
	struct gtp_ie_eps_bearer_id *bearer_id = arg;
	struct gtp_f_teid f_teid;

	f_teid.version = 2;
	f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, teid_grekey));
	f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, ipv4));

	return gtp_teid_create(srv, s, GTP_TEID_U, direction, &f_teid, bearer_id);
}

static struct gtp_teid *
gtpu_teid_create(struct gtp_server *srv, struct gtp_session *s, int direction, void *arg, uint8_t *ie_buffer)
{
	struct gtp_ie_eps_bearer_id *bearer_id = arg;
	struct gtp_teid *teid, *pteid;

	teid = gtpu_teid_add(srv, s, direction, bearer_id, ie_buffer);
	pteid = gtpu_teid_alloc_peer(teid, inet_sockaddrip4(&srv->s.addr), bearer_id, &srv->s.seed);
	gtp_teid_set(srv, s, pteid, GTP_TEID_U, !direction);
	return teid;
}

static int
gtpc_teid_set_bearer(struct gtp_session *s)
{
	struct gtp_teid *teid_c, *teid_u;

	if (list_empty(&s->gtpc_teid) || list_empty(&s->gtpu_teid))
		return -1;

	/* Bearer settings. First teid in gtp-c reference first one in gtp_u.
	 * FIXME: At the time of coding, we only support one GTP-C F-TEID
	 *        which sound Ok for most use-cases.
	 *        So just keep it simple that way for now */
	teid_c = list_first_entry(&s->gtpc_teid, struct gtp_teid, next);
	teid_u = list_first_entry(&s->gtpu_teid, struct gtp_teid, next);
	teid_c->bearer_teid = teid_u;

	/* Peer setting */
	teid_c = (teid_c->peer_teid) ? teid_c->peer_teid : NULL;
	teid_u = (teid_u->peer_teid) ? teid_u->peer_teid : NULL;
	teid_c->bearer_teid = teid_u;
	return 0;
}

static struct gtp_teid *
gtpc_teid_create(struct gtp_server *srv, struct gtp_session *s, struct gtp_msg *msg, bool create_peer)
{
	struct gtp_teid *teid = NULL, *pteid;
	struct gtp_msg_ie *msg_ie;
	struct gtp_f_teid f_teid;
	struct gtp_ie_eps_bearer_id *bearer_id = NULL;
	uint8_t *ie_buffer, *cp_bid;

	/* GTP-C create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (msg_ie) {
		ie_buffer = (uint8_t *) msg_ie->h;
		f_teid.version = 2;
		f_teid.teid_grekey = (uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, teid_grekey));
		f_teid.ipv4 = (uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, ipv4));
		teid = gtp_teid_create(srv, s, GTP_TEID_C, GTP_INGRESS, &f_teid, NULL);
		if (create_peer) {
			pteid = gtpc_teid_alloc_peer(teid,
						     inet_sockaddrip4(&srv->s.addr),
						     NULL, &srv->s.seed);
			gtp_teid_set(srv, s, pteid, GTP_TEID_C, GTP_EGRESS);
		}
	}

	/* GTP-U create */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_BEARER_CONTEXT_TYPE);
	if (!msg_ie)
		return teid;

	cp_bid = gtp_get_ie_offset(GTP_IE_EPS_BEARER_ID_TYPE, (uint8_t *) msg_ie->data, ntohs(msg_ie->h->length), 0);
	bearer_id = (cp_bid) ? (struct gtp_ie_eps_bearer_id *) cp_bid : NULL;
	gtp_foreach_ie(GTP_IE_F_TEID_TYPE, (uint8_t *) msg_ie->data, 0
					 , (uint8_t *) msg_ie->data + ntohs(msg_ie->h->length)
					 , srv, s, GTP_INGRESS
					 , bearer_id
					 , (create_peer) ? gtpu_teid_create : gtpu_teid_add);
	return teid;
}

static struct gtp_teid *
_gtpc_teid_get(uint32_t id, uint32_t ipv4)
{
	struct gtp_f_teid f_teid = { .version = 2, .teid_grekey = &id, .ipv4 = &ipv4 };

	return gtpc_teid_get(&f_teid);
}


/*
 *	Packet factory
 */
static int
gtpc_pkt_put_ie(struct pkt_buffer *pbuff, uint8_t type, uint16_t length)
{
	struct gtp_hdr *h = (struct gtp_hdr *) pbuff->head;
	struct gtp_ie *ie;

	if (pkt_buffer_put_zero(pbuff, length) < 0)
		return 1;

	ie = (struct gtp_ie *) pbuff->data;
	ie->type = type;
	ie->length = htons(length - sizeof(*ie));
	h->length = htons(ntohs(h->length) + length);
	return 0;
}

static int
gtpc_pkt_put_pid(struct pkt_buffer *pbuff,  uint16_t type, uint8_t length)
{
	struct gtp_pco_pid *pid;

	if (pkt_buffer_put_zero(pbuff, length) < 0)
		return 1;

	pid = (struct gtp_pco_pid *) pbuff->data;
	pid->type = htons(type);
	return 0;
}

static int
gtpc_pkt_put_imsi(struct pkt_buffer *pbuff, uint64_t imsi)
{
	struct gtp_ie_imsi *ie;

	if (!imsi)
		return 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_IMSI_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_imsi *) pbuff->data;
	int64_to_bcd_swap(imsi, ie->imsi, 8);
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_mei(struct pkt_buffer *pbuff, uint64_t mei)
{
	struct gtp_ie_mei *ie;

	if (!mei)
		return 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_MEI_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_mei *) pbuff->data;
	int64_to_bcd_swap(mei, ie->mei, 8);
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_cause(struct pkt_buffer *pbuff, uint8_t cause)
{
	struct gtp_ie_cause *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_CAUSE_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_cause *) pbuff->data;
	ie->value = cause;
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_recovery(struct pkt_buffer *pbuff)
{
	struct gtp_ie_recovery *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_RECOVERY_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_recovery *) pbuff->data;
	ie->recovery = daemon_data->restart_counter;
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_indication(struct pkt_buffer *pbuff, uint32_t bits)
{
	struct gtp_ie_indication *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_INDICATION_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_indication *) pbuff->data;
	ie->bits = htonl(bits);
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_ppp_ipcp_ip4(struct pkt_buffer *pbuff, struct gtp_pco_pid_ipcp *pid,
			  uint32_t ip4, uint8_t type)
{
	struct gtp_ppp_ipcp_option_ip4 *ppp_ipcp_ip4;

	if (!ip4)
		return 0;

	if (pkt_buffer_put_zero(pbuff, sizeof(*ppp_ipcp_ip4)) < 0)
		return 1;

	ppp_ipcp_ip4 = (struct gtp_ppp_ipcp_option_ip4 *) pbuff->data;
	ppp_ipcp_ip4->type = type;
	ppp_ipcp_ip4->length = 6;
	ppp_ipcp_ip4->addr = ip4;
	pkt_buffer_put_data(pbuff, sizeof(*ppp_ipcp_ip4));
	pid->length = htons(ntohs(pid->length) + sizeof(*ppp_ipcp_ip4));
	return 0;
}

static int
gtpc_pkt_put_pco_pid_ipcp(struct pkt_buffer *pbuff, struct gtp_pco *pco,
			  struct sipcp *ipcp, struct gtp_ie_pco *ie_pco)
{
	struct gtp_pco_pid_ipcp *pid;
	uint32_t pdns = 0, sdns = 0;
	int err = 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_IPCP, sizeof(*pid)) < 0)
		return 1;

	pid = (struct gtp_pco_pid_ipcp *) pbuff->data;
	pid->code = PPP_CONF_NAK;
	pid->id = 0;
	pid->length = htons(sizeof(*pid) - sizeof(struct gtp_pco_pid));
	pkt_buffer_put_data(pbuff, sizeof(*pid));

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
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) +
			  	 sizeof(struct gtp_pco_pid) +
			  	 pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco_pid_dns4(struct pkt_buffer *pbuff, uint32_t ip4,
			  struct gtp_ie_pco *ie_pco)
{
	struct gtp_pco_pid_dns *pid;

	if (!ip4)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_DNS, sizeof(*pid)) < 0)
		return 1;

	pid = (struct gtp_pco_pid_dns *) pbuff->data;
	pid->h.length = 4;
	pid->addr = ip4;
	pkt_buffer_put_data(pbuff, sizeof(*pid));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) +
				 sizeof(struct gtp_pco_pid) +
			  	 pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco_pid_dns(struct pkt_buffer *pbuff, struct gtp_pco *pco,
			 struct sipcp *ipcp, struct gtp_ie_pco *ie_pco)
{
	struct list_head *l = &pco->ns;
	struct gtp_ns *ns;
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
gtpc_pkt_put_pco_pid_mtu(struct pkt_buffer *pbuff, struct gtp_pco *pco,
			 struct sipcp *ipcp, struct gtp_ie_pco *ie_pco)
{
	struct gtp_pco_pid_mtu *pid;

	if (!pco || !pco->link_mtu)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_MTU, sizeof(*pid)) < 0)
		return 1;

	pid = (struct gtp_pco_pid_mtu *) pbuff->data;
	pid->h.length = 2;
	pid->mtu = htons(pco->link_mtu);
	pkt_buffer_put_data(pbuff, sizeof(*pid));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) +
				 sizeof(struct gtp_pco_pid) +
				 pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco_pid_sbcm(struct pkt_buffer *pbuff, struct gtp_pco *pco,
			  struct gtp_ie_pco *ie_pco)
{
	struct gtp_pco_pid_sbcm *pid;

	if (!pco || !pco->selected_bearer_control_mode)
		return 0;

	if (gtpc_pkt_put_pid(pbuff, GTP_PCO_PID_SBCM, sizeof(*pid)) < 0)
		return 1;

	pid = (struct gtp_pco_pid_sbcm *) pbuff->data;
	pid->h.length = 1;
	pid->sbcm = pco->selected_bearer_control_mode;
	pkt_buffer_put_data(pbuff, sizeof(*pid));
	ie_pco->h.length = htons(ntohs(ie_pco->h.length) +
				 sizeof(struct gtp_pco_pid) +
				 pid->h.length);
	return 0;
}

static int
gtpc_pkt_put_pco(struct pkt_buffer *pbuff, struct gtp_pco *pco, struct sipcp *ipcp)
{
	struct gtp_hdr *h = (struct gtp_hdr *) pbuff->head;
	struct gtp_ie_pco *ie;
	int err = 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_PCO_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_pco *) pbuff->data;
	ie->ext = 1 << 7; /* Extension is TRUE */
	ie->h.length = htons(1);
	pkt_buffer_put_data(pbuff, sizeof(*ie));

	/* Put Protocol or Container ID */
	err = err ? : gtpc_pkt_put_pco_pid_ipcp(pbuff, pco, ipcp, ie);
	err = err ? : gtpc_pkt_put_pco_pid_dns(pbuff, pco, ipcp, ie);
	err = err ? : gtpc_pkt_put_pco_pid_mtu(pbuff, pco, ipcp, ie);
	err = err ? : gtpc_pkt_put_pco_pid_sbcm(pbuff, pco, ie);
	if (err)
		return 1;

	h->length = htons(ntohs(h->length) + ntohs(ie->h.length) - 1);
	return 0;
}

static int
gtpc_pkt_put_f_teid(struct pkt_buffer *pbuff, struct gtp_teid *teid,
		    uint8_t instance, uint8_t type)
{
	struct gtp_ie_f_teid *ie;
	uint16_t len = sizeof(*ie);

	if (!teid)
		return 1;

	len -= (teid->ipv4) ? 3*sizeof(uint32_t) : 0;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_F_TEID_TYPE, len) < 0)
		return 1;

	ie = (struct gtp_ie_f_teid *) pbuff->data;
	ie->h.instance = instance;
	ie->v4 = 1;
	ie->interface_type = type;
	ie->teid_grekey = teid->id;
	ie->ipv4 = teid->ipv4;
	pkt_buffer_put_data(pbuff, len);
	return 0;
}

static int
gtpc_pkt_put_apn_restriction(struct pkt_buffer *pbuff, struct gtp_apn *apn)
{
	struct gtp_ie_apn_restriction *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_APN_RESTRICTION_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_apn_restriction *) pbuff->data;
	ie->value = apn->restriction;
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_paa(struct pkt_buffer *pbuff, uint32_t addr)
{
	struct gtp_ie_paa *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_PAA_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_paa *) pbuff->data;
	ie->type = GTP_PAA_IPV4_TYPE;
	ie->addr = addr;
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_eps_bearer_id(struct pkt_buffer *pbuff, uint8_t id)
{
	struct gtp_ie_eps_bearer_id *ie;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_EPS_BEARER_ID_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_eps_bearer_id *) pbuff->data;
	ie->id = id;
	pkt_buffer_put_data(pbuff, sizeof(*ie));
	return 0;
}

static int
gtpc_pkt_put_charging_id(struct pkt_buffer *pbuff, uint32_t id)
{
	struct gtp_ie_charging_id *charging_id;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_CHARGING_ID_TYPE, sizeof(*charging_id)) < 0)
		return 1;

	charging_id = (struct gtp_ie_charging_id *) pbuff->data;
	charging_id->id = htonl(id);
	pkt_buffer_put_data(pbuff, sizeof(*charging_id));
	return 0;
}

static int
gtpc_pkt_put_bearer_context(struct pkt_buffer *pbuff, struct gtp_session *s, struct gtp_teid *teid)
{
	struct gtp_ie_bearer_context *ie;
	struct gtp_apn *apn = s->apn;
	int err = 0, len;

	if (!teid || !teid->bearer_teid)
		return 1;
	teid = teid->bearer_teid;

	if (gtpc_pkt_put_ie(pbuff, GTP_IE_BEARER_CONTEXT_TYPE, sizeof(*ie)) < 0)
		return 1;

	ie = (struct gtp_ie_bearer_context *) pbuff->data;
	pkt_buffer_put_data(pbuff, sizeof(*ie));

	err = err ? : gtpc_pkt_put_eps_bearer_id(pbuff, (apn->eps_bearer_id) ? : teid->bearer_id);
	err = err ? : gtpc_pkt_put_cause(pbuff, GTP_CAUSE_REQUEST_ACCEPTED);
	err = err ? : gtpc_pkt_put_f_teid(pbuff, teid, 2, GTP_TEID_INTERFACE_TYPE_SGW_GTPU);
	err = err ? : gtpc_pkt_put_charging_id(pbuff, s->charging_id);
	if (err)
		return 1;

	/* Update header length if no error */
	len = sizeof(struct gtp_ie_eps_bearer_id) +
	      sizeof(struct gtp_ie_cause) +
	      sizeof(struct gtp_ie_f_teid) +
	      sizeof(struct gtp_ie_charging_id);
	if (teid)
		len -= (teid->ipv4) ? 3 * sizeof(uint32_t) : 0;
	ie->h.length = htons(len);
	return 0;
}

static int
gtpc_build_header(struct pkt_buffer *pbuff, struct gtp_teid *teid, uint8_t type)
{
	struct gtp_hdr *h = (struct gtp_hdr *) pbuff->head;

	h->version = 2;
	h->type = type;
	h->teid_presence = 1;
	h->length = 0;
	h->teid = (teid) ? teid->id : 0;
	h->sqn = (teid) ? teid->sqn : 0;
	pkt_buffer_set_end_pointer(pbuff, sizeof(*h));
	pkt_buffer_set_data_pointer(pbuff, sizeof(*h));
	return 0;
}

static int
gtpc_build_create_session_response(struct pkt_buffer *pbuff, struct gtp_session *s,
				   struct gtp_teid *teid, struct sipcp *ipcp)
{
	struct gtp_hdr *h = (struct gtp_hdr *) pbuff->head;
	struct gtp_apn *apn = s->apn;
	int err = 0;

	/* Header update */
	gtpc_build_header(pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE);

	/* Put IE */
	err = err ? : gtpc_pkt_put_cause(pbuff, GTP_CAUSE_REQUEST_ACCEPTED);
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
	h->length = htons(ntohs(h->length) + sizeof(*h) - 4);

	/* CDR Update */
	gtp_cdr_update(pbuff, NULL, s->cdr);
	return 0;
}

static int
gtpc_build_change_notification_response(struct pkt_buffer *pbuff, struct gtp_session *s,
					struct gtp_teid *teid)
{
	struct gtp_hdr *h = (struct gtp_hdr *) pbuff->head;
	int err = 0;

	/* Header update */
	gtpc_build_header(pbuff, teid, GTP_CHANGE_NOTIFICATION_RESPONSE);

	/* Put IE */
	err = err ? : gtpc_pkt_put_imsi(pbuff, s->conn->imsi);
	err = err ? : gtpc_pkt_put_mei(pbuff, s->mei);
	err = err ? : gtpc_pkt_put_cause(pbuff, GTP_CAUSE_REQUEST_ACCEPTED);
	if (err) {
		log_message(LOG_INFO, "%s(): Error building PKT !?"
				    , __FUNCTION__);
		return -1;
	}

	/* 3GPP TS 129.274 Section 5.5.1 */
	h->length = htons(ntohs(h->length) + sizeof(*h) - 4);
	return 0;
}

static int
gtpc_build_errmsg(struct pkt_buffer *pbuff, struct gtp_teid *teid,
		  uint8_t type, uint8_t cause)
{
	struct gtp_hdr *h = (struct gtp_hdr *) pbuff->head;
	int err = 0;

	/* Header update */
	gtpc_build_header(pbuff, teid, type);

	/* Put IE */
	err = err ? : gtpc_pkt_put_cause(pbuff, cause);
	err = err ? : gtpc_pkt_put_recovery(pbuff);
	if (err)
		return -1;

	/* 3GPP TS 129.274 Section 5.5.1 */
	h->length = htons(ntohs(h->length) + sizeof(*h) - 4);

	/* CDR Update */
	if (teid)
		gtp_cdr_update(pbuff, NULL, teid->session->cdr);
	return 0;
}

static int
gtpc_build_delete_bearer_request(struct pkt_buffer *pbuff, struct gtp_teid *teid,
				 uint8_t cause)
{
	struct gtp_hdr *h = (struct gtp_hdr *) pbuff->head;
	struct gtp_teid *bearer_teid = (teid) ? teid->bearer_teid : NULL;
	uint8_t bearer_id = (bearer_teid) ? bearer_teid->bearer_id : 0;
	int err = 0;

	if (!bearer_id)
		return -1;

	/* Header update */
	gtpc_build_header(pbuff, teid, GTP_DELETE_BEARER_REQUEST);

	/* Put IE */
	err = err ? : gtpc_pkt_put_eps_bearer_id(pbuff, bearer_id);
	if (cause)
		err = err ? : gtpc_pkt_put_cause(pbuff, cause);
	if (err)
		return -1;

	/* 3GPP TS 129.274 Section 5.5.1 */
	h->length = htons(ntohs(h->length) + sizeof(*h) - 4);
	return 0;
}

int
gtpc_send_delete_bearer_request(struct gtp_teid *teid)
{
	struct gtp_session *s = teid->session;
	struct gtp_server *srv = s->srv;
	struct sockaddr_in addr;
	struct pkt_buffer *pbuff;
	int ret;

	pbuff = pkt_buffer_alloc(GTP_BUFFER_SIZE);
	ret = gtpc_build_delete_bearer_request(pbuff, teid, 0);
	if (ret < 0)
		return -1;

	addr = teid->sgw_addr;
	addr.sin_port = htons(GTP_C_PORT);
	inet_server_snd(&srv->s, srv->s.fd, pbuff, (struct sockaddr_in*) &addr);
	pkt_buffer_free(pbuff);
	return 0;
}

/*
 *	GTP-C PPP Callback
 */
void
gtpc_pppoe_tls(struct sppp *sp)
{
	struct spppoe *s = sp->s_pppoe;
	struct gtp_session *s_gtp = s->s_gtp;
	struct gtp_conn *c = s_gtp->conn;

	/* Session is starting */
	log_message(LOG_INFO, "PPPoE-Starting:={IMSI:%ld"
			      " Host-Uniq:0x%.8x"
			      " hw_src:" ETHER_FMT
			      " hw_dst:" ETHER_FMT
			      " username:%s}"
			    , c->imsi
			    , s->unique
			    , ETHER_BYTES(s->hw_src.ether_addr_octet)
			    , ETHER_BYTES(s->hw_dst.ether_addr_octet)
			    , s->gtp_username);
}

void
gtpc_pppoe_tlf(struct sppp *sp)
{
	struct spppoe *s = sp->s_pppoe;
	struct gtp_session *s_gtp = s->s_gtp;
	struct gtp_conn *c = s_gtp->conn;
	struct gtp_server *srv = s_gtp->srv;
	struct gtp_teid *teid = s->teid;
	struct pkt_buffer *pbuff;

	log_message(LOG_INFO, "PPPoE-Stopping:={IMSI:%ld"
			      " Host-Uniq:0x%.8x}"
			    ,  c->imsi
			    , s->unique);

	if (__test_bit(GTP_PPPOE_FL_AUTH_FAILED, &s->flags)) {
		pbuff = pkt_buffer_alloc(GTP_BUFFER_SIZE);
		gtpc_build_errmsg(pbuff, teid, GTP_CREATE_SESSION_RESPONSE_TYPE
					     , GTP_CAUSE_USER_AUTH_FAILED);
		inet_server_snd(&srv->s, srv->s.fd, pbuff,
				(struct sockaddr_in *) &s->gtpc_peer_addr);

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
gtpc_pppoe_create_session_response(struct sppp *sp)
{
	struct spppoe *s = sp->s_pppoe;
	struct gtp_session *s_gtp = s->s_gtp;
	struct gtp_conn *c = s_gtp->conn;
	struct gtp_teid *teid = s->teid;
	struct gtp_server *srv = s_gtp->srv;
	struct pkt_buffer *pbuff;
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
	inet_server_snd(&srv->s, srv->s.fd, pbuff,
			(struct sockaddr_in *) &s->gtpc_peer_addr);
	pkt_buffer_free(pbuff);
}

void
gtpc_pppoe_chg(struct sppp *sp, int state)
{
	/* Session is changing state */
}


/*
 *	GTP-C Protocol helpers
 */
static int
gtpc_echo_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *h = (struct gtp_hdr *) srv->s.pbuff->head;
	struct gtp_ie_recovery *rec;
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_RECOVERY_TYPE, srv->s.pbuff);
	if (cp) {
		rec = (struct gtp_ie_recovery *) cp;
		rec->recovery = daemon_data->restart_counter;
	}

	h->type = GTP_ECHO_RESPONSE_TYPE;
	return 0;
}

static int
gtpc_create_session_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_msg *msg;
	struct gtp_msg_ie *msg_ie;
	struct gtp_conn *c;
	struct gtp_session *s = NULL;
	struct spppoe *s_pppoe;
	struct pppoe *pppoe = NULL;
	struct gtp_teid *teid;
	struct gtp_id_ecgi *ecgi = NULL;
	struct gtp_ie_ambr *ambr = NULL;
	struct gtp_apn *apn;
	char apn_str[64];
	uint64_t imsi;
	uint8_t *ptype;
	int ret, rc = -1;
	bool retransmit = false;

	msg = gtp_msg_alloc(srv->s.pbuff);
	if (!msg)
		return -1;

	/* At least F-TEID present for create session */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(srv->s.pbuff, NULL
						 , GTP_CREATE_SESSION_RESPONSE_TYPE
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
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						 , GTP_CREATE_SESSION_RESPONSE_TYPE
						 , GTP_CAUSE_REQUEST_REJECTED);
		goto end;
	}

	imsi = bcd_to_int64(msg_ie->data, ntohs(msg_ie->h->length));
	c = gtp_conn_get_by_imsi(imsi);
	if (!c)
		c = gtp_conn_alloc(imsi, 0, 0);

	/* APN */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_APN_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no Access-Point-Name IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						   , GTP_CREATE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_MISSING_OR_UNKNOWN_APN);
		goto end;
	}

	memset(apn_str, 0, 63);
	ret = gtp_ie_apn_extract_ni((struct gtp_ie_apn *) msg_ie->h, apn_str, 63);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error parsing Access-Point-Name IE. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						   , GTP_CREATE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_MISSING_OR_UNKNOWN_APN);
		goto end;
	}

	apn = gtp_apn_get(apn_str);
	if (!apn) {
		log_message(LOG_INFO, "%s(): Unknown Access-Point-Name:%s. ignoring..."
				    , __FUNCTION__, apn_str);
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						   , GTP_CREATE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_MISSING_OR_UNKNOWN_APN);
		goto end;
	}

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_PDN_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no PDN-TYPE IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						   , GTP_CREATE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_REQUEST_REJECTED);
		goto end;
	}

	ptype = (uint8_t *) msg_ie->data;
	if (__test_bit(GTP_APN_FL_SESSION_UNIQ_PTYPE, &apn->flags)) {
		ret = gtp_session_uniq_ptype(c, *ptype);
		if (ret) {
			rc = gtpc_build_errmsg(srv->s.pbuff, teid
							   , GTP_CREATE_SESSION_RESPONSE_TYPE
							   , GTP_CAUSE_REQUEST_REJECTED);
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
	s->srv = srv;

#if 0
	/* Allocate IP Address from APN pool if configured */
	s->ipv4 = gtp_ip_pool_get(apn);
	if (apn->ip_pool && !s->ipv4) {
		log_message(LOG_INFO, "%s(): APN:%s All IP Address occupied"
				    , __FUNCTION__
				    , apn_str);
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						   , GTP_CREATE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_ALL_DYNAMIC_ADDRESS_OCCUPIED);
		goto end;
	}
#endif

	teid = gtpc_teid_create(srv, s, msg, true);
	if (!teid) {
		log_message(LOG_INFO, "%s(): No GTP-C F-TEID, cant create session. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						   , GTP_CREATE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_REQUEST_REJECTED);
//		gtp_ip_pool_put(apn, s->ipv4);
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
		ecgi = gtp_ie_uli_extract_ecgi((struct gtp_ie_uli *) msg_ie->h);

	/* AMBR */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_AMBR_TYPE);
	if (msg_ie)
		ambr = (struct gtp_ie_ambr *) msg_ie->h;

	/* Update last sGW visited */
	gtp_teid_update_sgw(teid, addr);

	/* Generate Charging-ID */
	s->charging_id = poor_prng(&srv->s.seed) ^ c->sgw_addr.sin_addr.s_addr;

	/* CDR init */
	gtp_cdr_update(srv->s.pbuff, msg, s->cdr);

	/* IP VRF is in use and PPPoE session forwarding is configured */
	if (apn->vrf && (__test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags) ||
			 __test_bit(IP_VRF_FL_PPPOE_BUNDLE_BIT, &apn->vrf->flags))) {
		if (__test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags))
			pppoe = apn->vrf->pppoe;
		else
			pppoe = pppoe_bundle_get_active_instance(apn->vrf->pppoe_bundle);

		if (!pppoe) {
			log_message(LOG_INFO, "No active PPPoE Instance available to handle request");
			rc = gtpc_build_errmsg(srv->s.pbuff, teid
							 , GTP_CREATE_SESSION_RESPONSE_TYPE
							 , GTP_CAUSE_REQUEST_REJECTED);
			goto end;
		}

		s_pppoe = spppoe_alloc(pppoe, c,
				       gtpc_pppoe_tls, gtpc_pppoe_tlf,
				       gtpc_pppoe_create_session_response, gtpc_pppoe_chg,
				       imsi, s->mei, apn_str, ecgi, ambr);
		if (!s_pppoe) {
			rc = gtpc_build_errmsg(srv->s.pbuff, teid
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

	rc = gtpc_build_create_session_response(srv->s.pbuff, s, teid, NULL);
  end:
	gtp_msg_destroy(msg);
	return rc;
}

static int
gtpc_delete_session_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *h = (struct gtp_hdr *) srv->s.pbuff->head;
	struct gtp_teid *teid, *pteid;
	struct gtp_msg *msg;
	struct gtp_msg_ie *msg_ie;
	uint32_t id, ipv4;
	uint8_t *ie_buffer;
	int rc = -1;

	msg = gtp_msg_alloc(srv->s.pbuff);
	if (!msg)
		return -1;

	teid = _gtpc_teid_get(h->teid, inet_sockaddrip4(&srv->s.addr));
	if (!teid) {
		rc = gtpc_build_errmsg(srv->s.pbuff, NULL
						   , GTP_DELETE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_CONTEXT_NOT_FOUND);
		goto end;
	}

	log_message(LOG_INFO, "Delete-Session-Req:={F-TEID:0x%.8x}", ntohl(teid->peer_teid->id));

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (!msg_ie) {
		log_message(LOG_INFO, "%s(): no F_TEID IE present. ignoring..."
				    , __FUNCTION__);
		rc = gtpc_build_errmsg(srv->s.pbuff, NULL
						   , GTP_CREATE_SESSION_RESPONSE_TYPE
						   , GTP_CAUSE_INVALID_PEER);
		goto end;
	}

	ie_buffer = (uint8_t *) msg_ie->h;
	id = *(uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, teid_grekey));
	ipv4 = *(uint32_t *) (ie_buffer + offsetof(struct gtp_ie_f_teid, ipv4));
	pteid = _gtpc_teid_get(id, ipv4);
	if (!pteid) {
		rc = gtpc_build_errmsg(srv->s.pbuff, teid
						   , GTP_DELETE_SESSION_RESPONSE_TYPE
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
	gtp_sqn_update(srv, teid);
	gtp_sqn_update(srv, pteid);

	rc = gtpc_build_errmsg(srv->s.pbuff, pteid
					   , GTP_DELETE_SESSION_RESPONSE_TYPE
					   , GTP_CAUSE_REQUEST_ACCEPTED);

	gtp_teid_put(teid);
	gtp_teid_put(pteid);
	if (teid->session && teid->session->s_pppoe)
		spppoe_close(teid->session->s_pppoe);
	else
		gtp_session_destroy(teid->session);

	/* CDR Update */
	gtp_cdr_update(srv->s.pbuff, NULL, teid->session->cdr);

  end:
	gtp_msg_destroy(msg);
	return rc;
}

static int
gtpc_modify_bearer_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *h = (struct gtp_hdr *) srv->s.pbuff->head;
	struct gtp_teid *teid, *pteid = NULL, *t, *t_u;
	struct gtp_session *s;
	struct ip_vrf *vrf;
	struct gtp_msg *msg;
	int rc = -1;

	msg = gtp_msg_alloc(srv->s.pbuff);
	if (!msg)
		return -1;

	teid = _gtpc_teid_get(h->teid, inet_sockaddrip4(&srv->s.addr));
	if (!teid) {
		log_message(LOG_INFO, "%s(): Unknown TEID 0x%.8x..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		rc = gtpc_build_errmsg(srv->s.pbuff, NULL
						   , GTP_MODIFY_BEARER_RESPONSE_TYPE
						   , GTP_CAUSE_CONTEXT_NOT_FOUND);
		goto end;
	}

	/* Update sGW */
	gtp_teid_update_sgw(teid, addr);
	gtp_teid_update_sgw(teid->peer_teid, addr);
	s = teid->session;

	/* Update SQN */
	gtp_sqn_update(srv, teid);
	gtp_sqn_update(srv, teid->peer_teid);

	/* Create TEID */
	t = gtpc_teid_create(srv, s, msg, false);
	if (!t)
		goto accept;

	/* GTP-C Update */
	pteid = teid->peer_teid;
	t->old_teid = pteid;
	gtp_teid_bind(teid, t);

	/* GTP-U Update: resolve old GTP-U ref before pteid is freed */
	t_u = gtp_session_gtpu_teid_get_by_sqn(s, t->sqn);
	if (t_u) {
		t->bearer_teid = t_u;
		t_u->old_teid = (pteid) ? pteid->bearer_teid : NULL;
		gtp_teid_bind(teid->bearer_teid, t_u);
	}

	gtp_session_gtpc_teid_destroy(t->old_teid);

	if (t_u && t_u->old_teid &&
	    __test_bit(GTP_TEID_FL_LINKED, &t_u->old_teid->flags))
		gtp_session_gtpu_teid_destroy(t_u->old_teid);

	/* Add delayed XDP entries */
	vrf = (s->apn) ? s->apn->vrf : NULL;
	if (vrf && __test_bit(IP_VRF_FL_PPPOE_BIT, &vrf->flags))
		gtp_session_gtpu_teid_xdp_add(s);

	/* CDR Update */
	gtp_cdr_update(srv->s.pbuff, msg, s->cdr);

  accept:
	rc = gtpc_build_errmsg(srv->s.pbuff, teid->peer_teid
					   , GTP_MODIFY_BEARER_RESPONSE_TYPE
					   , GTP_CAUSE_REQUEST_ACCEPTED);
  end:
	gtp_msg_destroy(msg);
	return rc;
}

static int
gtpc_change_notification_request_hdl(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *h = (struct gtp_hdr *) srv->s.pbuff->head;
	struct gtp_teid *teid;
	struct gtp_msg *msg;
	int rc = -1;

	msg = gtp_msg_alloc(srv->s.pbuff);
	if (!msg)
		return -1;

	teid = _gtpc_teid_get(h->teid, inet_sockaddrip4(&srv->s.addr));
	if (!teid) {
		log_message(LOG_INFO, "%s(): Unknown TEID 0x%.8x..."
				    , __FUNCTION__
				    , ntohl(h->teid));
		rc = gtpc_build_errmsg(srv->s.pbuff, NULL
			 			   , GTP_CHANGE_NOTIFICATION_RESPONSE
						   , GTP_CAUSE_IMSI_IMEI_NOT_KNOWN);
		goto end;
	}

	/* Update SQN */
	gtp_sqn_update(srv, teid);
	gtp_sqn_update(srv, teid->peer_teid);

	rc = gtpc_build_change_notification_response(srv->s.pbuff, teid->session,
						     teid->peer_teid);
  end:
	gtp_msg_destroy(msg);
	return rc;
}


/*
 *	GTP-C Message handle
 */
static const struct {
	int (*hdl) (struct gtp_server *, struct sockaddr_storage *);
} gtpc_msg_hdl[1 << 8] = {
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
gtpc_router_handle(struct gtp_server *srv, struct sockaddr_storage *addr)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) srv->s.pbuff->head;

	if (*(gtpc_msg_hdl[gtph->type].hdl)) {
		gtp_metrics_rx(&srv->msg_metrics, gtph->type);

		return (*(gtpc_msg_hdl[gtph->type].hdl)) (srv, addr);
	}

	gtp_metrics_rx_notsup(&srv->msg_metrics, gtph->type);
	return -1;
}


/*
 *	GTP-U Message handle
 */
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
	return 0;
}

static const struct {
	int (*hdl) (struct gtp_server *, struct sockaddr_storage *);
} gtpu_msg_hdl[0xff + 1] = {
	[GTPU_ECHO_REQ_TYPE]			= { gtpu_echo_request_hdl },
	[GTPU_ERR_IND_TYPE]			= { gtpu_error_indication_hdl },
	[GTPU_END_MARKER_TYPE]			= { gtpu_end_marker_hdl	},
};

int
gtpu_router_handle(struct gtp_server *srv, struct sockaddr_storage *addr)
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
