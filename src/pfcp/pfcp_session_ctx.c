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
#include <stdint.h>
#include "pfcp_session.h"
#include "pfcp.h"
#include "pfcp_teid.h"
#include "pfcp_msg.h"
#include "pfcp_router.h"
#include "pfcp_proto_hdl.h"
#include "pfcp_bpf.h"
#include "gtp_bpf_utils.h"
#include "bitops.h"
#include "logger.h"


static struct traffic_endpoint *
pfcp_session_get_te_by_id(struct pfcp_session *s, uint8_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->te[i].id; i++) {
		if (s->te[i].id == id)
			return &s->te[i];
	}

	return NULL;
}

static struct far *
pfcp_session_get_far_by_id(struct pfcp_session *s, uint32_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->far[i].id; i++) {
		if (s->far[i].id == id)
			return &s->far[i];
	}

	return NULL;
}

static struct qer *
pfcp_session_get_qer_by_id(struct pfcp_session *s, uint32_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->qer[i].id; i++) {
		if (s->qer[i].id == id)
			return &s->qer[i];
	}

	return NULL;
}

static struct urr *
pfcp_session_get_urr_by_id(struct pfcp_session *s, uint32_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->urr[i].id; i++) {
		if (s->urr[i].id == id)
			return &s->urr[i];
	}

	return NULL;
}

static struct gtp_server *
pfcp_session_get_gtp_server_by_interface(struct pfcp_router *r, uint8_t interface)
{
	struct gtp_server *srv = NULL;

	switch (interface) {
	case PFCP_3GPP_INTERFACE_S1U:
		if (__test_bit(PFCP_ROUTER_FL_S1U, &r->flags))
			srv = &r->gtpu_s1;
		break;

	case PFCP_3GPP_INTERFACE_S5U:
		if (__test_bit(PFCP_ROUTER_FL_S5U, &r->flags))
			srv = &r->gtpu_s5;
		break;

	case PFCP_3GPP_INTERFACE_S8U:
		if (__test_bit(PFCP_ROUTER_FL_S8U, &r->flags))
			srv = &r->gtpu_s8;
		break;

	case PFCP_3GPP_INTERFACE_N9:
		if (__test_bit(PFCP_ROUTER_FL_N9U, &r->flags))
			srv = &r->gtpu_n9;
		break;
	}

	if (!srv && __test_bit(PFCP_ROUTER_FL_ALL, &r->flags))
		srv = &r->gtpu;

	return srv;
}

struct sockaddr_storage *
pfcp_session_get_addr_by_interface(struct pfcp_router *r, uint8_t interface)
{
	struct gtp_server *srv;

	srv = pfcp_session_get_gtp_server_by_interface(r, interface);
	if (!srv) {
		log_message(LOG_INFO, "%s(): pfcp-router:'%s' No GTP-U interface configured !!!"
				    , __FUNCTION__, r->name);
		return NULL;
	}

	return &srv->s.addr;
}

static struct pfcp_teid *
pfcp_session_alloc_teid(struct pfcp_session *s, uint8_t interface, uint32_t *id)
{
	struct pfcp_router *r = s->router;
	struct sockaddr_storage *gtpu_addr = NULL;
	struct in_addr *ipv4;
	struct in6_addr *ipv6;
	struct pfcp_teid *t;
	uint32_t new_id;

	gtpu_addr = pfcp_session_get_addr_by_interface(r, interface);
	if (!gtpu_addr)
		return NULL;

	ipv4 = (gtpu_addr->ss_family == AF_INET) ? &((struct sockaddr_in *)gtpu_addr)->sin_addr : NULL;
	ipv6 = (gtpu_addr->ss_family == AF_INET6) ? &((struct sockaddr_in6 *)gtpu_addr)->sin6_addr : NULL;

	/* Try to use same TEID for different IP Address */
	if (!*id)  {
		new_id = pfcp_teid_roll_the_dice(r->teid, &r->seed, ipv4, ipv6);
		if (!new_id)
			return NULL;
		*id = new_id;
	}

	t = pfcp_teid_alloc(r->teid, &r->seed, interface, *id, ipv4, ipv6);
	if (!t)
		return NULL;

	__sync_add_and_fetch(&s->teid_cnt, 1);
	return t;
}

static int
pfcp_session_destroy_teid(struct pfcp_session *s, struct traffic_endpoint *te,
			  struct pfcp_teid *t, int sndem)
{
	struct pfcp_router *r = s->router;
	struct gtp_server *srv;

	if (!sndem)
		goto teid_del;

	srv = pfcp_session_get_gtp_server_by_interface(r, te->interface_type);
	if (!srv)
		goto teid_del;

	gtpu_send_end_marker(srv, t);

teid_del:
	pfcp_bpf_teid_action(r, RULE_DEL, t, &s->ue_ip);
	pfcp_teid_free(t);
	__sync_sub_and_fetch(&s->teid_cnt, 1);
	return 0;
}


static int
pfcp_session_create_te(struct pfcp_session *s, struct traffic_endpoint *te,
		       struct pfcp_ie_create_traffic_endpoint *ie, uint32_t *id)
{
	struct pfcp_ie_f_teid *fteid = ie->local_f_teid;
	struct ue_ip_address *ue_ip = &te->ue_ip;
	struct pfcp_teid *t;

	te->id = ie->traffic_endpoint_id->value;

	if (ie->source_interface_type)
		te->interface_type = ie->source_interface_type->value;

	if (ie->ue_ip_address) {
		if (ie->ue_ip_address->chv4)
			ue_ip->flags |= UE_CHV4;

		if (ie->ue_ip_address->chv6)
			ue_ip->flags |= UE_CHV6;

		if (ie->ue_ip_address->v4) {
			ue_ip->flags |= UE_IPV4;
			ue_ip->v4 = ie->ue_ip_address->ip_address.v4;
		}

		if (ie->ue_ip_address->v6) {
			ue_ip->flags |= UE_IPV6;
			memcpy(&ue_ip->v6, &ie->ue_ip_address->ip_address.v6,
			       sizeof(struct in6_addr));
		}
	}

	if (!fteid)
		return 0;

	if (fteid->chid)
		te->choose_id = fteid->choose_id;

	if (!fteid->ch) {
		/* Restoration procedure */
		t = pfcp_teid_restore(s->router->teid, fteid);
		if (!t)
			return -1;

		goto set_type;
	}

	t = pfcp_session_alloc_teid(s, te->interface_type, id);
	if (!t)
		return -1;

set_type:
	if (te->interface_type == PFCP_3GPP_INTERFACE_SGI) {
		__set_bit(PFCP_TEID_F_INGRESS, &t->flags);
		te->teid[PFCP_DIR_INGRESS] = t;
	} else {
		__set_bit(PFCP_TEID_F_EGRESS, &t->flags);
		te->teid[PFCP_DIR_EGRESS] = t;
	}

	return 0;
}

static int
pfcp_session_create_far(struct pfcp_session *s, struct far *far,
			struct pfcp_ie_create_far *ie)
{
	struct pfcp_router *r = s->router;
	struct pfcp_ie_forwarding_parameters *fwd = ie->forwarding_parameters;
	struct pfcp_ie_outer_header_creation *ohc;
	struct in_addr ipv4;
	struct pfcp_teid *t;
	uint8_t interface = 0;

	far->id = ie->far_id->value;

	/* Optional: Forwarding Parameters */
	if (!ie->forwarding_parameters)
		return 0;

	if (fwd->destination_interface)
		far->dst_interface = fwd->destination_interface->value;

	if (fwd->destination_interface_type) {
		interface = fwd->destination_interface_type->value;
		far->dst_interface_type = interface;
	}

	if (fwd->transport_level_marking) {
		far->tos_tclass = ntohs(fwd->transport_level_marking->traffic_class) & 0xff;
		far->tos_mask = (ntohs(fwd->transport_level_marking->traffic_class) >> 8) & 0xff;
	}

	if (fwd->linked_traffic_endpoint_id)
		far->dst_te = pfcp_session_get_te_by_id(s, fwd->linked_traffic_endpoint_id->value);

	ohc = fwd->outer_header_creation;
	/* TODO: Support IPv6... */
	if (ohc && ntohs(ohc->description) == PFCP_OUTER_HEADER_GTPUV4 && far->dst_te) {
		ipv4.s_addr = ohc->ip_address.v4.s_addr;
		t = pfcp_teid_alloc_static(r->teid, interface, ntohl(ohc->teid), &ipv4, NULL);
		if (t) {
			if (far->dst_interface == PFCP_SRC_INTERFACE_TYPE_ACCESS) {
				__set_bit(PFCP_TEID_F_INGRESS, &t->flags);
				far->dst_te->teid[PFCP_DIR_INGRESS] = t;
				return 0;
			}

			pfcp_teid_free(t);
		}
	}

	return 0;
}

static int
pfcp_session_update_far(struct pfcp_session *s, struct pfcp_ie_update_far *uf)
{
	struct pfcp_router *r = s->router;
	struct pfcp_ie_update_forwarding_parameters *ufwd;
	struct pfcp_ie_outer_header_creation *ohc;
	struct pfcp_ie_pfcpsmreq_flags *pfcpsm_flags;
	struct far *far = NULL;
	struct traffic_endpoint *te;
	struct in_addr ipv4;
	struct pfcp_teid *t;
	uint8_t interface = 0;

	far = pfcp_session_get_far_by_id(s, uf->far_id->value);
	if (!far)
		return -1;

	te = far->dst_te;
	ufwd = uf->update_forwarding_parameters;
	if (!ufwd)
		return -1;

	if (ufwd->destination_interface_type)
		interface = ufwd->destination_interface_type->value;

	/* Update TE accordingly */
	if (te && ufwd->linked_traffic_endpoint_id &&
	    te->id != ufwd->linked_traffic_endpoint_id->value) {
		far->dst_te = pfcp_session_get_te_by_id(s, ufwd->linked_traffic_endpoint_id->value);
		/* Unknown TE... */
		if (!far->dst_te)
			return -1;
	} else if (!te && ufwd->linked_traffic_endpoint_id) {
		far->dst_te = pfcp_session_get_te_by_id(s, ufwd->linked_traffic_endpoint_id->value);
		/* Unknown TE... */
		if (!far->dst_te)
			return -1;
	}

	/* Outer header creation induce ingress traffic from
	 * SGi to Access */
	ohc = ufwd->outer_header_creation;
	if (!ohc)
		return 0;

	/* Same TE, F-TEID changed ? */
	if (te && te == far->dst_te) {
		t = te->teid[PFCP_DIR_INGRESS];

		/* Same F-TEID, just ignore and return */
		if (t && (t->id == ohc->teid &&
		    t->ipv4.s_addr == ohc->ip_address.v4.s_addr))
			return 0;

		/* New F-TEID, release previous one and notify */
		if (t) {
			int sndem = 0;
			pfcpsm_flags = ufwd->pfcpsm_req_flags;
			if (pfcpsm_flags && pfcpsm_flags->sndem)
				sndem = 1;
			pfcp_session_destroy_teid(s, te, t, sndem);
			te->teid[PFCP_DIR_INGRESS] = NULL;
		}
	}

	if (ntohs(ohc->description) == PFCP_OUTER_HEADER_GTPUV4 && far->dst_te) {
		ipv4.s_addr = ohc->ip_address.v4.s_addr;
		t = pfcp_teid_alloc_static(r->teid, interface,
					   ntohl(ohc->teid), &ipv4, NULL);
		if (t) {
			if (far->dst_interface == PFCP_SRC_INTERFACE_TYPE_ACCESS) {
				__set_bit(PFCP_TEID_F_INGRESS, &t->flags);
				far->dst_te->teid[PFCP_DIR_INGRESS] = t;
				return 0;
			}

			pfcp_teid_free(t);
		}
	}

	return 0;
}

static int
pfcp_session_create_qer(struct pfcp_session *s, struct qer *qer,
			struct pfcp_ie_create_qer *ie)
{
	qer->id = ie->qer_id->value;

	if (ie->maximum_bitrate) {
		qer->ul_mbr = ntohl(ie->maximum_bitrate->ul_mbr);
		qer->dl_mbr = ntohl(ie->maximum_bitrate->dl_mbr);
	}

	return 0;
}

static int
pfcp_session_create_urr(struct pfcp_session *s, struct urr *urr,
			struct pfcp_ie_create_urr *ie)
{
	urr->id = ie->urr_id->value;

	urr->start_time = time_now_to_ntp();

	urr->measurement_method = ie->measurement_method->measurement_method;

	urr->triggers = ntohs(ie->reporting_triggers->triggers);

	if (ie->measurement_information)
		urr->measurement_info = ie->measurement_information->flags;

	if (ie->inactivity_detection_time)
		urr->inactivity_detection_time = ntohl(ie->inactivity_detection_time->value);

	if (ie->quota_holding_time)
		urr->quota_holdtime = ntohl(ie->quota_holding_time->value);

	if (ie->volume_threshold) {
		if (ie->volume_threshold->tovol)
			urr->volume_threshold_to = be64toh(ie->volume_threshold->total_volume);
		if (ie->volume_threshold->ulvol)
			urr->volume_threshold_ul = be64toh(ie->volume_threshold->uplink_volume);
		if (ie->volume_threshold->dlvol)
			urr->volume_threshold_dl = be64toh(ie->volume_threshold->downlink_volume);
	}

	if (ie->linked_urr_id)
		urr->linked_urr_id = ie->linked_urr_id->value;

	return 0;
}

static int
pfcp_session_link_urr(struct pfcp_session *s)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->urr[i].id; i++) {
		if (!s->urr[i].linked_urr_id)
			continue;

		s->urr[i].linked_urr = pfcp_session_get_urr_by_id(s, s->urr[i].linked_urr_id);
	}

	return 0;
}

static int
pfcp_session_pdi(struct pfcp_session *s, struct pdr *pdr, struct pfcp_ie_pdi *pdi,
		 uint32_t *id)
{
	struct pfcp_ie_f_teid *fteid = pdi->local_f_teid;
	struct ue_ip_address *ue_ip = &pdr->ue_ip;
	struct pfcp_teid *t;

	if (!pdi)
		return -1;

	/* PDI is traffic-endpoint OR local_f_teid */
	if (pdi->traffic_endpoint_id) {
		pdr->te = pfcp_session_get_te_by_id(s, pdi->traffic_endpoint_id->value);

		return (pdr->te) ? 0 : -1;
	}

	if (!fteid)
		return 0;

	/* local_f_teid */
	if (!pdi->source_interface_type)
		return -1;

	pdr->src_interface = pdi->source_interface_type->value;

	if (pdi->ue_ip_address) {
		if (pdi->ue_ip_address->v4) {
			ue_ip->flags |= UE_IPV4;
			ue_ip->v4 = pdi->ue_ip_address->ip_address.v4;
		}

		if (pdi->ue_ip_address->v6) {
			ue_ip->flags |= UE_IPV6;
			memcpy(&ue_ip->v6, &pdi->ue_ip_address->ip_address.v6,
			       sizeof(struct in6_addr));
		}
	}

	if (fteid->chid)
		pdr->choose_id = fteid->choose_id;

	if (!fteid->ch) {
		/* Restoration procedure */
		t = pfcp_teid_restore(s->router->teid, fteid);
		if (!t)
			return -1;

		goto set_type;
	}

	t = pfcp_session_alloc_teid(s, pdr->src_interface, id);
	if (!t)
		return -1;

set_type:
	if (pdr->src_interface == PFCP_SRC_INTERFACE_TYPE_ACCESS) {
		__set_bit(PFCP_TEID_F_EGRESS, &t->flags);
		pdr->teid[PFCP_DIR_EGRESS] = t;
	} else {
		__set_bit(PFCP_TEID_F_INGRESS, &t->flags);
		pdr->teid[PFCP_DIR_INGRESS] = t;
	}

	return 0;
}

static int
pfcp_session_create_pdr(struct pfcp_session *s, struct pdr *pdr,
			struct pfcp_ie_create_pdr *ie, uint32_t *id)
{
	int i, err;

	pdr->id = ie->pdr_id->rule_id;

	pdr->precedence = be32toh(ie->precedence->value);

	err = pfcp_session_pdi(s, pdr, ie->pdi, id);
	if (err)
		return -1;

	if (ie->far_id)
		pdr->far = pfcp_session_get_far_by_id(s, ie->far_id->value);

	if (ie->urr_id) {
		for (i = 0; i < ie->nr_urr_id && i < PFCP_MAX_NR_ELEM; i++) {
			pdr->urr[i] = pfcp_session_get_urr_by_id(s, ie->urr_id[i]->value);
			if (!pdr->urr[i])
				return -1;
		}
	}

	if (ie->qer_id) {
		pdr->qer = pfcp_session_get_qer_by_id(s, ie->qer_id->value);
		if (!pdr->qer)
			return -1;
	}

	if (ie->activate_predefined_rules) {
		size_t len = ntohs(ie->activate_predefined_rules->h.length);
		if (len > 0 && len < PFCP_STR_MAX_LEN)
			memcpy(pdr->predifined_rule,
			       ie->activate_predefined_rules->predefined_rules_name, len);
	}

	return 0;
}

int
pfcp_session_create(struct pfcp_session *s, struct pfcp_session_establishment_request *req,
		    struct sockaddr_storage *addr)
{
	int i, err = 0;
	uint32_t id = 0;

	/* Remote SEID */
	s->remote_seid.id = req->cp_f_seid->seid;
	s->remote_seid.addr = *addr;

	/* Traffic Endpoint */
	for (i = 0; i < req->nr_create_traffic_endpoint && i < PFCP_MAX_NR_ELEM; i++) {
		err = pfcp_session_create_te(s, &s->te[i],
					     req->create_traffic_endpoint[i], &id);
		if (err)
			return -1;
	}

	/* FAR */
	for (i = 0; i < req->nr_create_far && i < PFCP_MAX_NR_ELEM; i++)
		pfcp_session_create_far(s, &s->far[i], req->create_far[i]);

	/* QER */
	for (i = 0; i < req->nr_create_qer && i < PFCP_MAX_NR_ELEM; i++)
		pfcp_session_create_qer(s, &s->qer[i], req->create_qer[i]);

	/* URR */
	for (i = 0; i < req->nr_create_urr && i < PFCP_MAX_NR_ELEM; i++)
		pfcp_session_create_urr(s, &s->urr[i], req->create_urr[i]);
	pfcp_session_link_urr(s);

	/* PDR will reference parsed elem */
	for (i = 0; i < req->nr_create_pdr && i < PFCP_MAX_NR_ELEM; i++) {
		err = pfcp_session_create_pdr(s, &s->pdr[i], req->create_pdr[i],
					      &id);
		if (err)
			return -1;
	}

	return 0;
}

int
pfcp_session_modify(struct pfcp_session *s, struct pfcp_session_modification_request *req)
{
	int i, err = 0;

	/* Update FAR */
	for (i = 0; i < req->nr_update_far; i++) {
		err = pfcp_session_update_far(s, req->update_far[i]);
		if (err)
			return -1;
	}

	return 0;
}


/*
 *	Session IE put
 */
static void
pfcp_session_init_teid_values(struct pfcp_teid *t, uint32_t *teid,
			      struct in_addr **ipv4, struct in6_addr **ipv6)
{
	*teid = 0;
	*ipv4 = NULL;
	*ipv6 = NULL;

	if (!t)
		return;

	*teid = t->id;
	if (__test_bit(PFCP_TEID_F_IPV4, &t->flags))
		*ipv4 = &t->ipv4;
	if (__test_bit(PFCP_TEID_F_IPV6, &t->flags))
		*ipv6 = &t->ipv6;
}

static int
pfcp_session_init_ue_values(struct pfcp_session *s, struct traffic_endpoint *te,
			    struct in_addr **ipv4, struct in6_addr **ipv6)
{
	struct ue_ip_address *ue_ip_s = &s->ue_ip;
	struct ue_ip_address *ue_ip = &te->ue_ip;
	struct in_addr *v4 = &ue_ip_s->v4;
	struct in6_addr *v6 = &ue_ip_s->v6;
	int err;

	*ipv4 = NULL;
	*ipv6 = NULL;

	if (ue_ip->flags & UE_CHV4) {
		/* Session UE IP Address is not initialized */
		if (!(ue_ip_s->flags & UE_CHV4)) {
			err = pfcp_session_alloc_ue_ip(s, AF_INET);
			if (err) {
				errno = ENOSPC;
				return -1;
			}
		}
		*ipv4 = v4;
	}

	if (ue_ip->flags & UE_CHV6) {
		/* Session UE IP Address is not initialized */
		if (!(ue_ip_s->flags & UE_CHV6)) {
			err = pfcp_session_alloc_ue_ip(s, AF_INET6);
			if (err) {
				pfcp_session_release_ue_ip(s);
				errno = ENOSPC;
				return -1;
			}
		}
		*ipv6 = v6;
	}

	return 0;
}

int
pfcp_session_put_created_pdr(struct pkt_buffer *pbuff, struct pfcp_session *s)
{
	struct pdr *p;
	uint32_t teid;
	struct in_addr *ipv4;
	struct in6_addr *ipv6;
	int i, err;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->pdr[i].id; i++) {
		p = &s->pdr[i];
		pfcp_session_init_teid_values(p->teid[PFCP_DIR_EGRESS], &teid, &ipv4, &ipv6);
		err = pfcp_ie_put_created_pdr(pbuff, p->id, htonl(teid), ipv4, ipv6);
		if (err)
			return -1;
	}

	return 0;
}

int
pfcp_session_put_created_traffic_endpoint(struct pkt_buffer *pbuff, struct pfcp_session *s)
{
	struct traffic_endpoint *te;
	uint32_t teid;
	struct in_addr *t_ipv4, *ue_ipv4;
	struct in6_addr *t_ipv6, *ue_ipv6;
	int i, err;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->te[i].id; i++) {
		te = &s->te[i];
		pfcp_session_init_teid_values(te->teid[PFCP_DIR_EGRESS], &teid, &t_ipv4, &t_ipv6);
		err = pfcp_session_init_ue_values(s, te, &ue_ipv4, &ue_ipv6);
		if (err) {
			errno = ENOSPC;
			return -1;
		}

		err = pfcp_ie_put_created_te(pbuff, te->id, htonl(teid),
					     t_ipv4, t_ipv6, ue_ipv4, ue_ipv6);
		if (err) {
			errno = EINVAL;
			return -1;
		}
	}

	return 0;
}

int
pfcp_session_put_usage_report(struct pkt_buffer *pbuff, struct pfcp_session *s)
{
	struct urr *u;
	int i, err;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->urr[i].id; i++) {
		u = &s->urr[i];
		u->end_time = time_now_to_ntp();
		err = pfcp_ie_put_usage_report(pbuff, u->id, u->start_time, u->end_time,
					       &u->uplink, &u->downlink);
		if (err)
			return -1;
	}

	return 0;
}
