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
#include "pfcp_ie.h"
#include "pfcp_session.h"
#include "pfcp_teid.h"
#include "pfcp_msg.h"
#include "pfcp_router.h"
#include "pfcp_proto_hdl.h"
#include "pfcp_bpf.h"
#include "bitops.h"
#include "logger.h"


static struct traffic_endpoint *
pfcp_session_get_te_by_id(struct pfcp_session *s, uint8_t id)
{
	struct traffic_endpoint *te;

	list_for_each_entry(te, &s->te_list, next) {
		if (te->id == id)
			return te;
	}

	return NULL;
}

static struct far *
pfcp_session_get_far_by_id(struct pfcp_session *s, uint32_t id)
{
	struct far *f;

	list_for_each_entry(f, &s->far_list, next) {
		if (f->id == id)
			return f;
	}

	return NULL;
}

static struct qer *
pfcp_session_get_qer_by_id(struct pfcp_session *s, uint32_t id)
{
	struct qer *q;

	list_for_each_entry(q, &s->qer_list, next) {
		if (q->id == id)
			return q;
	}

	return NULL;
}

static struct urr *
pfcp_session_get_urr_by_id(struct pfcp_session *s, uint32_t id)
{
	struct urr *u;

	list_for_each_entry(u, &s->urr_list, next) {
		if (u->id == id)
			return u;
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

int
pfcp_session_release_teid(struct pfcp_session *s)
{
	struct pdr *pdr;
	struct traffic_endpoint *te;

	/* Non-optimized pdi */
	list_for_each_entry(pdr, &s->pdr_list, next) {
		pfcp_teid_free(pdr->teid);
	}

	/* Optimized PDI */
	list_for_each_entry(te, &s->te_list, next) {
		pfcp_teid_free(te->teid);
	}

	return 0;
}

int
pfcp_session_release_ue_ip(struct pfcp_session *s)
{
	struct ue_ip_address *ue_ip = &s->ue_ip;

	if ((ue_ip->flags & UE_CHV4) && ue_ip->pool_v4) {
		ip_pool_put(ue_ip->pool_v4, &ue_ip->v4);
		ue_ip->pool_v4 = NULL;
	}

	if ((ue_ip->flags & UE_CHV6) && ue_ip->pool_v6) {
		ip_pool_put(ue_ip->pool_v6, &ue_ip->v6);
		ue_ip->pool_v6 = NULL;
	}

	return 0;
}

static int
pfcp_session_create_te(struct pfcp_session *s, struct traffic_endpoint *te,
		       struct pfcp_ie_create_traffic_endpoint *ie, uint32_t *id)
{
	struct pfcp_ie_f_teid *fteid = ie->local_f_teid;
	struct ue_ip_address *ue_ip_s = &s->ue_ip;
	struct ue_ip_address *ue_ip = &te->ue_ip;
	struct pfcp_teid *t;
	int err;

	te->action = PFCP_ACT_CREATE;

	te->id = ie->traffic_endpoint_id->value;

	if (ie->source_interface_type)
		te->interface_type = ie->source_interface_type->value;

	if (ie->ue_ip_address) {
		if (ie->ue_ip_address->chv4) {
			ue_ip->flags |= UE_CHV4;
			/* Session UE IP Address is not initialized */
			if (!(ue_ip_s->flags & UE_IPV4)) {
				err = pfcp_session_alloc_ue_ip(s, AF_INET);
				if (err) {
					errno = ENOSPC;
					return -1;
				}
			}
		}

		if (ie->ue_ip_address->chv6) {
			ue_ip->flags |= UE_CHV6;
			/* Session UE IP Address is not initialized */
			if (!(ue_ip_s->flags & UE_IPV6)) {
				err = pfcp_session_alloc_ue_ip(s, AF_INET6);
				if (err) {
					pfcp_session_release_ue_ip(s);
					errno = ENOSPC;
					return -1;
				}
			}
		}

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
	te->teid = t;
	return 0;
}

static int
pfcp_session_create_far(struct pfcp_session *s, struct far *far,
			struct pfcp_ie_create_far *ie)
{
	struct pfcp_ie_forwarding_parameters *fwd = ie->forwarding_parameters;
	struct pfcp_ie_outer_header_creation *ohc;

	far->action = PFCP_ACT_CREATE;

	far->id = ie->far_id->value;

	/* Optional: Forwarding Parameters */
	if (!ie->forwarding_parameters)
		return 0;

	if (fwd->destination_interface)
		far->dst_interface = fwd->destination_interface->value;

	if (fwd->destination_interface_type)
		far->dst_interface_type = fwd->destination_interface_type->value;

	if (fwd->transport_level_marking) {
		far->tos_tclass = ntohs(fwd->transport_level_marking->traffic_class) & 0xff;
		far->tos_mask = (ntohs(fwd->transport_level_marking->traffic_class) >> 8) & 0xff;
	}

	if (fwd->linked_traffic_endpoint_id)
		far->dst_te = pfcp_session_get_te_by_id(s, fwd->linked_traffic_endpoint_id->value);

	ohc = fwd->outer_header_creation;

	/* Set action flags */
	if (ohc)
		far->flags |= UPF_FWD_FL_ACT_CREATE_OUTER_HEADER;

	if (ie->apply_action) {
		far->flags |= ie->apply_action->forw ? UPF_FWD_FL_ACT_FWD : 0;
		far->flags |= ie->apply_action->buff ? UPF_FWD_FL_ACT_BUFF : 0;
		far->flags |= ie->apply_action->drop ? UPF_FWD_FL_ACT_DROP : 0;
		far->flags |= ie->apply_action->dupl ? UPF_FWD_FL_ACT_DUPL : 0;
	}

	/* TODO: Support IPv6... */
	if (ohc && ntohs(ohc->description) == PFCP_OUTER_HEADER_GTPUV4 && far->dst_te) {
		far->outer_header_teid = ohc->teid;
		far->outer_header_ip4 = ohc->ip_address.v4;
	}

	return 0;
}

static int
pfcp_session_end_marker_teid(struct pfcp_session *s, struct traffic_endpoint *te,
			     struct far *f)
{
	struct pfcp_router *r = s->router;
	struct gtp_server *srv;

	srv = pfcp_session_get_gtp_server_by_interface(r, te->interface_type);
	if (!srv)
		return -1;

	gtpu_send_end_marker(srv, f);
	return 0;
}

static int
pfcp_session_update_far(struct pfcp_session *s, struct pfcp_ie_update_far *uf)
{
	struct pfcp_ie_update_forwarding_parameters *ufwd;
	struct pfcp_ie_outer_header_creation *ohc;
	struct pfcp_ie_pfcpsmreq_flags *pfcpsm_flags;
	struct far *far = NULL;
	struct traffic_endpoint *te;

	far = pfcp_session_get_far_by_id(s, uf->far_id->value);
	if (!far)
		return -1;

	te = far->dst_te;
	ufwd = uf->update_forwarding_parameters;
	if (!ufwd)
		return -1;

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

	far->action = PFCP_ACT_UPDATE;

	/* Set action flags */
	far->flags = 0;
	if (ohc)
		far->flags |= UPF_FWD_FL_ACT_CREATE_OUTER_HEADER;

	if (uf->apply_action) {
		far->flags |= uf->apply_action->forw ? UPF_FWD_FL_ACT_FWD : 0;
		far->flags |= uf->apply_action->buff ? UPF_FWD_FL_ACT_BUFF : 0;
		far->flags |= uf->apply_action->drop ? UPF_FWD_FL_ACT_DROP : 0;
		far->flags |= uf->apply_action->dupl ? UPF_FWD_FL_ACT_DUPL : 0;
	}

	/* Same TE, F-TEID changed ? */
	if (te && te == far->dst_te) {
		/* Same F-TEID, just ignore and return */
		if (far->outer_header_teid == ohc->teid &&
		    far->outer_header_ip4.s_addr == ohc->ip_address.v4.s_addr)
			return 0;

		/* New F-TEID, notify previous one */
		pfcpsm_flags = ufwd->pfcpsm_req_flags;
		if (pfcpsm_flags && pfcpsm_flags->sndem)
			pfcp_session_end_marker_teid(s, te, far);
	}

	if (ntohs(ohc->description) == PFCP_OUTER_HEADER_GTPUV4 && far->dst_te) {
		far->outer_header_teid = ohc->teid;
		far->outer_header_ip4 = ohc->ip_address.v4;
	}

	return 0;
}

static int
pfcp_session_create_qer(struct pfcp_session *s, struct qer *qer,
			struct pfcp_ie_create_qer *ie)
{
	qer->action = PFCP_ACT_CREATE;

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
	urr->action = PFCP_ACT_CREATE;

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
	struct urr *u, *r;

	list_for_each_entry(u, &s->urr_list, next) {
		if (!u->linked_urr_id)
			continue;

		r = pfcp_session_get_urr_by_id(s, u->linked_urr_id);
		if (!r)
			continue;

		u->linked_urr = r;
		r->parent_urr = u->linked_urr;
	}

	return 0;
}

static int
pfcp_session_pdi(struct pfcp_session *s, struct pdr *pdr, struct pfcp_ie_pdi *pdi,
		 uint32_t *id)
{
	struct ue_ip_address *ue_ip;
	struct pfcp_ie_f_teid *fteid;
	struct pfcp_teid *t;

	if (!pdi)
		return -1;

	if (!pdi->source_interface)
		return -1;

	fteid = pdi->local_f_teid;
	if (pdi->source_interface)
		pdr->src_interface = pdi->source_interface->value;

	/* PDI is traffic-endpoint OR local_f_teid */
	if (pdi->traffic_endpoint_id) {
		pdr->te = pfcp_session_get_te_by_id(s, pdi->traffic_endpoint_id->value);

		return pdr->te ? 0 : -1;
	}

	if (!fteid)
		return 0;

	if (pdi->ue_ip_address) {
		ue_ip = &pdr->ue_ip;
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
	pdr->teid = t;
	return 0;
}

static int
pfcp_session_create_pdr(struct pfcp_session *s, struct pdr *pdr,
			struct pfcp_ie_create_pdr *ie, uint32_t *id)
{
	int i, err;

	pdr->action = PFCP_ACT_CREATE;

	pdr->id = ie->pdr_id->rule_id;

	pdr->precedence = be32toh(ie->precedence->value);

	err = pfcp_session_pdi(s, pdr, ie->pdi, id);
	if (err)
		return -1;

	if (ie->far_id)
		pdr->far = pfcp_session_get_far_by_id(s, ie->far_id->value);

	if (ie->outer_header_removal)
		pdr->flags |= UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER; 

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

static int
pfcp_session_set_fwd_rule(struct pfcp_session *s, struct pdr *p)
{
	struct pfcp_fwd_rule *r = p->fwd_rule;
	struct upf_fwd_rule *u = &r->rule;
	struct far *f = p->far;
	struct qer *q = p->qer;
	
	/* Rule flags init */
	u->flags = 0;
	u->flags |= p->flags;
	u->flags |= !p->src_interface ? UPF_FWD_FL_EGRESS : UPF_FWD_FL_INGRESS;
	u->flags |= f->flags;

	/* GTP-U encapsulation */
	if (f->flags & UPF_FWD_FL_ACT_CREATE_OUTER_HEADER) {
		u->gtpu_remote_teid = f->outer_header_teid;
		u->gtpu_remote_addr = f->outer_header_ip4.s_addr;
		u->gtpu_remote_port = htons(GTP_U_PORT);

		/* Non-optimized pdi */
		if (p->teid)
			u->gtpu_local_addr = p->teid->ipv4.s_addr;
		else if (p->te)	/* Optimized PDI */
			u->gtpu_local_addr = p->te->teid ? p->te->teid->ipv4.s_addr : 0;

		u->gtpu_local_port = htons(GTP_U_PORT);
	}

	/* QER handling */
	if (q && q->action) {
		q->action = PFCP_ACT_NONE;
		u->ul_mbr = q->ul_mbr;
		u->dl_mbr = q->dl_mbr;
	}

	/* FAR Level Marking */
	u->tos_tclass = f->tos_tclass ? : 0;
	u->tos_mask = f->tos_mask ? : 0;

	/* Set data-path */
	if (u->flags & UPF_FWD_FL_EGRESS) {
		if (p->teid)
			pfcp_bpf_action(s->router, r, p->teid, NULL);
		else if (p->te && p->te->teid)
			pfcp_bpf_action(s->router, r, p->te->teid, NULL);
	} else {
		pfcp_bpf_action(s->router, r, NULL, &s->ue_ip);
	}

	/* Reset context actions for next round */
	r->action = p->action = f->action = PFCP_ACT_NONE;
	return 0;
}

static int
pfcp_session_create_fwd_rules(struct pfcp_session *s)
{
	struct pfcp_fwd_rule *new;
	struct pdr *p;
	struct far *f;

	list_for_each_entry(p, &s->pdr_list, next) {
		f = p->far;

		if (!p->action || !f)
			continue;

		new = calloc(1, sizeof(*new));
		if (!new)
			return -1;

		new->action = PFCP_ACT_CREATE;
		p->fwd_rule = new;
		pfcp_session_set_fwd_rule(s, p);
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
	for (i = 0; i < req->nr_create_traffic_endpoint; i++) {
		struct traffic_endpoint *te = calloc(1, sizeof(*te));
		if (!te)
			return -1;
		INIT_LIST_HEAD(&te->next);
		err = pfcp_session_create_te(s, te,
					     req->create_traffic_endpoint[i], &id);
		if (err) {
			free(te);
			return -1;
		}
		list_add_tail(&te->next, &s->te_list);
	}

	/* FAR */
	for (i = 0; i < req->nr_create_far; i++) {
		struct far *far = calloc(1, sizeof(*far));
		if (!far)
			return -1;
		INIT_LIST_HEAD(&far->next);
		pfcp_session_create_far(s, far, req->create_far[i]);
		list_add_tail(&far->next, &s->far_list);
	}

	/* QER */
	for (i = 0; i < req->nr_create_qer; i++) {
		struct qer *qer = calloc(1, sizeof(*qer));
		if (!qer)
			return -1;
		INIT_LIST_HEAD(&qer->next);
		pfcp_session_create_qer(s, qer, req->create_qer[i]);
		list_add_tail(&qer->next, &s->qer_list);
	}

	/* URR */
	for (i = 0; i < req->nr_create_urr; i++) {
		struct urr *urr = calloc(1, sizeof(*urr));
		if (!urr)
			return -1;
		INIT_LIST_HEAD(&urr->next);
		pfcp_session_create_urr(s, urr, req->create_urr[i]);
		list_add_tail(&urr->next, &s->urr_list);
	}
	pfcp_session_link_urr(s);

	/* PDR will reference parsed elem */
	for (i = 0; i < req->nr_create_pdr; i++) {
		struct pdr *pdr = calloc(1, sizeof(*pdr));
		if (!pdr)
			return -1;
		INIT_LIST_HEAD(&pdr->next);
		err = pfcp_session_create_pdr(s, pdr, req->create_pdr[i], &id);
		if (err) {
			free(pdr);
			return -1;
		}
		list_add_tail(&pdr->next, &s->pdr_list);
	}

	/* Create data-path forwarding rules */
	pfcp_session_create_fwd_rules(s);
	return 0;
}

static int
pfcp_session_update_fwd_rules(struct pfcp_session *s)
{
	struct pfcp_fwd_rule *r;
	struct pdr *p;
	struct far *f;
	struct qer *q;

	list_for_each_entry(p, &s->pdr_list, next) {
		r = p->fwd_rule;
		f = p->far;
		q = p->qer;

		/* no fwd rules */
		if (!r)
			continue;

		/* Update needed ? */
		if (!p->action && (f && !f->action) && (q && !q->action))
			continue;

		r->action = PFCP_ACT_UPDATE;
		pfcp_session_set_fwd_rule(s, p);
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

	/* Update data-path forwarding rules */
	pfcp_session_update_fwd_rules(s);
	return 0;
}

static int
pfcp_session_delete_fwd_rules(struct pfcp_session *s, struct pdr *p)
{
	struct pfcp_fwd_rule *r = p->fwd_rule;

	/* no fwd rules */
	if (!r)
		return -1;

	r->action = PFCP_ACT_DELETE;
	if (r->rule.flags & UPF_FWD_FL_EGRESS) {
		if (p->teid)
			pfcp_bpf_action(s->router, r, p->teid, NULL);
		else if (p->te && p->te->teid)
			pfcp_bpf_action(s->router, r, p->te->teid, NULL);
	} else {
		pfcp_bpf_action(s->router, r, NULL, &s->ue_ip);
	}

	free(r);
	return 0;
}

int
pfcp_session_delete(struct pfcp_session *s)
{
	struct pdr *p, *_p;
	struct far *f, *_f;
	struct qer *q, *_q;
	struct urr *u, *_u;
	struct traffic_endpoint *te, *_te;

	/* Free PDR list */
	list_for_each_entry_safe(p, _p, &s->pdr_list, next) {
		list_head_del(&p->next);
		pfcp_session_delete_fwd_rules(s, p);
		free(p);
	}

	/* Free FAR list */
	list_for_each_entry_safe(f, _f, &s->far_list, next) {
		list_head_del(&f->next);
		free(f);
	}

	/* Free QER list */
	list_for_each_entry_safe(q, _q, &s->qer_list, next) {
		list_head_del(&q->next);
		free(q);
	}

	/* Free URR list */
	list_for_each_entry_safe(u, _u, &s->urr_list, next) {
		list_head_del(&u->next);
		free(u);
	}

	/* Free Traffic Endpoint list */
	list_for_each_entry_safe(te, _te, &s->te_list, next) {
		list_head_del(&te->next);
		free(te);
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

	*ipv4 = NULL;
	*ipv6 = NULL;

	/* Only support a single IPv4+IPv6 per session */
	if (ue_ip->flags & UE_CHV4)
		*ipv4 = v4;

	if (ue_ip->flags & UE_CHV6)
		*ipv6 = v6;

	return 0;
}

int
pfcp_session_put_created_pdr(struct pkt_buffer *pbuff, struct pfcp_session *s)
{
	struct pdr *p;
	uint32_t teid;
	struct in_addr *ipv4;
	struct in6_addr *ipv6;
	int err;

	list_for_each_entry(p, &s->pdr_list, next) {
		pfcp_session_init_teid_values(p->teid, &teid, &ipv4, &ipv6);
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
	int err;

	list_for_each_entry(te, &s->te_list, next) {
		pfcp_session_init_teid_values(te->teid, &teid, &t_ipv4, &t_ipv6);
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
pfcp_session_put_usage_report_deletion(struct pkt_buffer *pbuff, struct pfcp_session *s)
{
	struct urr *u;
	int err;

	list_for_each_entry(u, &s->urr_list, next) {
		u->end_time = time_now_to_ntp();
		err = pfcp_ie_put_usage_report_deletion(pbuff, u->id, u->start_time, u->end_time,
							u->seqn++, &u->ul, &u->dl);
		if (err)
			return -1;
	}

	return 0;
}
