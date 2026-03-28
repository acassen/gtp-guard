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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <inttypes.h>
#include <stdint.h>
#include "pfcp_ie.h"
#include "pfcp_session.h"
#include "pfcp.h"
#include "pfcp_msg.h"
#include "pfcp_router.h"
#include "pfcp_bpf.h"
#include "inet_utils.h"
#include "logger.h"

struct pfcp_report {
	struct pfcp_session	*s;
	uint32_t		query_urr_ref;
	struct urr		*urr[PFCP_MAX_NR_ELEM];
	union pfcp_usage_report_trigger rtrig[PFCP_MAX_NR_ELEM];
	int			urr_n;
};

/* Extern data */
extern struct thread_master *master;


static inline int
_put_usage_report(struct pkt_buffer *pbuff, struct urr *u, int type,
		  union pfcp_usage_report_trigger rtrig, uint32_t qurr_ref)
{
	struct pfcp_metrics_pkt ul, dl;
	bool vol = u->measurement_method.volum;

	if (vol) {
		pfcp_metrics_pkt_sub(&u->ul, &u->last_report_ul, &ul);
		pfcp_metrics_pkt_sub(&u->dl, &u->last_report_dl, &dl);
		u->last_report_ul = ul;
		u->last_report_dl = dl;
	}

	return pfcp_ie_put_usage_report(pbuff, type, u->id, u->seqn, rtrig, qurr_ref,
					u->pkt_first_time, u->pkt_last_time,
					u->start_time, u->end_time, u->duration,
					vol ? &ul : NULL, vol ? &dl : NULL);
}

static void
pfcp_session_report_build_and_send(struct pfcp_report *r)
{
	struct pfcp_session *s = r->s;
	struct pfcp_server *srv = &s->router->s;
	struct pkt *p;
	struct pkt_buffer *pbuff;
	struct f_seid *remote_seid = &s->remote_seid;
	int err, i, nr_report_urr = 0;

	p = __pkt_queue_get(&srv->pkt_q);
	if (!p) {
		log_message(LOG_INFO, "%s(): Error getting pkt from queue for server [%s]:%d"
				    , __FUNCTION__
				    , inet_sockaddrtos(&srv->s.addr)
				    , ntohs(inet_sockaddrport(&srv->s.addr)));
		return;
	}

	/* Pkt building */
	pbuff = p->pbuff;
	pfcp_msg_header_init(pbuff, PFCP_SESSION_REPORT_REQUEST, remote_seid->id,
			     htonl(srv->seqn++ << 8));
	err = pfcp_ie_put_report_type(pbuff, PFCP_IE_REPORT_TYPE_USAR);
	if (err)
		goto end;

	for (i = 0; i < r->urr_n; i++) {
		err = _put_usage_report(pbuff, r->urr[i], PFCP_IE_USAGE_REPORT,
					r->rtrig[i], r->query_urr_ref);
		if (!err)
			nr_report_urr++;
	}

	/* Sollicited report, add additional usage infos */
	err = (err) ? : pfcp_ie_put_additional_usage_reports_info(pbuff, false,
								  nr_report_urr);
	if (err) {
		log_message(LOG_INFO, "%s(): Error building report pkt for server [%s]:%d"
				    , __FUNCTION__
				    , inet_sockaddrtos(&srv->s.addr)
				    , ntohs(inet_sockaddrport(&srv->s.addr)));
		goto end;
	}

	/* Run, Baby, Run */
	inet_server_snd(&srv->s, srv->s.fd, pbuff, &s->remote_seid.addr.sin);
end:
	__pkt_queue_put(&srv->pkt_q, p);
}


static void
pfcp_session_report_delayed_cb(struct thread *t)
{
	struct pfcp_report *r = THREAD_ARG(t);

	pfcp_session_report_build_and_send(r);
	free(r);
}


static void
pfcp_session_report_send_delayed(struct pfcp_report *r)
{
	struct pfcp_report *ar;

	ar = malloc(sizeof (*ar));
	*ar = *r;
	thread_add_event(master, pfcp_session_report_delayed_cb, ar, 0);
}


void
pfcp_session_report_triggered(struct pfcp_session *s,
			      struct upf_urr_report_data *urd)
{
	union pfcp_usage_report_trigger rtrig;
	struct urr *urr, *lu;
	uint32_t urr_id;
	struct pfcp_report r = {
		.s = s,
	};
	int i;

	/* who did the trigger ? */
	list_for_each_entry(urr, &s->urr_list, next) {
		if (urr->urr_idx != urd->r.urr_idx)
			continue;

		urr_id = 0;
		rtrig.trigger_flags = 0;

		if ((urd->r.report_flags & UPF_TRIG_FL_VOLTH) &&
		    urr->triggers.volth &&
		    urr->volume_threshold_to != ~0) {
			urr_id = urr->id;
			rtrig.volth = 1;
		}
		if ((urd->r.report_flags & UPF_TRIG_FL_VOLQU) &&
		    urr->triggers.volqu) {
			urr_id = urr->id;
			rtrig.volqu = 1;
		}
		if ((urd->r.report_flags & UPF_TRIG_FL_TIMTH) &&
		    urr->triggers.timth) {
			urr_id = urr->id;
			rtrig.timth = 1;
		}
		if ((urd->r.report_flags & UPF_TRIG_FL_TIMQU) &&
		    urr->triggers.timqu) {
			urr_id = urr->id;
			rtrig.timqu = 1;
		}
		if ((urd->r.report_flags & UPF_TRIG_FL_PERIO) &&
		    urr->triggers.perio) {
			urr_id = urr->id;
			rtrig.perio = 1;
		}

		if (!urr_id)
			continue;

		/* add this urr and linked urrs */
		if (r.urr_n >= PFCP_MAX_NR_ELEM)
			break;
		r.rtrig[r.urr_n] = rtrig;
		r.urr[r.urr_n++] = urr;
		list_for_each_entry(lu, &s->urr_list, next) {
			if (r.urr_n >= PFCP_MAX_NR_ELEM)
				break;
			for (i = 0; i < PFCP_MAX_NR_ELEM && lu->linked_urr_id[i]; i++)
				if (lu->linked_urr_id[i] == urr->id) {
					r.rtrig[r.urr_n].liusa = 1;
					r.urr[r.urr_n++] = lu;
				}
		}
	}

	if (!r.urr_n) {
		printf("%s: did not find triggered urr (urr_idx:%d)\n",
		       __func__, urd->r.urr_idx);
		return;
	}

	pfcp_session_report_build_and_send(&r);
}


/* report usage on session modification request.
 * if pbuff is NULL, then send a separate session report request */
int
pfcp_session_report_put_modification(struct pkt_buffer *pbuff,
				     struct pfcp_session *s,
				     struct pfcp_session_modification_request *req)
{
	struct pfcp_ie_query_urr_reference *ie_urr_ref = req->query_urr_reference;
	union pfcp_usage_report_trigger rtrig = { .immer = 1 };
	struct urr *u;
	int i, err;

	struct pfcp_report r = {
		.s = s,
		.query_urr_ref = ie_urr_ref ? ie_urr_ref->value : 0,
	};

	if (req->pfcpsmreq_flags && req->pfcpsmreq_flags->qaurr) {
		/* Report for all URRs */
		list_for_each_entry(u, &s->urr_list, next) {
			if (pbuff == NULL) {
				if (r.urr_n >= PFCP_MAX_NR_ELEM)
					break;
				r.rtrig[r.urr_n] = rtrig;
				r.urr[r.urr_n++] = u;
			} else {
				err = _put_usage_report(pbuff, u,
							PFCP_IE_USAGE_REPORT_MODIFICATION,
							rtrig,
							r.query_urr_ref);
				if (err)
					return -1;
			}
		}

	} else {
		/* Report for queried and their linked URRs */
		for (i = 0; i < PFCP_MAX_NR_ELEM && req->query_urr[i]; i++) {
			if (pbuff == NULL) {
				list_for_each_entry(u, &s->urr_list, next) {
					if (u->id == req->query_urr[i]->urr_id->value) {
						r.rtrig[r.urr_n] = rtrig;
						r.urr[r.urr_n++] = u;
						break;
					}
				}
			} else {
				err = _put_usage_report(pbuff, u,
							PFCP_IE_USAGE_REPORT_MODIFICATION,
							rtrig,
							r.query_urr_ref);
				if (err)
					return -1;
			}
		}
	}

	if (pbuff == NULL)
		pfcp_session_report_send_delayed(&r);

	return 0;
}


int
pfcp_session_report_put_deletion(struct pkt_buffer *pbuff, struct pfcp_session *s)
{
	union pfcp_usage_report_trigger report_trigger = {
		.immer = 1,
		.termr = 1,
	};
	struct urr *u;
	int err;

	list_for_each_entry(u, &s->urr_list, next) {
		err = _put_usage_report(pbuff, u, PFCP_IE_USAGE_REPORT_DELETION,
					report_trigger, 0);
		if (err)
			return -1;
	}

	return 0;
}
