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
#include "pfcp.h"
#include "pfcp_msg.h"
#include "pfcp_router.h"
#include "pfcp_bpf.h"
#include "inet_utils.h"
#include "logger.h"

/* Extern data */
extern struct thread_master *master;



static int
pfcp_session_report_add_urr(struct pkt_buffer *pbuff, struct urr *u,
			    uint32_t query_urr_ref)
{
	struct pfcp_metrics_pkt ul_tmp, dl_tmp;
	uint32_t end_time;
	int err;

	pfcp_metrics_pkt_sub(&u->ul, &u->last_report_ul, &ul_tmp);
	pfcp_metrics_pkt_sub(&u->dl, &u->last_report_dl, &dl_tmp);
	end_time = time_now_to_ntp();

	err = pfcp_ie_put_usage_report_request(pbuff, query_urr_ref, u->id,
					       u->start_time, end_time,
					       u->seqn++, &ul_tmp, &dl_tmp);
	if (err)
		return -1;

	/* update counters */
	u->end_time = end_time;
	u->start_time = time_now_to_ntp();
	pfcp_metrics_pkt_cpy(&u->last_report_ul, &u->ul);
	pfcp_metrics_pkt_cpy(&u->last_report_dl, &u->dl);
	return 0;
}

static void
pfcp_session_report_send(struct thread *t)
{
	struct pfcp_session *s = THREAD_ARG(t);
	struct pfcp_router *r = s->router;
	struct pfcp_server *srv = &r->s;
	struct pfcp_report *report = &s->report;
	struct urr *u;
	struct pkt *p;
	struct pkt_buffer *pbuff;
	struct f_seid *remote_seid = &s->remote_seid;
	int i, err, nr_null = 0, nr_report_urr = 0;

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
	memset(pbuff->head, 0, pkt_buffer_size(pbuff));
	pfcp_msg_header_init(pbuff, PFCP_SESSION_REPORT_REQUEST, remote_seid->id,
			     htonl(srv->seqn++));
	err = pfcp_ie_put_report_type(pbuff, PFCP_IE_REPORT_TYPE_USAR);
	if (err)
		goto end;

	for (i = 0; i < s->nr_urr; i++) {
		u = &s->urr[i];
		if (pfcp_metrics_pkt_cmp(&u->ul, &u->last_report_ul) <= 0 &&
		    pfcp_metrics_pkt_cmp(&u->dl, &u->last_report_dl) <= 0) {
			nr_null++;
			continue;
		}

		err = pfcp_session_report_add_urr(pbuff, u, report->query_urr_ref);
		if (!err)
			nr_report_urr++;
	}

	/* If report is requested but no updates available, then simply use
	 * first urr.
	 */
	if (s->nr_urr && nr_null == s->nr_urr) {
		err = pfcp_session_report_add_urr(pbuff, &s->urr[0],
						  report->query_urr_ref);
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
	inet_server_snd(&srv->s, srv->s.fd, pbuff,
			(struct sockaddr_in *) &report->addr);
end:
	__pkt_queue_put(&srv->pkt_q, p);
}

void
pfcp_session_report(struct pfcp_session *s,
		    struct pfcp_session_modification_request *req,
		    struct sockaddr_storage *addr)
{
	struct pfcp_report *r = &s->report;
	struct pfcp_ie_query_urr_reference *ie_urr_ref = req->query_urr_reference;
	int i;

	/* Requested URR */
	if (req->pfcpsmreq_flags && req->pfcpsmreq_flags->qaurr) {
		for (i = 0; i < PFCP_MAX_NR_ELEM && s->urr[i].id; i++)
			r->urr_id[i] = s->urr[i].id;
	} else {
		for (i = 0; i < PFCP_MAX_NR_ELEM && req->query_urr[i]; i++)
			r->urr_id[i] = req->query_urr[i]->urr_id->value;
	}

	/* Query URR ref */
	r->query_urr_ref = (ie_urr_ref) ? ie_urr_ref->value : 0;

	r->addr = *addr;

	thread_add_event(master, pfcp_session_report_send, s, 0);
}
