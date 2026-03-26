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

#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <bpf.h>

#include "pfcp_bpf.h"
#include "pfcp_router.h"
#include "pfcp_session_report.h"
#include "pfcp_teid.h"
#include "gtp_bpf_utils.h"
#include "list_head.h"
#include "addr.h"
#include "logger.h"
#include "table.h"
#include "bpf/lib/upf-def.h"


/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


static void
_log_egress_rule(int action, struct upf_fwd_rule *u, struct pfcp_teid *t, int err)
{
	char gtpu_str[INET6_ADDRSTRLEN];
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char action_str[60] = {};

	if (err)
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);

	if (action == RULE_ADD &&
	    (u->flags & UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) ==
	    UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) {
		snprintf(action_str, sizeof (action_str),
			 "fwd to teid:0x%.8x remote:'%s'",
			 u->gtpu_remote_teid,
			 inet_ntop(AF_INET, &u->gtpu_remote_addr,
				   gtpu_str, INET6_ADDRSTRLEN));
	} else {
		snprintf(action_str, sizeof(action_str), "%s%s",
			 (u->flags & UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER) ? "decap|" : "",
			 (u->flags & UPF_FWD_FL_ACT_FWD) ? "fwd" : "drop");
	}

	log_message(LOG_INFO, "pfcp_bpf: %s%s XDP 'egress' rule "
		    "{local_teid:0x%.8x, local_gtpu:'%s', %s} %s",
		    (err) ? "Error " : "",
		    (action == RULE_ADD) ? "adding" : "deleting",
		    t->id,
		    inet_ntop(AF_INET, &t->ipv4, gtpu_str, INET6_ADDRSTRLEN),
		    action_str,
		    (err) ? errmsg : "");
}

static int
_update_egress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct pfcp_teid *t,
		 __u64 flags)
{
	struct upf_egress_key key = {
		.gtpu_local_teid = htonl(t->id),
		.gtpu_local_addr = t->ipv4.s_addr,
		.gtpu_local_port = htons(GTP_U_PORT),
	};
	int err;

	err = bpf_map__update_elem(r->bpf_data->user_egress, &key, sizeof(key),
				   u, sizeof(*u), flags);
	_log_egress_rule(RULE_ADD, u, t, err);

	return err ? -1 : 0;
}

static int
_delete_egress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct pfcp_teid *t)
{
	struct upf_egress_key key = {
		.gtpu_local_teid = htonl(t->id),
		.gtpu_local_addr = t->ipv4.s_addr,
		.gtpu_local_port = htons(GTP_U_PORT),
	};
	int err = bpf_map__delete_elem(r->bpf_data->user_egress, &key,
				       sizeof(key), 0);
	_log_egress_rule(RULE_DEL, u, t, err);

	return err ? -1 : 0;
}

static int
_log_ingress_rule(int action, int type, struct upf_fwd_rule *u, struct ue_ip_address *ue,
		  int err)
{
	char ue_str[INET6_ADDRSTRLEN];
	char gtpu_str[INET6_ADDRSTRLEN];
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char action_str[60] = {};
	sa_family_t family = 0;

	if (err)
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);

	if (type == UE_IPV4 && ue->flags & UE_IPV4)
		family = AF_INET;

	if (type == UE_IPV6 && ue->flags & UE_IPV6)
		family = AF_INET6;

	if (!family)
		return -1;

	snprintf(action_str, sizeof(action_str), "%s%s",
		 (u->flags & UPF_FWD_FL_ACT_CREATE_OUTER_HEADER) ? "encap|" : "",
		 (u->flags & UPF_FWD_FL_ACT_FWD) ? "fwd" : "drop");

	log_message(LOG_INFO, "pfcp_bpf: %s%s XDP 'ingress' rule "
		    "{ue_ipv%d:'%s', remote_teid:0x%.8x, remote_gtpu:'%s', %s} %s",
		    (err) ? "Error " : "",
		    (action == RULE_ADD) ? "adding" : "deleting",
		    (family == AF_INET) ? 4 : 6,
		    inet_ntop(family, (family == AF_INET) ? (void *)&ue->v4 : (void *)&ue->v6,
			      ue_str, INET6_ADDRSTRLEN),
		    ntohl(u->gtpu_remote_teid),
		    inet_ntop(AF_INET, &u->gtpu_remote_addr, gtpu_str, INET6_ADDRSTRLEN),
		    action_str,
		    (err) ? errmsg : "");

	return 0;
}

static int
_update_ingress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct ue_ip_address *ue,
		     __u64 flags)
{
	struct upf_ingress_key key = {};
	int err = 0, err_cnt = 0;

	if (ue->flags & UE_IPV4) {
		key.flags = UE_IPV4;
		key.ue_addr.ip4 = ue->v4.s_addr;

		err = bpf_map__update_elem(r->bpf_data->user_ingress,
					   &key, sizeof(key),
					   u, sizeof(*u), flags);
		_log_ingress_rule(RULE_ADD, UE_IPV4, u, ue, err);
		err_cnt += (bool) err;
	}

	if (ue->flags & UE_IPV6) {
		key.flags = UE_IPV6;
		memcpy(&key.ue_addr.ip6, &ue->v6, sizeof (ue->v6));

		err = bpf_map__update_elem(r->bpf_data->user_ingress,
					   &key, sizeof(key),
					   u, sizeof(*u), flags);
		_log_ingress_rule(RULE_ADD, UE_IPV6, u, ue, err);
		err_cnt += (bool) err;
	}

	return err_cnt ? -1 : 0;
}

static int
_delete_ingress_rule(struct pfcp_router *r, struct upf_fwd_rule *u, struct ue_ip_address *ue)
{
	struct upf_ingress_key key = {};
	int err = 0, err_cnt = 0;

	if (ue->flags & UE_IPV4) {
		key.flags = UE_IPV4;
		key.ue_addr.ip4 = ue->v4.s_addr;

		err = bpf_map__delete_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key), 0);
		_log_ingress_rule(RULE_DEL, UE_IPV4, u, ue, err);
		err_cnt += (bool) err;
	}

	if (ue->flags & UE_IPV6) {
		key.flags = UE_IPV6;
		memcpy(&key.ue_addr.ip6, &ue->v6, sizeof (ue->v6));

		err = bpf_map__delete_elem(r->bpf_data->user_ingress,
					   &key, sizeof (key), 0);
		_log_ingress_rule(RULE_DEL, UE_IPV6, u, ue, err);
		err_cnt += (bool) err;
	}

	return err_cnt ? -1 : 0;
}

int
pfcp_bpf_action(struct pfcp_router *rtr, struct pfcp_fwd_rule *r,
		struct pfcp_teid *t, struct ue_ip_address *ue)
{
	struct upf_fwd_rule *u = &r->rule;
	int err = -1;

	if (!rtr->bpf_data || !rtr->bpf_data->user_ingress)
		return -1;

	switch (r->action) {
	case PFCP_ACT_CREATE:
		if (u->flags & UPF_FWD_FL_EGRESS)
			err = _update_egress_rule(rtr, u, t, BPF_NOEXIST);
		else if (u->flags & UPF_FWD_FL_INGRESS)
			err = _update_ingress_rule(rtr, u, ue, BPF_NOEXIST);
		break;

	case PFCP_ACT_UPDATE:
		if (u->flags & UPF_FWD_FL_EGRESS)
			err = _update_egress_rule(rtr, u, t, BPF_EXIST);
		else if (u->flags & UPF_FWD_FL_INGRESS)
			err = _update_ingress_rule(rtr, u, ue, BPF_EXIST);
		break;

	case PFCP_ACT_DELETE:
		if (u->flags & UPF_FWD_FL_EGRESS)
			err = _delete_egress_rule(rtr, u, t);
		else if (u->flags & UPF_FWD_FL_INGRESS)
			err = _delete_ingress_rule(rtr, u, ue);
		break;

	default:
		return -1;
	}

	return err;
}


/*************************************************************************/
/* vty */

int
pfcp_bpf_teid_vty(struct vty *vty, struct gtp_bpf_prog *p, int dir,
		  struct ue_ip_address *ue, struct pfcp_teid *t)
{
	struct pfcp_bpf_data *bd = gtp_bpf_prog_tpl_data_get(p, "upf");
	struct upf_egress_key ek = {};
	struct upf_ingress_key ik = {};
	struct upf_urr c = {};
	struct upf_fwd_rule rule;
	int err;

	if (dir == UPF_FWD_FL_EGRESS) {
		ek.gtpu_local_teid = htonl(t->id);
		ek.gtpu_local_addr = t->ipv4.s_addr;
		ek.gtpu_local_port = htons(GTP_U_PORT);

		err = bpf_map__lookup_elem(bd->user_egress, &ek, sizeof(ek),
					   &rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "            no data-plane ?!!%s"
				   , VTY_NEWLINE);
			return -1;
		}
		bpf_map__lookup_elem(bd->upf_urr,
				     &rule.urr_idx, sizeof(rule.urr_idx),
				     &c, sizeof(c), 0);

		vty_out(vty, "            packets:%lld bytes:%lld\n"
			     "            drop:%lld\n"
			   , c.ul.pkt, c.ul.bytes, c.ul.drop_pkt);
		return 0;
	}

	if (dir != UPF_FWD_FL_INGRESS)
		return -1;

	if (ue->flags & UE_IPV4) {
		ik.flags = UE_IPV4;
		ik.ue_addr.ip4 = ue->v4.s_addr;
		err = bpf_map__lookup_elem(bd->user_ingress, &ik, sizeof(ik),
					   &rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "              IPv4 - no data-plane ?!!%s"
				   , VTY_NEWLINE);
		} else {
			bpf_map__lookup_elem(bd->upf_urr,
					     &rule.urr_idx, sizeof(rule.urr_idx),
					     &c, sizeof(c), 0);
			vty_out(vty, "              IPv4 - packets:%lld bytes:%lld\n"
				     "                     drop:%lld\n"
				   , c.dl.pkt, c.dl.bytes, c.dl.drop_pkt);
		}
	}

	if (ue->flags & UE_IPV6) {
		ik.flags = UE_IPV6;
		memcpy(&ik.ue_addr.ip6, &ue->v6, sizeof(ue->v6));
		err = bpf_map__lookup_elem(bd->user_ingress, &ik, sizeof(ik),
					   &rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "              IPv6 - no data-plane ?!!%s"
				   , VTY_NEWLINE);
		} else {
			bpf_map__lookup_elem(bd->upf_urr,
					     &rule.urr_idx, sizeof(rule.urr_idx),
					     &c, sizeof(c), 0);
			vty_out(vty, "              IPv6 - packets:%lld bytes:%lld\n"
				     "                     drop:%lld\n"
				   , c.dl.pkt, c.dl.bytes, c.dl.drop_pkt);
		}
	}

	return 0;
}

static void
pfcp_bpf_vty(struct gtp_bpf_prog *p, void *ud, struct vty *vty,
		int argc, const char **argv)
{
	struct pfcp_bpf_data *bd = ud;
	struct table *tbl;
	struct upf_egress_key ek = {};
	struct upf_ingress_key ik = {};
	struct upf_fwd_rule rule;
	struct upf_urr c = {};
	union addr addr, laddr, addr_ue;
	char buf1[26], buf2[40], buf3[26], action_str[40];
	uint32_t key = 0;
	int err = 0;

	if (!bd->user_ingress || !bd->user_egress)
		return;

	tbl = table_init(6, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "TEID Remote", "UE Endpoint", "GTP-U Remote E.", "GTP-U Local E.",
			 "Packets", "Bytes");

	vty_out(vty, "bpf-program '%s', downlink (ingress):\n", p->name);

	/* Walk hashtab */
	while (!bpf_map__get_next_key(bd->user_ingress, &ik, &ik, sizeof(ik))) {
		err = bpf_map__lookup_elem(bd->user_ingress, &ik, sizeof(ik),
					   &rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "%% error fetching value for "
				"teid_key:0x%.8x (%m)\n", key);
			break;
		}
		bpf_map__lookup_elem(bd->upf_urr,
				     &rule.urr_idx, sizeof(rule.urr_idx),
				     &c, sizeof(c), 0);

		if (ik.flags & UE_IPV4)
			addr_fromip4(&addr_ue, ik.ue_addr.ip4);
		else if (ik.flags & UE_IPV6)
			addr_fromip6b(&addr_ue, ik.ue_addr.ip6.addr);
		addr_fromip4(&addr, rule.gtpu_remote_addr);
		addr_set_port(&addr, ntohs(rule.gtpu_remote_port));
		addr_fromip4(&laddr, rule.gtpu_local_addr);
		addr_set_port(&laddr, ntohs(rule.gtpu_local_port));
		table_add_row_fmt(tbl, "0x%.8x|%s|%s|%s|%lld|%lld",
				  ntohl(rule.gtpu_remote_teid),
				  addr_stringify(&addr_ue, buf2, sizeof (buf2)),
				  addr_stringify(&addr, buf1, sizeof (buf1)),
				  addr_stringify(&laddr, buf3, sizeof (buf3)),
				  c.dl.pkt, c.dl.bytes);
	}
	table_vty_out(tbl, vty);
	table_destroy(tbl);

	tbl = table_init(5, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "TEID Local", "GTP-U Local E.", "Action",
			 "Packets", "Bytes");

	vty_out(vty, "uplink (egress):\n");

	/* Walk hashtab */
	while (!bpf_map__get_next_key(bd->user_egress, &ek, &ek, sizeof(ek))) {
		err = bpf_map__lookup_elem(bd->user_egress, &ek, sizeof(ek),
					   &rule, sizeof(rule), 0);
		if (err) {
			vty_out(vty, "%% error fetching value for "
				"teid_key:0x%.8x (%m)\n", key);
			break;
		}
		bpf_map__lookup_elem(bd->upf_urr,
				     &rule.urr_idx, sizeof(rule.urr_idx),
				     &c, sizeof(c), 0);

		if ((rule.flags & UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) ==
		    UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) {
			snprintf(action_str, sizeof (action_str),
				 "Fwd to teid 0x%08x",
				 ntohl(rule.gtpu_remote_teid));
		} else {
			snprintf(action_str, sizeof(action_str), "Decap");
		}

		addr_fromip4(&addr, ek.gtpu_local_addr);
		addr_set_port(&addr, ntohs(ek.gtpu_local_port));
		table_add_row_fmt(tbl, "0x%.8x|%s|%s|%lld|%lld",
				  ntohl(ek.gtpu_local_teid),
				  addr_stringify(&addr, buf1, sizeof (buf1)),
				  action_str, c.ul.pkt, c.ul.bytes);
	}
	table_vty_out(tbl, vty);
	table_destroy(tbl);
}


/*************************************************************************/
/* urr_ctl syscall */

struct pfcp_bpf_data_thread
{
	struct pfcp_bpf_data	*bd;
	pthread_t		task;
	pthread_cond_t		cond;
	pthread_mutex_t		lock;
	struct list_head	cmd_list;
	bool			run;
};

static int
_thread_urr_ctl(struct pfcp_bpf_data *bd, struct upf_urr_cmd_req *uc)
{
	int ret;

	LIBBPF_OPTS(bpf_test_run_opts, rcfg,
		    .ctx_in = uc,
		    .ctx_size_in = sizeof (*uc));

	ret = bpf_prog_test_run_opts(bd->urr_ctl_prog_fd, &rcfg);
	if (ret) {
		log_message(LOG_INFO, "%s: run bpf failed: %m",
			    __func__);
		return -1;
	}

	return 0;
}

static void *
_thread_main_loop(void *arg)
{
	struct pfcp_bpf_data_thread *th = arg;
	struct list_head tmp_list = LIST_HEAD_INIT(tmp_list);
	struct pfcp_urr_cmd *puc;

	pthread_mutex_lock(&th->lock);
	while (th->run) {
		if (list_empty(&th->cmd_list))
			pthread_cond_wait(&th->cond, &th->lock);
		list_splice_init(&th->cmd_list, &tmp_list);

		pthread_mutex_unlock(&th->lock);
		list_for_each_entry(puc, &tmp_list, clist) {
			_thread_urr_ctl(th->bd, &puc->uc);
		}
		INIT_LIST_HEAD(&tmp_list);
		pthread_mutex_lock(&th->lock);
	}
	pthread_mutex_unlock(&th->lock);

	return NULL;
}

static struct pfcp_bpf_data_thread *
_thread_start(struct pfcp_bpf_data *bd, int cpu)
{
	struct pfcp_bpf_data_thread *th;
	cpu_set_t set;
	int ret;

	th = calloc(1, sizeof (*th));
	if (th == NULL)
		return NULL;

	th->bd = bd;
	pthread_cond_init(&th->cond, NULL);
	pthread_mutex_init(&th->lock, NULL);
	INIT_LIST_HEAD(&th->cmd_list);
	th->run = true;
	ret = pthread_create(&th->task, NULL, _thread_main_loop, th);
	if (ret < 0) {
		log_message(LOG_INFO, "pthread_create: %m");
		free(th);
		return NULL;
	}

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	pthread_setaffinity_np(th->task, sizeof(set), &set);
	return th;
}

struct upf_urr_cmd_req *
pfcp_bpf_urr_alloc_cmd(struct pfcp_session *s)
{
	struct pfcp_urr_cmd *puc;

	puc = calloc(1, sizeof (*puc));
	if (puc == NULL)
		return NULL;
	puc->uc.seid = s->seid;
	puc->uc.request_id = ++s->urr_cmd_next_id;

	return &puc->uc;
}

int
pfcp_bpf_urr_ctl(struct pfcp_session *s, struct upf_urr_cmd_req *uc)
{
	struct pfcp_bpf_data *bd = s->router->bpf_data;
	struct pfcp_bpf_data_thread *th;
	struct pfcp_urr_cmd *puc = (struct pfcp_urr_cmd *)uc;

	if (bd == NULL) {
		free(uc);
		return -1;
	}

	th = bd->ctl_task[s->cpu];
	if (th == NULL) {
		th = _thread_start(bd, s->cpu);
		if (th == NULL) {
			free(uc);
			return -1;
		}
		bd->ctl_task[s->cpu] = th;
	}

	pthread_mutex_lock(&th->lock);
	if (list_empty(&th->cmd_list))
		pthread_cond_signal(&th->cond);
	list_add_tail(&puc->clist, &th->cmd_list);
	pthread_mutex_unlock(&th->lock);

	list_add_tail(&puc->plist, &s->urr_cmd_pending_list);

	return 0;
}

uint32_t
pfcp_bpf_alloc_urr_idx(struct pfcp_session *s)
{
	struct pfcp_bpf_data *bd = s->router->bpf_data;
	int i;

	for (i = 0; i < BPF_UPF_USER_COUNTER_MAP_SIZE; i++) {
		if (++bd->urr_alloc_cur == BPF_UPF_USER_COUNTER_MAP_SIZE)
			bd->urr_alloc_cur = 1;
		if (!bd->urr_alloc[bd->urr_alloc_cur]) {
			bd->urr_alloc[bd->urr_alloc_cur] = 1;
			return bd->urr_alloc_cur;
		}
	}
	return 0;
}

void
pfcp_bpf_release_urr_idx(struct pfcp_session *s, uint32_t urr_idx)
{
	struct pfcp_bpf_data *bd = s->router->bpf_data;

	if (bd != NULL)
		bd->urr_alloc[urr_idx] = 0;
}



/*************************************************************************/
/* ring buffer */

static int
pfcp_bpf_ring_buffer_process(void *ctx, void *data, size_t size)
{
	struct upf_urr_report *ur;
	struct upf_urr_report_data *urd;
	struct pfcp_urr_cmd *puc;
	struct pfcp_session *s;

	if (size == sizeof (*urd)) {
		urd = data;
		ur = data;
	} else if (sizeof (*ur)) {
		ur = data;
	} else {
		log_message(LOG_INFO, "%s: unexpected size: %ld", __func__, size);
		return 0;
	}

	/* get pfcp session */
	s = pfcp_session_get(ur->seid);
	if (s == NULL) {
		log_message(LOG_DEBUG, "%s: report (size:%ld) for unknown seid %lld",
			    __func__, size, ur->seid);
		return 0;
	}

	/* it's a trigger */
	if (!ur->request_id) {
		if (urd != NULL)
			pfcp_session_report_triggered(s, urd);
		return 0;
	}

	/* it's a ack for a previous command */
	list_for_each_entry(puc, &s->urr_cmd_pending_list, plist) {
		if (puc->uc.request_id == ur->request_id) {
			list_del(&puc->plist);
			free(puc);
			goto next;
		}
	}
	log_message(LOG_DEBUG, "urr request_id %d doesn't match any request",
		    ur->request_id);

 next:
	/* no more pending urr command, send reply */
	/* XXX should go elsewhere */
	if (s->pending_pbuff != NULL && list_empty(&s->urr_cmd_pending_list)) {
		struct pkt_buffer *pbuff = s->pending_pbuff;
		struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
		if (pfcph->type == PFCP_SESSION_DELETION_RESPONSE)
			pfcp_session_put_usage_report_deletion(pbuff, s);
		inet_server_snd(&s->router->s.s, s->router->s.s.fd, pbuff,
				&s->pending_addr.sin);
		pkt_buffer_free(pbuff);
		s->pending_pbuff = NULL;
	}

	return 0;
}


static void
pfcp_bpf_ring_buffer_event_cb(struct thread *th)
{
	struct pfcp_bpf_data *bd = THREAD_ARG(th);
	int ret;

	ret = ring_buffer__consume(bd->rbuf);
	if (ret < 0)
		log_message(LOG_INFO, "ring_buffer consume: %m");

	bd->rbuf_th = thread_add_read(master, pfcp_bpf_ring_buffer_event_cb,
				      bd, THREAD_FD(th), TIMER_NEVER, 0);
}


/*************************************************************************/
/* bpf template */

static void *
pfcp_bpf_alloc(struct gtp_bpf_prog *p)
{
	struct pfcp_bpf_data *bd;

	bd = calloc(1, sizeof (*bd));
	if (bd == NULL)
		return NULL;

	bd->urr_alloc = calloc(BPF_UPF_USER_COUNTER_MAP_SIZE, 1);
	bd->ctl_task = calloc(libbpf_num_possible_cpus(),
			      sizeof (*bd->ctl_task));
	if (bd->urr_alloc == NULL || bd->ctl_task == NULL) {
		free(bd);
		return NULL;
	}
	INIT_LIST_HEAD(&bd->pfcp_router_list);

	return bd;
}

static void
pfcp_bpf_release(struct gtp_bpf_prog *p, void *udata)
{
	struct pfcp_bpf_data *bd = udata;
	struct pfcp_router *c, *tmp;
	int nr_cpu = libbpf_num_possible_cpus();
	int i;

	list_for_each_entry_safe(c, tmp, &bd->pfcp_router_list, bpf_list) {
		c->bpf_prog = NULL;
		c->bpf_data = NULL;
		list_del_init(&c->bpf_list);
	}
	for (i = 0; i < nr_cpu; i++) {
		if (bd->ctl_task[i] != NULL) {
			bd->ctl_task[i]->run = false;
			pthread_cond_signal(&bd->ctl_task[i]->cond);
			pthread_join(bd->ctl_task[i]->task, NULL);
			free(bd->ctl_task[i]);
		}
	}
	free(bd->ctl_task);
	free(bd->urr_alloc);
	free(bd);
}


static int
pfcp_bpf_loaded(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct pfcp_bpf_data *bd = udata;
	struct bpf_program *prg;
	struct bpf_map *map;
	int fd;

	bd->user_egress = gtp_bpf_prog_load_map(p->obj_load, "user_egress");
	bd->user_ingress = gtp_bpf_prog_load_map(p->obj_load, "user_ingress");
	bd->upf_urr = gtp_bpf_prog_load_map(p->obj_load, "upf_urr");
	if (bd->user_egress == NULL || bd->user_ingress == NULL ||
	    bd->upf_urr == NULL)
		return -1;

	prg = bpf_object__find_program_by_name(p->obj_load, "urr_ctl");
	if (prg == NULL) {
		log_message(LOG_INFO, "cannot find urr_ctl in ebpf prog");
		return -1;
	}
	bd->urr_ctl_prog_fd = bpf_program__fd(prg);

	map = gtp_bpf_prog_load_map(p->obj_load, "upf_events");
	if (map == NULL)
		return -1;
	fd = bpf_map__fd(map);

	if (reload)
		return 0;

	bd->rbuf = ring_buffer__new(fd, pfcp_bpf_ring_buffer_process, bd, NULL);
	if (bd->rbuf == NULL)
		return -1;
	bd->rbuf_th = thread_add_read(master, pfcp_bpf_ring_buffer_event_cb,
				      bd, fd, TIMER_NEVER, 0);

	return 0;
}

static void
pfcp_bpf_closed(struct gtp_bpf_prog *p, void *udata)
{
	struct pfcp_bpf_data *bd = udata;

	thread_del(bd->rbuf_th);
	bd->rbuf_th = NULL;
	if (bd->rbuf != NULL)
		ring_buffer__free(bd->rbuf);
	bd->rbuf = NULL;
}


static struct gtp_bpf_prog_tpl pfcp_bpf_tpl = {
	.name = "upf",
	.description = "3GPP User Plane Function",
	.alloc = pfcp_bpf_alloc,
	.loaded = pfcp_bpf_loaded,
	.closed = pfcp_bpf_closed,
	.release = pfcp_bpf_release,
	.vty_out = pfcp_bpf_vty,
};

static void __attribute__((constructor))
pfcp_bpf_init(void)
{
	gtp_bpf_prog_tpl_register(&pfcp_bpf_tpl);
}
