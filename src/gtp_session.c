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

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
static uint32_t gtp_session_id;
static void gtp_session_expire(thread_ref_t);


/*
 *	GTP Sessions tracking
 */
static int gtp_sessions_count = 0;

int
gtp_sessions_count_read(void)
{
	return gtp_sessions_count;
}


/*
 *	Session handling
 */
gtp_teid_t *
gtp_session_gtpu_teid_get_by_sqn(gtp_session_t *s, uint32_t sqn)
{
	list_head_t *l = &s->gtpu_teid;
	gtp_teid_t *t;

	list_for_each_entry(t, l, next) {
		if (t->sqn == sqn)
			return t;
	}

	return NULL;
}

static int
gtp_session_teid_del(gtp_session_t *s, gtp_teid_t *teid)
{
	if (!__test_and_clear_bit(GTP_TEID_FL_LINKED, &teid->flags)) {
		log_message(LOG_INFO, "%s(): TEID:0x%.8x already unlinked from session:0x%.8x!!!"
				    , __FUNCTION__, ntohl(teid->id), s->id);
		return -1;
	}

	list_head_del(&teid->next);
	__sync_sub_and_fetch(&teid->refcnt, 1);
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
gtp_session_teid_add(gtp_session_t *s, gtp_teid_t *teid, list_head_t *l)
{
	if (__test_and_set_bit(GTP_TEID_FL_LINKED, &teid->flags)) {
		log_message(LOG_INFO, "%s(): TEID:0x%.8x already linked to session:0x%.8x !!!"
			    , __FUNCTION__, ntohl(teid->id), s->id);
		return -1;
	}

	list_add_tail(&teid->next, l);
	__sync_add_and_fetch(&teid->refcnt, 1);
	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

int
gtp_session_gtpc_teid_add(gtp_session_t *s, gtp_teid_t *teid)
{
	return gtp_session_teid_add(s, teid, &s->gtpc_teid);
}

static void
gtp_session_gtu_teid_xdp_rule_add(gtp_teid_t *teid)
{
	int err = -1;

	if (__test_bit(GTP_TEID_FL_FWD, &teid->flags))
		err = gtp_bpf_fwd_teid_action(RULE_ADD, teid);
	else if (__test_bit(GTP_TEID_FL_RT, &teid->flags))
		err = gtp_bpf_rt_teid_action(RULE_ADD, teid);

	if (!err)
		__set_bit(GTP_TEID_FL_XDP_SET, &teid->flags);
}

int
gtp_session_gtpu_teid_add(gtp_session_t *s, gtp_teid_t *teid)
{
	if (__test_and_clear_bit(GTP_TEID_FL_XDP_DELAYED, &teid->flags))
		goto end;

	/* Fast-Path setup */
	gtp_session_gtu_teid_xdp_rule_add(teid);

  end:
	return gtp_session_teid_add(s, teid, &s->gtpu_teid);
}

int
gtp_session_gtpu_teid_xdp_add(gtp_session_t *s)
{
	list_head_t *l = &s->gtpu_teid;
	gtp_teid_t *teid;

	/* Fast-Path setup */
	list_for_each_entry(teid, l, next) {
		if (__test_bit(GTP_TEID_FL_XDP_SET, &teid->flags))
			continue;

		gtp_session_gtu_teid_xdp_rule_add(teid);
	}

	return 0;
}

void
gtp_session_mod_timer(gtp_session_t *s, int timeout)
{
	thread_del_timer(s->timer);
	s->timer = thread_add_timer(master, gtp_session_expire, s
					  , timeout * TIMER_HZ);
}

static void
gtp_session_add_timer(gtp_session_t *s)
{
	gtp_apn_t *apn = s->apn;

	if (!apn->session_lifetime)
		return;

	/* Sort it by timeval */
	gtp_session_mod_timer(s, apn->session_lifetime);
}

static int
gtp_session_add(gtp_conn_t *c, gtp_session_t *s)
{
	list_add_tail(&s->next, &c->gtp_sessions);
	__sync_add_and_fetch(&c->refcnt, 1);
	__sync_add_and_fetch(&gtp_sessions_count, 1);

	return 0;
}

const char *
gtp_session_roaming_status_str(gtp_session_t *s)
{
	if (__test_bit(GTP_SESSION_FL_HPLMN, &s->flags))
		return "HPLMN";

	if (__test_bit(GTP_SESSION_FL_ROAMING_OUT, &s->flags))
		return "Roaming-OUT";

	if (__test_bit(GTP_SESSION_FL_ROAMING_IN, &s->flags))
		return "Roaming-IN";

	return "unknown";
}

int
gtp_session_roaming_status_set(gtp_session_t *s)
{
	gtp_conn_t *c = s->conn;
	gtp_apn_t *apn = s->apn;
	list_head_t *l = &apn->hplmn;
	gtp_plmn_t *p, *splmn = &s->serving_plmn;
	uint8_t imsi[8] = {};
	int ret;

	/* reset previous status */
	__clear_bit(GTP_SESSION_FL_HPLMN, &s->flags);
	__clear_bit(GTP_SESSION_FL_ROAMING_OUT, &s->flags);
	__clear_bit(GTP_SESSION_FL_ROAMING_IN, &s->flags);

	ret = int64_to_bcd_swap(c->imsi, imsi, 8);
	if (ret < 0)
		return -1;

	if (bcd_imsi_plmn_match(imsi, splmn->plmn)) {
		__set_bit(GTP_SESSION_FL_HPLMN, &s->flags);
		return 0;
	}

	list_for_each_entry(p, l, next) {
		if (bcd_imsi_plmn_match(imsi, p->plmn)) {
			__set_bit(GTP_SESSION_FL_ROAMING_OUT, &s->flags);
			return 0;
		}
	}

	__set_bit(GTP_SESSION_FL_ROAMING_IN, &s->flags);
	return 0;
}

gtp_session_t *
gtp_session_alloc(gtp_conn_t *c, gtp_apn_t *apn,
		  int (*gtpc_destroy) (gtp_teid_t *), int (*gtpu_destroy) (gtp_teid_t *))
{
	gtp_session_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->gtpc_teid);
	INIT_LIST_HEAD(&new->gtpu_teid);
	INIT_LIST_HEAD(&new->next);
	new->apn = apn;
	new->conn = c;
	new->gtpc_teid_destroy = gtpc_destroy;
	new->gtpu_teid_destroy = gtpu_destroy;
	time_now_to_calendar(&new->creation_time);
	/* This is a local session id, simply monotonically incremented */
	__sync_add_and_fetch(&gtp_session_id, 1);
	new->id = gtp_session_id;

	/* CDR context */
	if (apn->cdr_spool)
		new->cdr = gtp_cdr_alloc();

	gtp_session_add(c, new);
	gtp_session_add_timer(new);
	__sync_add_and_fetch(&apn->session_count, 1);
	return new;
}


int
gtp_session_gtpc_teid_destroy(gtp_teid_t *teid)
{
	gtp_session_t *s;

	if (!teid)
		return -1;

	s = teid->session;
	(*s->gtpc_teid_destroy) (teid);
	if (gtp_session_teid_del(s, teid) < 0)
		return -1;

	gtp_teid_free(teid);
	return 0;
}

int
gtp_session_gtpu_teid_destroy(gtp_teid_t *teid)
{
	gtp_session_t *s;

	if (!teid)
		return -1;

	s = teid->session;
	(*s->gtpu_teid_destroy) (teid);
	if (gtp_session_teid_del(s, teid) < 0)
		return -1;

	/* Fast-Path cleanup */
	if (!__test_bit(GTP_TEID_FL_XDP_SET, &teid->flags))
		goto end;

	/* cdr volume update from bpf counters */
	gtp_cdr_volumes_update_from_bpf(teid);

	/* release bpf ruleset */
	if (__test_bit(GTP_TEID_FL_FWD, &teid->flags))
		gtp_bpf_fwd_teid_action(RULE_DEL, teid);
	else if (__test_bit(GTP_TEID_FL_RT, &teid->flags))
		gtp_bpf_rt_teid_action(RULE_DEL, teid);

  end:
	gtp_teid_free(teid);
	return 0;
}

static int
gtp_session_teid_destroy(gtp_session_t *s)
{
	gtp_teid_t *t, *_t;

	/* Release control plane */
	list_for_each_entry_safe(t, _t, &s->gtpc_teid, next)
		gtp_session_gtpc_teid_destroy(t);

	/* Release data plane */
	list_for_each_entry_safe(t, _t, &s->gtpu_teid, next)
		gtp_session_gtpu_teid_destroy(t);

	return 0;
}

static int
gtp_session_send_delete_bearer(gtp_session_t *s)
{
	gtp_teid_t *t;

	list_for_each_entry(t, &s->gtpc_teid, next) {
		if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags))
			continue;

		gtpc_send_delete_bearer_request(t);
	}

	return 0;
}

static int
gtp_session_free(gtp_session_t *s)
{
	__sync_sub_and_fetch(&s->apn->session_count, 1);
	__sync_sub_and_fetch(&gtp_sessions_count, 1);
	gtp_session_teid_destroy(s);
	gtp_apn_cdr_commit(s->apn, s->cdr);
	spppoe_destroy(s->s_pppoe);
	list_head_del(&s->next);
	FREE(s);
	return 0;
}

int
gtp_session_destroy(gtp_session_t *s)
{
	gtp_conn_t *c = s->conn;

	thread_del_timer(s->timer);

	/* Send Delete-Bearer-Request if needed */
	if (s->action == GTP_ACTION_SEND_DELETE_BEARER_REQUEST)
		gtp_session_send_delete_bearer(s);

	gtp_session_free(s);

	/* Release connection if no more sessions */
	if (__sync_sub_and_fetch(&c->refcnt, 1) == 0) {
		gtp_conn_unhash(c);
		log_message(LOG_INFO, "IMSI:%ld - no more sessions - Releasing tracking"
				    , c->imsi);
		FREE(c);
	}

	return 0;
}

int
gtp_session_set_delete_bearer(gtp_session_t *s, gtp_ie_eps_bearer_id_t *ebi)
{
	gtp_teid_t *t;

	list_for_each_entry(t, &s->gtpu_teid, next) {
		if ((ebi->h.instance == 0) ||
		    (ebi->h.instance == 1 && t->bearer_id == ebi->id))
			t->action = GTP_ACTION_DELETE_BEARER;
	}

	return 0;
}

int
gtp_session_destroy_bearer(gtp_session_t *s)
{
	gtp_teid_t *t, *_t;

	list_for_each_entry_safe(t, _t, &s->gtpc_teid, next) {
		if (t->bearer_teid && t->bearer_teid->action == GTP_ACTION_DELETE_BEARER) {
			gtp_session_gtpc_teid_destroy(t);
		}
	}

	list_for_each_entry_safe(t, _t, &s->gtpu_teid, next) {
		if (t->action == GTP_ACTION_DELETE_BEARER) {
			gtp_session_gtpu_teid_destroy(t);
		}
	}

	if (__sync_sub_and_fetch(&s->refcnt, 0) == 0)
		return gtp_session_destroy(s);

	return 0;
}

int
gtp_session_destroy_teid(gtp_teid_t *teid)
{
	gtp_teid_t *bteid;
	gtp_session_t *s;

	if (!teid)
		return -1;

	s = teid->session;
	gtp_session_gtpc_teid_destroy(teid);
	gtp_session_gtpc_teid_destroy(teid->peer_teid);
	bteid = teid->bearer_teid;
	if (bteid) {
		gtp_session_gtpu_teid_destroy(bteid);
		gtp_session_gtpu_teid_destroy(bteid->peer_teid);
	}

	if (__sync_sub_and_fetch(&s->refcnt, 0) == 0)
		gtp_session_destroy(s);

	return 0;
}

int
gtp_session_uniq_ptype(gtp_conn_t *c, uint8_t ptype)
{
	gtp_session_t *s;
	int err = 0;

	list_for_each_entry(s, &c->gtp_sessions, next) {
		if (s->ptype != ptype)
			continue;

		s->action = GTP_ACTION_SEND_DELETE_BEARER_REQUEST;
		gtp_session_destroy(s);
		err = -1;
	}

	return err;
}


/*
 *	Session expiration handling
 */
static void
gtp_session_expire(thread_ref_t thread)
{
	gtp_session_t *s = THREAD_ARG(thread);

	log_message(LOG_INFO, "IMSI:%ld - Expiring session-id:0x%.8x"
			    , s->conn->imsi, s->id);
	gtp_session_destroy(s);
}

int
gtp_sessions_release(gtp_conn_t *c)
{
	list_head_t *l = &c->gtp_sessions;
	gtp_session_t *s, *_s;

	/* Release sessions */
	list_for_each_entry_safe(s, _s, l, next)
		gtp_session_destroy(s);

	return 0;
}

int
gtp_sessions_free(gtp_conn_t *c)
{
	list_head_t *l = &c->gtp_sessions;
	gtp_session_t *s, *_s;

	list_for_each_entry_safe(s, _s, l, next) {
		thread_del_timer(s->timer);
		gtp_session_free(s);
	}

	return 0;
}


/*
 *	Session tracking init
 */
int
gtp_sessions_init(void)
{
	return 0;
}

int
gtp_sessions_destroy(void)
{
	return 0;
}
