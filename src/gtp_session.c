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
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "timer.h"
#include "mpool.h"
#include "vector.h"
#include "command.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "list_head.h"
#include "json_writer.h"
#include "jhash.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_sqn.h"
#include "gtp_xdp.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
static uint32_t gtp_session_id;
static rb_root_cached_t gtp_session_timer = RB_ROOT_CACHED;
RB_TIMER_LESS(gtp_session, n);
pthread_mutex_t gtp_session_timer_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t gtp_session_expiration_task;
pthread_cond_t gtp_session_expiration_cond;
pthread_mutex_t gtp_session_expiration_mutex;


/*
 *	Session handling
 */
static int
__gtp_session_teid_cp_vty(vty_t *vty, list_head_t *l)
{
	gtp_teid_t *t;

	/* Walk the line */
	list_for_each_entry(t, l, next)
		vty_out(vty, "  [CP] vteid:0x%.8x teid:0x%.8x vsqn:0x%.8x sqn:0x%.8x"
			     " ipaddr:%u.%u.%u.%u sGW:%u.%u.%u.%u pGW:%u.%u.%u.%u%s"
			   , t->vid, ntohl(t->id), t->vsqn, t->sqn, NIPQUAD(t->ipv4)
			   , NIPQUAD(t->sgw_addr.sin_addr.s_addr)
			   , NIPQUAD(t->pgw_addr.sin_addr.s_addr)
			   , VTY_NEWLINE);
	return 0;
}

static int
__gtp_session_teid_up_vty(vty_t *vty, list_head_t *l)
{
	gtp_teid_t *t;

	/* Walk the line */
	list_for_each_entry(t, l, next) {
		vty_out(vty, "  [UP] vteid:0x%.8x teid:0x%.8x sqn:0x%.8x bearer-id:0x%.2x remote_ipaddr:%u.%u.%u.%u%s"
			   , t->vid, ntohl(t->id), t->sqn, t->bearer_id, NIPQUAD(t->ipv4)
			   , VTY_NEWLINE);
		if (t->vid)
			gtp_xdpfwd_teid_vty(vty, ntohl(t->vid));
	}
	return 0;
}

int
gtp_session_vty(vty_t *vty, gtp_conn_t *c)
{
	list_head_t *l = &c->gtp_sessions;
	time_t timeout = 0;
	gtp_session_t *s;
	struct tm *t;

	/* Walk the line */
	pthread_mutex_lock(&c->gtp_session_mutex);
	list_for_each_entry(s, l, next) {
		if (timerisset(&s->sands)) {
			timeout = s->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);
		}

		t = &s->creation_time;
		vty_out(vty, " session-id:0x%.8x apn:%s creation:%.2d/%.2d/%.2d-%.2d:%.2d:%.2d expire:%s%s"
			   , s->id, s->apn->name
			   , t->tm_mday, t->tm_mon+1, t->tm_year+1900
			   , t->tm_hour, t->tm_min, t->tm_sec
			   , timerisset(&s->sands) ? s->tmp_str : "never"
			   , VTY_NEWLINE);
		__gtp_session_teid_cp_vty(vty, &s->gtpc_teid);
		__gtp_session_teid_up_vty(vty, &s->gtpu_teid);
	}
	pthread_mutex_unlock(&c->gtp_session_mutex);
	return 0;
}

int
gtp_session_summary_vty(vty_t *vty, gtp_conn_t *c)
{
	list_head_t *l = &c->gtp_sessions;
	time_t timeout = 0;
	gtp_session_t *s;
	gtp_apn_t *apn = NULL;

	/* Walk the line */
	pthread_mutex_lock(&c->gtp_session_mutex);
	list_for_each_entry(s, l, next) {
		if (timerisset(&s->sands)) {
			timeout = s->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);
		}

		if (!apn) {
			vty_out(vty, "| %.15ld | %10s |  session-id:0x%.8x #teid:%.2d expiration:%11s |%s"
				   , c->imsi, s->apn->name, s->id, s->refcnt
				   , timerisset(&s->sands) ? s->tmp_str : "never"
				   , VTY_NEWLINE);
			apn = s->apn;
			continue;
		}

		vty_out(vty, "|                 | %10s |  session-id:0x%.8x #teid:%.2d expiration:%11s |%s"
			   , (apn == s->apn) ? "" : s->apn->name
			   , s->id, s->refcnt
			   , timerisset(&s->sands) ? s->tmp_str : "never"
			   , VTY_NEWLINE);
		apn = s->apn;
	}
	pthread_mutex_unlock(&c->gtp_session_mutex);

	/* Footer */
	vty_out(vty, "+-----------------+------------+--------------------------------------------------------+%s"
		   , VTY_NEWLINE);
	return 0;
}


gtp_teid_t *
gtp_session_gtpu_teid_get_by_sqn(gtp_session_t *s, uint32_t sqn)
{
	gtp_conn_t *c = s->conn;
	list_head_t *l = &s->gtpu_teid;
	gtp_teid_t *t;

	pthread_mutex_lock(&c->gtp_session_mutex);
	list_for_each_entry(t, l, next) {
		if (t->sqn == sqn) {
			pthread_mutex_unlock(&c->gtp_session_mutex);
			return t;
		}
	}

	pthread_mutex_unlock(&c->gtp_session_mutex);
	return NULL;
}

static int
gtp_session_teid_add(gtp_session_t *s, gtp_teid_t *teid, list_head_t *l)
{
	gtp_conn_t *c = s->conn;

	pthread_mutex_lock(&c->gtp_session_mutex);
	list_add_tail(&teid->next, l);
	pthread_mutex_unlock(&c->gtp_session_mutex);

	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

int
gtp_session_gtpc_teid_add(gtp_session_t *s, gtp_teid_t *teid)
{
	return gtp_session_teid_add(s, teid, &s->gtpc_teid);
}

int
gtp_session_gtpu_teid_add(gtp_session_t *s, gtp_teid_t *teid)
{
	return gtp_session_teid_add(s, teid, &s->gtpu_teid);
}

static void
gtp_session_add_timer(gtp_session_t *s)
{
	gtp_apn_t *apn = s->apn;

	if (!apn->session_lifetime)
		return;

	s->sands = timer_add_now_sec(s->sands, apn->session_lifetime);

	/* Sort it by timeval */
	pthread_mutex_lock(&gtp_session_timer_mutex);
	rb_add_cached(&s->n, &gtp_session_timer, gtp_session_timer_less);
	pthread_mutex_unlock(&gtp_session_timer_mutex);
}

gtp_session_t *
gtp_session_alloc(gtp_conn_t *c, gtp_apn_t *apn)
{
	gtp_session_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->gtpc_teid);
	INIT_LIST_HEAD(&new->gtpu_teid);
	INIT_LIST_HEAD(&new->next);
	new->apn = apn;
	new->conn = c;
	time_now_to_calendar(&new->creation_time);
	/* This is a local session id, simply monotonically incremented */
	__sync_add_and_fetch(&gtp_session_id, 1);
	new->id = gtp_session_id;

	pthread_mutex_lock(&c->gtp_session_mutex);
	list_add_tail(&new->next, &c->gtp_sessions);
	pthread_mutex_unlock(&c->gtp_session_mutex);

	gtp_session_add_timer(new);

	return new;
}


static int
__gtp_session_gtpc_teid_destroy(gtp_ctx_t *ctx, gtp_teid_t *teid)
{
	gtp_session_t *s = teid->session;

	list_head_del(&teid->next);
	gtp_vteid_unhash(&ctx->vteid_tab, teid);
	gtp_teid_unhash(&ctx->gtpc_teid_tab, teid);
	gtp_vsqn_unhash(&ctx->vsqn_tab, teid);

	FREE(teid);
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

int
gtp_session_gtpc_teid_destroy(gtp_ctx_t *ctx, gtp_teid_t *teid)
{
	gtp_session_t *s = teid->session;
	gtp_conn_t *c = s->conn;

	pthread_mutex_lock(&c->gtp_session_mutex);
	__gtp_session_gtpc_teid_destroy(ctx, teid);
	pthread_mutex_unlock(&c->gtp_session_mutex);
	return 0;
}

static int
__gtp_session_gtpu_teid_destroy(gtp_ctx_t *ctx, gtp_teid_t *teid)
{
	gtp_session_t *s = teid->session;

	list_head_del(&teid->next);
	gtp_vteid_unhash(&ctx->vteid_tab, teid);
	gtp_teid_unhash(&ctx->gtpu_teid_tab, teid);

	/* Fast-Path cleanup */
	gtp_xdpfwd_teid_action(XDPFWD_RULE_DEL, teid, 0);

	FREE(teid);
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

int
gtp_session_gtpu_teid_destroy(gtp_ctx_t *ctx, gtp_teid_t *teid)
{
	gtp_session_t *s = teid->session;
	gtp_conn_t *c = s->conn;

	pthread_mutex_lock(&c->gtp_session_mutex);
	__gtp_session_gtpu_teid_destroy(ctx, teid);
	pthread_mutex_unlock(&c->gtp_session_mutex);
	return 0;
}

static int
__gtp_session_teid_destroy(gtp_ctx_t *ctx, gtp_session_t *s)
{
	gtp_teid_t *t, *_t;

	/* Release control plane */
	list_for_each_entry_safe(t, _t, &s->gtpc_teid, next) {
		__gtp_session_gtpc_teid_destroy(ctx, t);
		/* FIXME: refcnt playground here */
	}

	/* Release data plane */
	list_for_each_entry_safe(t, _t, &s->gtpu_teid, next) {
		__gtp_session_gtpu_teid_destroy(ctx, t);
		/* FIXME: refcnt playground here */
	}

	return 0;
}

static int
__gtp_session_destroy(gtp_ctx_t *ctx, gtp_session_t *s)
{
	gtp_conn_t *c = s->conn;

	pthread_mutex_lock(&c->gtp_session_mutex);

	/* Release teid */
	__gtp_session_teid_destroy(ctx, s);

	/* Release session */
	list_head_del(&s->next);
	FREE(s);

	/* Release connection if no more sessions */
	if (list_empty(&c->gtp_sessions)) {
		log_message(LOG_INFO, "IMSI:%ld - no more sessions - Releasing tracking", c->imsi);
		gtp_conn_unhash(c);
		pthread_mutex_unlock(&c->gtp_session_mutex);
		FREE(c);
		return 0;
	}

	pthread_mutex_unlock(&c->gtp_session_mutex);
	return 0;
}

int
gtp_session_destroy(gtp_ctx_t *ctx, gtp_session_t *s)
{
	if (timerisset(&s->sands))
		return gtp_session_expire_now(s);

	return __gtp_session_destroy(ctx, s);
}

int
gtp_session_set_delete_bearer(gtp_ctx_t *ctx, gtp_session_t *s, gtp_ie_eps_bearer_id_t *ebi)
{
	gtp_conn_t *c = s->conn;
	gtp_teid_t *t;

	pthread_mutex_lock(&c->gtp_session_mutex);
	list_for_each_entry(t, &s->gtpu_teid, next) {
		if ((ebi->h.instance == 0) ||
		    (ebi->h.instance == 1 && t->bearer_id == ebi->id))
			t->action = GTP_ACTION_DELETE_BEARER;
	}
	pthread_mutex_unlock(&c->gtp_session_mutex);

	return 0;
}

int
gtp_session_destroy_bearer(gtp_ctx_t *ctx, gtp_session_t *s)
{
	gtp_conn_t *c = s->conn;
	gtp_teid_t *t, *_t;
	bool destroy_session = false;

	pthread_mutex_lock(&c->gtp_session_mutex);
	list_for_each_entry_safe(t, _t, &s->gtpu_teid, next) {
		if (t->action == GTP_ACTION_DELETE_BEARER) {
			__gtp_session_gtpu_teid_destroy(ctx, t);
		}
	}

	if (list_empty(&s->gtpc_teid) && list_empty(&s->gtpu_teid))
		destroy_session = true;
	pthread_mutex_unlock(&c->gtp_session_mutex);

	if (destroy_session)
		return gtp_session_destroy(ctx, s);

	return 0;
}


/*
 *	Session expiration handling
 */
int
gtp_session_expire_now(gtp_session_t *s)
{
	pthread_mutex_lock(&gtp_session_timer_mutex);
	rb_erase_cached(&s->n, &gtp_session_timer);
	gettimeofday(&s->sands, NULL);
	rb_add_cached(&s->n, &gtp_session_timer, gtp_session_timer_less);
	pthread_mutex_unlock(&gtp_session_timer_mutex);

	pthread_mutex_lock(&gtp_session_expiration_mutex);
	pthread_cond_signal(&gtp_session_expiration_cond);
	pthread_mutex_unlock(&gtp_session_expiration_mutex);
	return 0;
}

static int
__gtp_session_expire(gtp_session_t *s)
{
	gtp_conn_t *c = s->conn;
	gtp_ctx_t *ctx = c->ctx;

	log_message(LOG_INFO, "IMSI:%ld - Expiring sesion-id:%ld"
			    , s->conn->imsi, s->id);

	rb_erase_cached(&s->n, &gtp_session_timer);
	__gtp_session_destroy(ctx, s);
	return 0;
}

static int
gtp_sessions_release(gtp_conn_t *c)
{
	list_head_t *l = &c->gtp_sessions;
	gtp_session_t *s, *_s;

	/* Release sessions */
	pthread_mutex_lock(&c->gtp_session_mutex);
	list_for_each_entry_safe(s, _s, l, next) {
		gtp_session_expire_now(s);
	}
	pthread_mutex_unlock(&c->gtp_session_mutex);

	return 0;
}

static void
gtp_sessions_expire(timeval_t *now)
{
	gtp_session_t *s;
	rb_node_t *s_node;

	pthread_mutex_lock(&gtp_session_timer_mutex);
	while ((s_node = rb_first_cached(&gtp_session_timer))) {
		s = rb_entry(s_node, gtp_session_t, n);

		if (timercmp(now, &s->sands, <))
			break;

		__gtp_session_expire(s);
	}
	pthread_mutex_unlock(&gtp_session_timer_mutex);
}

void *
gtp_sessions_task(void *arg)
{
	struct timespec timeout;
	timeval_t now;

        /* Our identity */
        prctl(PR_SET_NAME, "session_expiration", 0, 0, 0, 0);

  session_process:
	/* Schedule interruptible timeout */
	pthread_mutex_lock(&gtp_session_expiration_mutex);
	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + 1;
	timeout.tv_nsec = now.tv_usec * 1000;
	pthread_cond_timedwait(&gtp_session_expiration_cond, &gtp_session_expiration_mutex, &timeout);
	pthread_mutex_unlock(&gtp_session_expiration_mutex);

	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		goto session_finish;

	/* Expiration handling */
	gtp_sessions_expire(&now);

	goto session_process;

  session_finish:
	return NULL;
}

static int
gtp_sessions_signal(void)
{
	pthread_mutex_lock(&gtp_session_expiration_mutex);
	pthread_cond_signal(&gtp_session_expiration_cond);
	pthread_mutex_unlock(&gtp_session_expiration_mutex);
	return 0;
}


/*
 *	Session tracking init
 */
int
gtp_sessions_init(void)
{
	pthread_mutex_init(&gtp_session_expiration_mutex, NULL);
	pthread_cond_init(&gtp_session_expiration_cond, NULL);
	pthread_create(&gtp_session_expiration_task, NULL, gtp_sessions_task, NULL);
	return 0;
}

int
gtp_sessions_destroy(void)
{
	gtp_sessions_signal();
	pthread_join(gtp_session_expiration_task, NULL);
	pthread_mutex_destroy(&gtp_session_expiration_mutex);
	pthread_cond_destroy(&gtp_session_expiration_cond);
	return 0;
}


/*
 *	VTY Command
 */
DEFUN(show_gtp_session,
      show_gtp_session_cmd,
      "show gtp session [INTEGER]",
      SHOW_STR
      "GTP related informations\n"
      "GTP Session tracking\n"
      "IMSI to look for\n")
{
	uint64_t imsi = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing argument, IMSI needed%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	imsi = strtoull(argv[0], NULL, 10);
	gtp_conn_vty(vty, gtp_session_vty, imsi);
	return CMD_SUCCESS;
}

DEFUN(show_gtp_session_summary,
      show_gtp_session_summary_cmd,
      "show gtp session-summary",
      SHOW_STR
      "GTP related informations\n"
      "GTP Session summary\n")
{
	/* Header */
	vty_out(vty, "+-----------------+------------+--------------------------------------------------------+%s"
		     "|      IMSI       |    APN     |                GTP Session Informations                |%s"
		     "+-----------------+------------+--------------------------------------------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	gtp_conn_vty(vty, gtp_session_summary_vty, 0);
	return CMD_SUCCESS;
}

DEFUN(clear_gtp_session,
      clear_gtp_session_cmd,
      "clear gtp session [INTEGER]",
      "Clear GTP related\n"
      "GTP session\n"
      "GTP Session\n"
      "IMSI\n")
{
	uint64_t imsi = 0;
	gtp_conn_t *c;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	imsi = strtoull(argv[0], NULL, 10);
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		vty_out(vty, "%% unknown imsi:%ld%s", imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_sessions_release(c);
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_sessions_vty_init(void)
{
	/* Install show commands */
	install_element(VIEW_NODE, &show_gtp_session_cmd);
	install_element(VIEW_NODE, &show_gtp_session_summary_cmd);
	install_element(ENABLE_NODE, &show_gtp_session_cmd);
	install_element(ENABLE_NODE, &show_gtp_session_summary_cmd);
	install_element(ENABLE_NODE, &clear_gtp_session_cmd);

	return 0;
}
