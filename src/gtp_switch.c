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
#include "list_head.h"
#include "json_writer.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_if.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_handle.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Worker
 */
static ssize_t
gtp_switch_udp_recvfrom(gtp_srv_worker_t *w, struct sockaddr *addr, socklen_t *addrlen)
{
	return recvfrom(w->fd, w->buffer, GTP_BUFFER_SIZE, 0, addr, addrlen);
}

static int
gtp_switch_udp_init(gtp_srv_t *srv)
{
	struct sockaddr_storage *addr = &srv->addr;
	socklen_t addrlen;
	int fd, err;

	/* Create UDP Listener */
	fd = socket(addr->ss_family, SOCK_DGRAM, 0);
	fd = (fd < 0) ? fd : if_setsockopt_reuseaddr(fd, 1);
	fd = (fd < 0) ? fd : if_setsockopt_reuseport(fd, 1);
	fd = (fd < 0) ? fd : if_setsockopt_rcvtimeo(fd, 1000);
	fd = (fd < 0) ? fd : if_setsockopt_sndtimeo(fd, 1000);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): error creating UDP [%s]:%d socket"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		goto socket_error;
	}

        /* Bind listening channel */
        addrlen = (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
                                                 sizeof(struct sockaddr_in6);
        err = bind(fd, (struct sockaddr *) addr, addrlen);
        if (err < 0) {
                log_message(LOG_INFO, "%s(): Error binding to [%s]:%d (%m)"
				    , __FUNCTION__
                		    , inet_sockaddrtos(addr)
                		    , ntohs(inet_sockaddrport(addr)));
                goto socket_error;
        }

	return fd;

  socket_error:
	return -1;
}

static int
gtp_switch_udp_fwd(gtp_srv_worker_t *w, int fd, struct sockaddr_in *addr)
{
	return sendto(fd, w->buffer, w->buffer_size, 0, addr, sizeof(*addr));
}

static struct sockaddr_in *
gtp_switch_fwd_addr_get(gtp_teid_t *teid, struct sockaddr_storage *addr)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;

	if (addr4->sin_addr.s_addr == teid->sgw_addr.sin_addr.s_addr)
		return &teid->pgw_addr;

	return &teid->sgw_addr;
}

static void *
gtp_switch_worker_task(void *arg)
{
	gtp_srv_worker_t *w = arg;
	gtp_srv_t *srv = w->srv;
	struct sockaddr_storage *addr = &srv->addr;
	struct sockaddr_storage addr_from;
	struct sockaddr_in *addr_to;
	socklen_t addrlen = sizeof(addr_from);
	gtp_teid_t *teid;
	gtp_ctx_t *ctx = srv->ctx;
	char pname[128];
	const char *ptype;
	int fd;

	/* Create Process Name */
	ptype = (__test_bit(GTP_FL_INGRESS_BIT, &srv->flags)) ? "in" : "out";
	if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
		ptype = "upf";
	snprintf(pname, 127, "%s-%s-%d"
		      , ctx->name
		      , ptype
		      , w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

	/* Create UDP Listener */
	fd = gtp_switch_udp_init(srv);
        if (fd < 0) {
                log_message(LOG_INFO, "%s(): %s: Error creating GTP on [%s]:%d"
				    , __FUNCTION__
				    , pname
                		    , inet_sockaddrtos(addr)
                		    , ntohs(inet_sockaddrport(addr)));
		return NULL;
        }

	/* So far so good */
	w->fd = fd;
	__set_bit(GTP_FL_RUNNING_BIT, &w->flags);

	/* Infinita tristessa */
	for (;;) {
		/* Perform ingress packet handling */
		w->buffer_size = gtp_switch_udp_recvfrom(w, (struct sockaddr *) &addr_from
							  , &addrlen);
		if (w->buffer_size == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			log_message(LOG_INFO, "%s(): %s: Error recv (%m). Exiting"
					    , __FUNCTION__
					    , pname);
			goto end;
		}

		/* GTP-U handling */
		if (__test_bit(GTP_FL_UPF_BIT, &srv->flags)) {
			teid = gtpu_handle(w, &addr_from);
			if (!teid)
				continue;

			gtp_switch_udp_fwd(w, w->fd, (struct sockaddr_in *) &addr_from);
			continue;
		}

		/* GTP-C handling */
		teid = gtpc_handle(w, &addr_from);
		if (!teid)
			continue;

		/* Set destination address */
		addr_to = gtp_switch_fwd_addr_get(teid, &addr_from);
		gtp_switch_udp_fwd(w, (teid->type == 0xff) ? w->fd : w->fwd->fd
				    , (teid->type == 0xff) ? (struct sockaddr_in *) &addr_from :
					 		     addr_to);

		gtpc_handle_post(w, teid);
	}

  end:
	close(fd);
	return NULL;
}


/*
 *	UDP listener init
 */
static gtp_srv_worker_t *
gtp_switch_worker_get(gtp_srv_t *srv)
{
	gtp_srv_worker_t *worker = NULL;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(worker, &srv->workers, next) {
		if (__test_bit(GTP_FL_STARTING_BIT, &worker->flags))
			continue;

		__set_bit(GTP_FL_STARTING_BIT, &worker->flags);
		pthread_mutex_unlock(&srv->workers_mutex);
		return worker;
	}
	pthread_mutex_unlock(&srv->workers_mutex);
	
	return NULL;
}

int
gtp_switch_worker_bind(gtp_ctx_t *ctx)
{
	gtp_srv_t *ingress = &ctx->gtpc_ingress;
	gtp_srv_t *egress = &ctx->gtpc_egress;
	gtp_srv_worker_t *iw, *ew;

	if (!(__test_bit(GTP_FL_RUNNING_BIT, &ingress->flags) &&
	      __test_bit(GTP_FL_RUNNING_BIT, &egress->flags)))
	    return -1;

	ingress->ctx = ctx;
	egress->ctx = ctx;
	pthread_mutex_lock(&ingress->workers_mutex);
	list_for_each_entry(iw, &ingress->workers, next) {
		if (!__test_and_set_bit(GTP_FL_STARTING_BIT, &iw->flags)) {
			ew = gtp_switch_worker_get(egress);
			iw->fwd = ew;
			ew->fwd = iw;
		}

	}
	pthread_mutex_unlock(&ingress->workers_mutex);

	return 0;
}

int
gtp_switch_worker_launch(gtp_srv_t *srv)
{
	gtp_srv_worker_t *worker;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(worker, &srv->workers, next) {
		pthread_create(&worker->task, NULL, gtp_switch_worker_task, worker);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

int
gtp_switch_worker_start(gtp_ctx_t *ctx)
{
	gtp_srv_t *ingress = &ctx->gtpc_ingress;
	gtp_srv_t *egress = &ctx->gtpc_egress;

	if (!(__test_bit(GTP_FL_RUNNING_BIT, &ingress->flags) &&
	      __test_bit(GTP_FL_RUNNING_BIT, &egress->flags)))
	    return -1;

	gtp_switch_worker_launch(ingress);
	gtp_switch_worker_launch(egress);

	return 0;
}

static int
gtp_switch_worker_alloc(gtp_srv_t *srv, int id)
{
	gtp_srv_worker_t *worker;

	PMALLOC(worker);
	INIT_LIST_HEAD(&worker->next);
	worker->srv = srv;
	worker->id = id;
	worker->seed = time(NULL);
	srand(worker->seed);

	pthread_mutex_lock(&srv->workers_mutex);
	list_add_tail(&worker->next, &srv->workers);
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

int
gtp_switch_worker_init(gtp_ctx_t *ctx, gtp_srv_t *srv)
{
	int i;

	/* Init worker related */
        INIT_LIST_HEAD(&srv->workers);
	srv->ctx = ctx;
	for (i = 0; i < srv->thread_cnt; i++)
		gtp_switch_worker_alloc(srv, i);

	__set_bit(GTP_FL_RUNNING_BIT, &srv->flags);

	return 0;
}

int
gtp_switch_udp_destroy(gtp_srv_t *srv)
{

	return 0;
}

/*
 *	GTP Switch init
 */
gtp_ctx_t *
gtp_switch_get(const char *name)
{
	gtp_ctx_t *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->gtp_ctx, next) {
		if (!memcmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

static void
gtp_htab_init(gtp_htab_t *h)
{
	h->htab = (struct hlist_head *) MALLOC(sizeof(struct hlist_head) *
					       CONN_HASHTAB_SIZE);
	h->dlock = dlock_init();
}

static void
gtp_htab_destroy(gtp_htab_t *h)
{
	FREE(h->htab);
	FREE(h->dlock);
}

gtp_ctx_t *
gtp_switch_init(const char *name)
{
	gtp_ctx_t *new;

	PMALLOC(new);
        INIT_LIST_HEAD(&new->next);
        memcpy(new->name, name, GTP_STR_MAX - 1);
        list_add_tail(&new->next, &daemon_data->gtp_ctx);

	/* Init hashtab */
	gtp_htab_init(&new->gtpc_teid_tab);
	gtp_htab_init(&new->gtpu_teid_tab);
	gtp_htab_init(&new->vteid_tab);
	gtp_htab_init(&new->vsqn_tab);

	return new;
}

int
gtp_switch_destroy(gtp_ctx_t *ctx)
{
	gtp_htab_destroy(&ctx->gtpc_teid_tab);
	gtp_htab_destroy(&ctx->gtpu_teid_tab);
	gtp_htab_destroy(&ctx->vteid_tab);
	gtp_htab_destroy(&ctx->vsqn_tab);
	return 0;
}
