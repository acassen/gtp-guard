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
#include "gtp_iptnl.h"
#include "gtp_htab.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_teid.h"
#include "gtp_server.h"
#include "gtp_switch.h"
#include "gtp_if.h"
#include "gtp_conn.h"
#include "gtp_session.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Worker
 */
static ssize_t
gtp_server_recvfrom(gtp_server_worker_t *w, struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t nbytes = recvfrom(w->fd, w->buffer, GTP_BUFFER_SIZE, 0, addr, addrlen);
	
	/* Update stats */
	if (nbytes > 0) {
		w->rx_pkt++;
		w->rx_bytes += nbytes;
	}

	return nbytes;
}

ssize_t
gtp_server_send(gtp_server_worker_t *w, int fd, struct sockaddr_in *addr)
{
	ssize_t nbytes = sendto(fd, w->buffer, w->buffer_size, 0, addr, sizeof(*addr));

	/* Update stats */
	if (nbytes > 0) {
		w->tx_pkt++;
		w->tx_bytes += nbytes;
	}

	return nbytes;
}

static int
gtp_server_udp_init(gtp_server_t *srv)
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

static void *
gtp_server_worker_task(void *arg)
{
	gtp_server_worker_t *w = arg;
	gtp_server_t *srv = w->srv;
	struct sockaddr_storage *addr = &srv->addr;
	struct sockaddr_storage addr_from;
	socklen_t addrlen = sizeof(addr_from);
	int fd;

	/* Initialize */
	(*srv->init) (w);

	/* Create UDP Listener */
	fd = gtp_server_udp_init(srv);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): %s: Error creating GTP on [%s]:%d"
				    , __FUNCTION__
				    , w->pname
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
		w->buffer_size = gtp_server_recvfrom(w, (struct sockaddr *) &addr_from
						      , &addrlen);
		if (w->buffer_size == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			log_message(LOG_INFO, "%s(): %s: Error recv (%m). Exiting"
					    , __FUNCTION__
					    , w->pname);
			goto end;
		}

		/* Process incoming buffer */
		(*srv->process) (w, &addr_from);
	}

  end:
	close(fd);
	return NULL;
}


/*
 *	UDP listener init
 */
static int
gtp_server_worker_launch(gtp_server_t *srv)
{
	gtp_server_worker_t *worker;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(worker, &srv->workers, next) {
		pthread_create(&worker->task, NULL, gtp_server_worker_task, worker);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

static int
gtp_server_worker_alloc(gtp_server_t *srv, int id)
{
	gtp_server_worker_t *worker;

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


/*
 *	GTP Server related
 */
int
gtp_server_start(gtp_server_t *srv)
{
	if (!__test_bit(GTP_FL_RUNNING_BIT, &srv->flags))
	    return -1;

	gtp_server_worker_launch(srv);

	return 0;
}

int
gtp_server_init(gtp_server_t *srv, void *ctx
				 , int (*init) (gtp_server_worker_t *)
				 , int (*process) (gtp_server_worker_t *, struct sockaddr_storage *))
{
	int i;

	/* Init worker related */
        INIT_LIST_HEAD(&srv->workers);
	srv->ctx = ctx;
	srv->init = init;
	srv->process = process;
	for (i = 0; i < srv->thread_cnt; i++)
		gtp_server_worker_alloc(srv, i);

	__set_bit(GTP_FL_RUNNING_BIT, &srv->flags);

	return 0;
}

int
gtp_server_destroy(gtp_server_t *srv)
{
	gtp_server_worker_t *w, *_w;

	if (!__test_bit(GTP_FL_RUNNING_BIT, &srv->flags))
		return -1;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry_safe(w, _w, &srv->workers, next) {
		pthread_cancel(w->task);
		pthread_join(w->task, NULL);
		list_head_del(&w->next);
		FREE(w);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}
