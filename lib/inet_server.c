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

/* system includes */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "scheduler.h"
#include "logger.h"
#include "bitops.h"
#include "memory.h"
#include "inet_utils.h"
#include "inet_server.h"


/*
 *	Connection handling
 */
static int
inet_cnx_destroy(inet_cnx_t *c)
{
	fclose(c->fp);	/* Also close c->fd */
	FREE(c);
	return 0;
}

ssize_t
inet_http_read(inet_cnx_t *c)
{
	inet_worker_t *w = c->worker;
	char *buffer = c->buffer_in;
	ssize_t nbytes, offset = 0;

	memset(buffer, 0, INET_BUFFER_SIZE);
	c->buffer_in_size = 0;

next_rcv:
	if (__test_bit(INET_FL_STOP_BIT, &w->flags))
		return -1;

	nbytes = read(c->fd, buffer + offset, INET_BUFFER_SIZE - offset);

	/* data are ready ? */
	if (nbytes == -1 || nbytes == 0) {
		if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
			goto next_rcv;

		return -1;
	}

	offset += nbytes;

	if (buffer[offset-2] == '\r' && buffer[offset-1] == '\n') {
		c->buffer_in_size = offset;
		return offset;
	}

	if (offset < INET_BUFFER_SIZE)
		goto next_rcv;

	c->buffer_in_size = INET_BUFFER_SIZE;
	return INET_BUFFER_SIZE;
}

void *
inet_server_tcp_thread(void *arg)
{
	inet_cnx_t *c = arg;
	inet_worker_t *w = c->worker;
	inet_server_t *s = w->server;
	char identity[64];
	ssize_t nbytes;
	int old_type, err;

	/* Out identity */
	snprintf(identity, 63, "%s", inet_sockaddrtos(&c->addr));
	prctl(PR_SET_NAME, identity, 0, 0, 0, 0);

	/* Set Cancel type */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

	/* Set timeout on session fd */
	c->fd = inet_setsockopt_rcvtimeo(c->fd, 2000);
	c->fd = inet_setsockopt_sndtimeo(c->fd, 2000);
	if (c->fd < 0)
		goto end;

	/* initialize */
	err = (*s->cnx_init) (c);
	if (err)
		goto end;

	/* receive */
	if (!s->cnx_rcv)
		goto end;

	nbytes = (*s->cnx_rcv) (c);
	if (nbytes < 0)
		goto end;

	err = (*s->cnx_process) (c);
	if (err)
		goto end;

  end:
	if (*s->cnx_destroy)
		(*s->cnx_destroy) (c);
	inet_cnx_destroy(c);
	return NULL;
}


/*
 *	Accept
 */
static void
inet_server_tcp_accept(thread_ref_t thread)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	inet_worker_t *w;
	inet_cnx_t *c;
	int fd, accept_fd, err;

	/* Fetch thread elements */
	fd = THREAD_FD(thread);
	w = THREAD_ARG(thread);

	/* Terminate event */
	if (__test_bit(INET_FL_STOP_BIT, &w->flags)) {
		thread_add_terminate_event(thread->master);
		return;
	}

	/* Wait until accept event */
	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_accept;

	/* Accept incoming connection */
	accept_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
	if (accept_fd < 0) {
		log_message(LOG_INFO, "%s(): #%d Error accepting connection from peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		goto next_accept;
	}

	/* remote client session allocation */
	PMALLOC(c);
	c->fd = accept_fd;
	c->addr = addr;
	c->worker = w;
	c->fp = fdopen(accept_fd, "w");
	if (!c->fp) {
		log_message(LOG_INFO, "%s(): #%d cant fdopen on accept socket with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		inet_cnx_destroy(c);
		goto next_accept;
	}

	/* Register reader on accept_sd */
	err = inet_setsockopt_nodelay(c->fd, 1);
	err = (err) ? : inet_setsockopt_nolinger(c->fd, 1);
	if (err) {
		log_message(LOG_INFO, "%s(): error creating TCP connection with [%s]:%d"
				    , __FUNCTION__
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		inet_cnx_destroy(c);
		goto next_accept;
	}

	/* Spawn a dedicated pthread per client. Dont really need performance here,
	* simply handle requests synchronously */
	err = pthread_attr_init(&c->task_attr);
	if (err) {
		log_message(LOG_INFO, "%s(): #%d cant init pthread_attr for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		inet_cnx_destroy(c);
		goto next_accept;
	}

	err = pthread_attr_setdetachstate(&c->task_attr, PTHREAD_CREATE_DETACHED);
	if (err) {
		log_message(LOG_INFO, "%s(): #%d cant set pthread detached for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		inet_cnx_destroy(c);
		goto next_accept;
	}

	err = pthread_create(&c->task, &c->task_attr, inet_server_tcp_thread, c);
	if (err) {
		log_message(LOG_INFO, "%s(): #%d cant create pthread for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		inet_cnx_destroy(c);
	}

next_accept:
	/* Register read thread on listen fd */
	w->r_thread = thread_add_read(thread->master, inet_server_tcp_accept, w, fd,
				      INET_TCP_LISTENER_TIMER, 0);
}


/*
 *	Listener
 */
static int
inet_server_tcp_listen(inet_worker_t *w)
{
	mode_t old_mask;
	inet_server_t *srv = w->server;
	struct sockaddr_storage *addr = &srv->addr;
	socklen_t addrlen;
	int err, fd = -1;

	/* Mask */
	old_mask = umask(0077);

	/* Create socket */
	fd = socket(addr->ss_family, SOCK_STREAM, 0);
	fd = inet_setsockopt_reuseaddr(fd, 1);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): error creating [%s]:%d socket"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		return -1;
	}

	/* Reuseport: ingress loadbalancing */
	inet_setsockopt_reuseport(fd, 1);

	/* Bind listening channel */
	addrlen = (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
	err = bind(fd, (struct sockaddr *) addr, addrlen);
	if (err < 0) {
		log_message(LOG_INFO, "%s(): Error binding to [%s]:%d (%m)"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		goto error;
	}

	/* Init listening channel */
	err = listen(fd, 5);
	if (err < 0) {
		log_message(LOG_INFO, "%s(): Error listening on [%s]:%d (%m)"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		goto error;
	}

	/* Restore old mask */
	umask(old_mask);

	/* Register acceptor thread */
	w->r_thread = thread_add_read(w->master, inet_server_tcp_accept, w, fd,
				      INET_TCP_LISTENER_TIMER, 0);
	w->fd = fd;
	return fd;

error:
	close(fd);
	return -1;
}

static void *
inet_server_worker_task(void *arg)
{
	inet_worker_t *w = arg;
	inet_server_t *srv = w->server;
	char pname[128];

	/* Create Process Name */
	snprintf(pname, 127, "inet-srv-%d", w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

        /* Welcome message */
        log_message(LOG_INFO, "%s(): Starting Listener Server[%s:%d]/Worker[%d]"
                            , __FUNCTION__
                            , inet_sockaddrtos(&srv->addr)
                            , ntohs(inet_sockaddrport(&srv->addr))
                            , w->id);
	__set_bit(INET_FL_RUNNING_BIT, &w->flags);

        /* I/O MUX init */
        w->master = thread_make_master(true);

        /* Register listener */
        inet_server_tcp_listen(w);

        /* Infinite loop */
        launch_thread_scheduler(w->master);

        /* Release Master stuff */
        log_message(LOG_INFO, "%s(): Stopping Listener Server[%s:%d]/Worker[%d]"
                            , __FUNCTION__
                            , inet_sockaddrtos(&srv->addr)
                            , ntohs(inet_sockaddrport(&srv->addr))
                            , w->id);
	__clear_bit(INET_FL_RUNNING_BIT, &w->flags);
	return NULL;
}


/*
 *	INET Server start
 */
int
inet_server_worker_launch(inet_server_t *srv)
{
	inet_worker_t *worker;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(worker, &srv->workers, next) {
		pthread_create(&worker->task, NULL, inet_server_worker_task, worker);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

int
inet_server_worker_start(inet_server_t *srv)
{
	if (!(__test_bit(INET_FL_RUNNING_BIT, &srv->flags)))
		return -1;

	return inet_server_worker_launch(srv);
}

static int
inet_server_worker_alloc(inet_server_t *srv, int id)
{
	inet_worker_t *worker;

	PMALLOC(worker);
	INIT_LIST_HEAD(&worker->next);
	worker->server = srv;
	worker->id = id;

	pthread_mutex_lock(&srv->workers_mutex);
	list_add_tail(&worker->next, &srv->workers);
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

static int
inet_server_worker_release(inet_worker_t *w)
{
	thread_destroy_master(w->master);
	close(w->fd);
	return 0;
}

int
inet_server_for_each_worker(inet_server_t *srv, int (*cb) (inet_worker_t *, void *), void *arg)
{
	inet_worker_t *w;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(w, &srv->workers, next)
		(*cb) (w, arg);
	pthread_mutex_unlock(&srv->workers_mutex);
	return 0;
}


/*
 *	INET Server init
 */
int
inet_server_init(inet_server_t *srv)
{
	int i;

	/* Init worker related */
	INIT_LIST_HEAD(&srv->workers);
	for (i = 0; i < srv->thread_cnt; i++)
		inet_server_worker_alloc(srv, i);

	__set_bit(INET_FL_RUNNING_BIT, &srv->flags);

	return 0;
}

int
inet_server_destroy(inet_server_t *srv)
{
	inet_worker_t *w, *_w;

	if (!__test_bit(INET_FL_RUNNING_BIT, &srv->flags))
		return -1;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry_safe(w, _w, &srv->workers, next) {
		__set_bit(INET_FL_STOP_BIT, &w->flags);
		pthread_join(w->task, NULL);
		inet_server_worker_release(w);
		list_head_del(&w->next);
		FREE(w);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	__clear_bit(INET_FL_RUNNING_BIT, &srv->flags);
	return 0;
}
