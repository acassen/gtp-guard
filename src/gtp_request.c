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
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Handle request
 */
static int
gtp_request_json_parse_cmd(gtp_req_session_t *s, json_node_t *json)
{
	char *cmd_str = NULL, *apn_str = NULL, *imsi_str = NULL;
	char addr_str[INET6_ADDRSTRLEN];
	gtp_apn_t *apn;
	gtp_conn_t *c;
	uint8_t imsi_swap[8];
	uint64_t imsi;

	jsonw_start_object(s->jwriter);

	if (!json_find_member_strvalue(json, "cmd", &cmd_str)) {
		jsonw_string_field(s->jwriter, "Error", "No command specified");
		goto end;
	}

	if (strncmp(cmd_str, "imsi_info", 9)) {
		jsonw_string_field_fmt(s->jwriter, "Error", "Unknown command %s", cmd_str);
		goto end;
	}

	if (!json_find_member_strvalue(json, "apn", &apn_str)) {
		jsonw_string_field(s->jwriter, "Error", "No Access-Point-Name specified");
		goto end;
	}

	if (!json_find_member_strvalue(json, "imsi", &imsi_str)) {
		jsonw_string_field(s->jwriter, "Error", "No IMSI specified");
		goto end;
	}

	gtp_apn_extract_ni(apn_str, strlen(apn_str), s->buffer_out, GTP_REQUEST_BUFFER_SIZE);
	apn = gtp_apn_get(s->buffer_out);
	if (!apn) {
		jsonw_string_field(s->jwriter, "Error", "Unknown Access-Point-Name");
		goto end;
	}

	memset(imsi_swap, 0, 8);
	str_imsi_to_bcd_swap(imsi_str, strlen(imsi_str), imsi_swap);
	gtp_imsi_rewrite(apn, imsi_swap);
	imsi = bcd_to_int64(imsi_swap, 8);
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		jsonw_string_field(s->jwriter, "Error", "Unknown IMSI");
		goto end;
	}

	jsonw_string_field_fmt(s->jwriter, "sgw-ip-address", "%u.%u.%u.%u"
					 , NIPQUAD(c->sgw_addr.sin_addr.s_addr));

	log_message(LOG_INFO, "%s(): imsi_info:={imsi:%s sgw-ip-address:%u.%u.%u.%u} with peer [%s]:%d"
			    , __FUNCTION__
			    , imsi_str
			    ,  NIPQUAD(c->sgw_addr.sin_addr.s_addr)
			    , inet_sockaddrtos2(&s->addr, addr_str)
			    , ntohs(inet_sockaddrport(&s->addr)));

	gtp_conn_put(c);
  end:
	jsonw_end_object(s->jwriter);
	return 0;
}

static int
gtp_request_json_parse(gtp_req_session_t *s)
{
	json_node_t *json;

	json = json_decode(s->buffer_in);
	if (!json) {
		log_message(LOG_INFO, "%s(): Error parsing JSON string : [%s]"
				    , __FUNCTION__
				    , s->buffer_in);
		return -1;
	}

	gtp_request_json_parse_cmd(s, json);
	json_destroy(json);
	return 0;
}


/*
 *	Main TCP thread
 */
static int
gtp_request_session_close(gtp_req_session_t *s)
{
	jsonw_destroy(&s->jwriter);
	fclose(s->fp);	/* Also close s->fd */
	FREE(s);
	return 0;
}

int
gtp_request_http_read(int sd, void *data, int size)
{
	int nbytes, offset = 0;
	char *buffer = (char *) data;

	if (!size)
		return 0;

next_rcv:
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return -1;

	nbytes = read(sd, data + offset, size - offset);

	/* data are ready ? */
	if (nbytes == -1 || nbytes == 0) {
		if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
			goto next_rcv;

		return -1;
	}

	/* Everything but the girl ! */
	offset += nbytes;

	if (buffer[offset-2] == '\r' && buffer[offset-1] == '\n')
		return offset;

	if (offset < size)
		goto next_rcv;

	return size;
}

static int
gtp_request_json_rcv(gtp_req_session_t *s)
{
	char *buffer = s->buffer_in;
	int ret;

	memset(buffer, 0, GTP_REQUEST_BUFFER_SIZE);
	ret = gtp_request_http_read(s->fd, buffer, GTP_REQUEST_BUFFER_SIZE);
	if (ret < 0)
		return -1;

	return ret;
}

void *
gtp_request_tcp_thread(void *arg)
{
	gtp_req_session_t *s = arg;
	char identity[64];
	int old_type, ret;

	/* Out identity */
	snprintf(identity, 63, "%s", inet_sockaddrtos(&s->addr));
	prctl(PR_SET_NAME, identity, 0, 0, 0, 0);

	/* Set Cancel type */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

	/* Set timeout on session fd */
	s->fd = if_setsockopt_rcvtimeo(s->fd, 2000);
	s->fd = if_setsockopt_sndtimeo(s->fd, 2000);
	if (s->fd < 0)
		goto end;

	ret = gtp_request_json_rcv(s);
	if (ret < 0)
		goto end;

	/* session handle */
#if 0
	dump_buffer("JSON : ", s->buffer_in, ret);
	printf("---[%s]---\nlength:%d\n", s->buffer_in, ret);
#endif
	s->jwriter = jsonw_new(s->fp);
	jsonw_pretty(s->jwriter, true);
	gtp_request_json_parse(s);
	jsonw_destroy(&s->jwriter);

  end:
	gtp_request_session_close(s);
	return NULL;
}

/*
 *	Accept
 */
static void
gtp_request_tcp_accept(thread_ref_t thread)
{
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
	gtp_req_worker_t *w;
        gtp_req_session_t *s;
        int fd, accept_fd, ret;

        /* Fetch thread elements */
        fd = THREAD_FD(thread);
        w = THREAD_ARG(thread);

	/* Terminate event */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		thread_add_terminate_event(thread->master);

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
	PMALLOC(s);
        s->fd = accept_fd;
        s->addr = addr;
        s->worker = w;
	s->fp = fdopen(accept_fd, "w");
	if (!s->fp) {
		log_message(LOG_INFO, "%s(): #%d cant fdopen on accept socket with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		gtp_request_session_close(s);
		goto next_accept;
	}

        /* Register reader on accept_sd */
        if_setsockopt_nodelay(s->fd, 1);
	if_setsockopt_nolinger(s->fd, 1);

	/* Spawn a dedicated pthread per client. Dont really need performance here,
	 * simply handle requests synchronously */
	ret = pthread_attr_init(&s->task_attr);
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): #%d cant init pthread_attr for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		gtp_request_session_close(s);
		goto next_accept;
	}

	ret = pthread_attr_setdetachstate(&s->task_attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): #%d cant set pthread detached for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		gtp_request_session_close(s);
		goto next_accept;
	}

	ret = pthread_create(&s->task, &s->task_attr, gtp_request_tcp_thread, s);
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): #%d cant create pthread for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		gtp_request_session_close(s);
	}

  next_accept:
        /* Register read thread on listen fd */
        w->r_thread = thread_add_read(thread->master, gtp_request_tcp_accept, w, fd,
                                      GTP_REQUEST_TCP_LISTENER_TIMER, 0);
}


/*
 *	Listener
 */
static int
gtp_request_tcp_listen(gtp_req_worker_t *w)
{
        mode_t old_mask;
        gtp_req_channel_t *req = w->channel;
        struct sockaddr_storage *addr = &req->addr;
        socklen_t addrlen;
        int err, fd = -1;

        /* Mask */
        old_mask = umask(0077);

        /* Create socket */
        fd = socket(addr->ss_family, SOCK_STREAM, 0);
        fd = if_setsockopt_reuseaddr(fd, 1);
        if (fd < 0) {
                log_message(LOG_INFO, "%s(): error creating [%s]:%d socket"
                                    , __FUNCTION__
                                    , inet_sockaddrtos(addr)
                                    , ntohs(inet_sockaddrport(addr)));
                return -1;
        }

        /* Reuseport: ingress loadbalancing */
        if_setsockopt_reuseport(fd, 1);

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
        w->r_thread = thread_add_read(w->master, gtp_request_tcp_accept, w, fd,
                                      GTP_REQUEST_TCP_LISTENER_TIMER, 0);
        w->fd = fd;
        return fd;

  error:
        close(fd);
        return -1;
}

static void *
gtp_request_worker_task(void *arg)
{
	gtp_req_worker_t *w = arg;
	gtp_req_channel_t *srv = w->channel;
	char pname[128];

	/* Create Process Name */
	snprintf(pname, 127, "req-ch-%d", w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

        /* Welcome message */
        log_message(LOG_INFO, "%s(): Starting Listener Server[%s:%d]/Worker[%d]"
                            , __FUNCTION__
                            , inet_sockaddrtos(&srv->addr)
                            , ntohs(inet_sockaddrport(&srv->addr))
                            , w->id);
	__set_bit(GTP_FL_RUNNING_BIT, &w->flags);

        /* I/O MUX init */
        w->master = thread_make_master(true);

        /* Register listener */
        gtp_request_tcp_listen(w);

        /* Infinite loop */
        launch_thread_scheduler(w->master);

        /* Release Master stuff */
        log_message(LOG_INFO, "%s(): Stopping Listener Server[%s:%d]/Worker[%d]"
                            , __FUNCTION__
                            , inet_sockaddrtos(&srv->addr)
                            , ntohs(inet_sockaddrport(&srv->addr))
                            , w->id);
	__clear_bit(GTP_FL_RUNNING_BIT, &w->flags);
	return NULL;
}

/*
 *	TCP listener init
 */
int
gtp_request_worker_launch(gtp_req_channel_t *srv)
{
	gtp_req_worker_t *worker;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(worker, &srv->workers, next) {
		pthread_create(&worker->task, NULL, gtp_request_worker_task, worker);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

int
gtp_request_worker_start(void)
{
	gtp_req_channel_t *srv = &daemon_data->request_channel;

	if (!(__test_bit(GTP_FL_RUNNING_BIT, &srv->flags)))
	    return -1;

	gtp_request_worker_launch(srv);

	return 0;
}

static int
gtp_request_worker_alloc(gtp_req_channel_t *srv, int id)
{
	gtp_req_worker_t *worker;

	PMALLOC(worker);
	INIT_LIST_HEAD(&worker->next);
	worker->channel = srv;
	worker->id = id;

	pthread_mutex_lock(&srv->workers_mutex);
	list_add_tail(&worker->next, &srv->workers);
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

static int
gtp_request_worker_release(gtp_req_worker_t *w)
{
	thread_destroy_master(w->master);
	close(w->fd);
	return 0;
}

int
gtp_request_for_each_worker(gtp_req_channel_t *srv, int (*cb) (gtp_req_worker_t *, void *), void *arg)
{
	gtp_req_worker_t *w;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(w, &srv->workers, next)
		(*cb) (w, arg);
	pthread_mutex_unlock(&srv->workers_mutex);
	return 0;
}

/*
 *	GTP Request init
 */
int
gtp_request_init(void)
{
	gtp_req_channel_t *srv = &daemon_data->request_channel;
	int i;

	/* Init worker related */
        INIT_LIST_HEAD(&srv->workers);
	for (i = 0; i < srv->thread_cnt; i++)
		gtp_request_worker_alloc(srv, i);

	__set_bit(GTP_FL_RUNNING_BIT, &srv->flags);

	return 0;
}

int
gtp_request_destroy(void)
{
	gtp_req_channel_t *srv = &daemon_data->request_channel;
	gtp_req_worker_t *w, *_w;

	if (!__test_bit(GTP_FL_RUNNING_BIT, &srv->flags))
		return -1;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry_safe(w, _w, &srv->workers, next) {
		pthread_join(w->task, NULL);
	        gtp_request_worker_release(w);
		list_head_del(&w->next);
		FREE(w);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}
