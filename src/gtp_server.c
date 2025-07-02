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


/*
 *	Worker
 */
static ssize_t
gtp_server_recvfrom(gtp_server_t *s, struct sockaddr *addr, socklen_t *addrlen)
{
	ssize_t nbytes = recvfrom(s->fd, s->pbuff->head
				       , pkt_buffer_size(s->pbuff)
				       , 0, addr, addrlen);
	/* metrics */
	if (nbytes < 0)
		return -1;

	gtp_metrics_pkt_update(&s->rx_metrics, nbytes);
	__sync_add_and_fetch(&s->rx_pkts, 1);
	return nbytes;
}

ssize_t
gtp_server_send(gtp_server_t *s, int fd, struct sockaddr_in *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) s->pbuff->head;

	ssize_t nbytes = sendto(fd, s->pbuff->head
				  , pkt_buffer_len(s->pbuff)
				  , 0, addr, sizeof(*addr));

	/* metrics */
	gtp_metrics_pkt_update(&s->tx_metrics, nbytes);
	gtp_metrics_tx(&s->msg_metrics, h->type);
	gtp_metrics_cause_update(&s->cause_tx_metrics, s->pbuff);
	__sync_add_and_fetch(&s->tx_pkts, 1);

	return nbytes;
}

ssize_t
gtp_server_send_async(gtp_server_t *s, pkt_buffer_t *pbuff, struct sockaddr_in *addr)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;

	ssize_t nbytes = pkt_buffer_send(s->fd, pbuff, (struct sockaddr_storage *) addr);

	/* metrics */
	gtp_metrics_pkt_update(&s->tx_metrics, pkt_buffer_len(pbuff));
	gtp_metrics_tx(&s->msg_metrics, h->type);
	gtp_metrics_cause_update(&s->cause_tx_metrics, pbuff);
	__sync_add_and_fetch(&s->tx_pkts, 1);

	return nbytes;
}

static int
gtp_server_udp_init(gtp_server_t *s)
{
	struct sockaddr_storage *addr = &s->addr;
	socklen_t addrlen;
	int fd, err;

	/* Server init */
	(*s->init) (s);

	/* Create UDP Listener */
	fd = socket(addr->ss_family, SOCK_DGRAM, 0);
	err = inet_setsockopt_reuseaddr(fd, 1);
	err = (err) ? : inet_setsockopt_reuseport(fd, 1);
	err = (err) ? : inet_setsockopt_rcvtimeo(fd, 5000);
	err = (err) ? : inet_setsockopt_sndtimeo(fd, 5000);
	if (err) {
		log_message(LOG_INFO, "%s(): error creating UDP [%s]:%d socket"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		close(fd);
		return -1;
	}

	/* Bind listening channel */
	addrlen = (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
	err = bind(fd, (struct sockaddr *) addr, addrlen);
	if (err) {
		log_message(LOG_INFO, "%s(): Error binding to [%s]:%d (%m)"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		close(fd);
		return -1;
	}

	return fd;
}

static void
gtp_server_async_recv_thread(thread_ref_t thread)
{
	gtp_server_t *s = THREAD_ARG(thread);
	struct sockaddr_storage *addr = &s->addr;
	struct sockaddr_storage addr_from;
	socklen_t addrlen;
	ssize_t nbytes;
	int ret;

	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_read;

	/* Perform ingress packet handling */
	nbytes = gtp_server_recvfrom(s, (struct sockaddr *) &addr_from, &addrlen);
	if (nbytes == -1) {
		if (errno == EAGAIN || errno == EINTR)
			goto next_read;
		log_message(LOG_INFO, "%s(): Error recv (%m). Exiting"
					, __FUNCTION__);
		/* re-init on error */
		thread_del_read(thread);
		close(s->fd);
		s->fd = gtp_server_udp_init(s);
		if (s->fd < 0) {
			log_message(LOG_INFO, "%s(): Error creating GTP on [%s]:%d...dying..."
					    , __FUNCTION__
					    , inet_sockaddrtos(addr)
					    , ntohs(inet_sockaddrport(addr)));
			return;
		}
		goto next_read;
	}
	pkt_buffer_set_end_pointer(s->pbuff, nbytes);

	/* Process incoming buffer */
	ret = (*s->process) (s, &addr_from);
	if (ret == -1 || ret == GTP_SERVER_DELAYED)
		goto next_read;

	/* That is UDP socket, ideally need to submit write operation to I/O MUX
	 * but to reduce syscall, we can directly send packet
	 *
	s->w_thread = thread_add_write(master, gtp_server_egress_thread
					     , s, s->fd, 3*TIMER_HZ, 0);
	 */
	gtp_server_send(s, s->fd, (struct sockaddr_in *) &addr_from);

  next_read:
	s->r_thread = thread_add_read(master, gtp_server_async_recv_thread
					    , s, s->fd, 3*TIMER_HZ, 0);
}


/*
 *	GTP Server related
 */
int
gtp_server_init(gtp_server_t *s, void *ctx
			       , int (*init) (gtp_server_t *)
			       , int (*process) (gtp_server_t *, struct sockaddr_storage *))
{
	struct sockaddr_storage *addr = &s->addr;
	int fd;

	/* Init worker related */
	s->ctx = ctx;
	s->init = init;
	s->process = process;
	s->pbuff = pkt_buffer_alloc(GTP_BUFFER_SIZE);
	s->seed = time(NULL);
	srand(s->seed);

	/* Create UDP Listener */
	fd = gtp_server_udp_init(s);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): Error creating GTP on [%s]:%d"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		pkt_buffer_free(s->pbuff);
		return -1;
	}

	/* So far so good */
	s->fd = fd;
	s->r_thread = thread_add_read(master, gtp_server_async_recv_thread
					    , s, s->fd, 3*TIMER_HZ, 0);
	__set_bit(GTP_FL_RUNNING_BIT, &s->flags);
	return 0;
}

int
gtp_server_destroy(gtp_server_t *s)
{
	if (!__test_bit(GTP_FL_RUNNING_BIT, &s->flags))
		return -1;

	close(s->fd);
	pkt_buffer_free(s->pbuff);
	return 0;
}


