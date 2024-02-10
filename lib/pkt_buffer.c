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
#include "list_head.h"
#include "pkt_buffer.h"


/*
 *	Pkt queue helpers
 */
pkt_t *
pkt_get(pkt_queue_t *q)
{
	pkt_t *pkt;

	pthread_mutex_lock(&q->mutex);
	if (list_empty(&q->queue)) {
		pthread_mutex_unlock(&q->mutex);
		PMALLOC(pkt);
		INIT_LIST_HEAD(&pkt->next);
		pkt->pbuff = pkt_buffer_alloc(DEFAULT_PKT_BUFFER_SIZE);
		return pkt;
	}

	pkt = list_first_entry(&q->queue, pkt_t, next);
	list_del_init(&pkt->next);
	pthread_mutex_unlock(&q->mutex);
	pkt_buffer_reset(pkt->pbuff);
	return pkt;
}

int
pkt_put(pkt_queue_t *q, pkt_t *pkt)
{
	if (!pkt)
		return -1;

	pthread_mutex_lock(&q->mutex);
	list_add_tail(&pkt->next, &q->queue);
	pthread_mutex_unlock(&q->mutex);
	return 0;
}

ssize_t
pkt_send(int fd, pkt_queue_t *q, pkt_t *pkt)
{
	ssize_t ret;

	ret = send(fd, pkt->pbuff->head, pkt_buffer_len(pkt->pbuff), 0);
	pkt_put(q, pkt);
	return ret;
}

ssize_t
pkt_recv(int fd, pkt_t *pkt)
{
	ssize_t nbytes;

	nbytes = recv(fd, pkt->pbuff->head, pkt_buffer_size(pkt->pbuff), 0);
	if (nbytes < 0)
		return -1;

	pkt_buffer_set_end_pointer(pkt->pbuff, nbytes);
	return nbytes;
}

int
pkt_queue_init(pkt_queue_t *q)
{
	INIT_LIST_HEAD(&q->queue);
	pthread_mutex_init(&q->mutex, NULL);
	return 0;
}

int
pkt_queue_destroy(pkt_queue_t *q)
{
	pkt_t *pkt, *_pkt;

	pthread_mutex_lock(&q->mutex);
	list_for_each_entry_safe(pkt, _pkt, &q->queue, next) {
		list_head_del(&pkt->next);
		pkt_buffer_free(pkt->pbuff);
		FREE(pkt);
	}
	pthread_mutex_unlock(&q->mutex);
	return 0;
}


/*
 *	Pkt helpers
 */
ssize_t
pkt_buffer_send(int fd, pkt_buffer_t *b, struct sockaddr_storage *addr)
{
	struct iovec iov = { .iov_base = b->head, .iov_len = pkt_buffer_len(b) };
	struct msghdr msg = {
		.msg_name = addr,
		.msg_namelen = sizeof(*addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0
	};

	return sendmsg(fd, &msg, 0);
}

int
pkt_buffer_put_zero(pkt_buffer_t *b, unsigned int size)
{
	if (pkt_buffer_tailroom(b) < size)
		return -1;

	memset(b->end, 0, size);
	b->end += size;
	return 0;
}

int
pkt_buffer_pad(pkt_buffer_t *b, unsigned int size)
{
	int len = pkt_buffer_len(b);

	if (len >= size)
		return -1;

	return pkt_buffer_put_zero(b, size - len);
}

pkt_buffer_t *
pkt_buffer_alloc(unsigned int size)
{
	pkt_buffer_t *new;
	void *data;

	PMALLOC(new);
	if (!new)
		return NULL;
	data = MALLOC(size);
	if (!data) {
		FREE(new);
		return NULL;
	}

	new->head = data;
	new->data = new->end = data;
	new->tail = data + size;

	return new;
}

void
pkt_buffer_free(pkt_buffer_t *b)
{
	if (!b)
		return;
	FREE(b->head);
	FREE(b);
}
