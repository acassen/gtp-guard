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
#include <netinet/in.h>
#include <errno.h>

/* local includes */
#include "memory.h"
#include "utils.h"
#include "list_head.h"
#include "pkt_buffer.h"


/*
 *	Pkt helpers
 */
ssize_t
pkt_send(int fd, pkt_queue_t *q, pkt_t *pkt)
{
	ssize_t ret;

	ret = send(fd, pkt->pbuff->head, pkt_buffer_len(pkt->pbuff), 0);
	pkt_queue_put(q, pkt);
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


/*
 *	Pkt queue helpers
 */
void
pkt_queue_run(pkt_queue_t *q, int (*run) (pkt_t *, void *), void *arg)
{
	pkt_t *pkt, *_pkt;

	pthread_mutex_lock(&q->mutex);
	list_for_each_entry_safe(pkt, _pkt, &q->queue, next) {
		list_del_init(&pkt->next);

		pthread_mutex_unlock(&q->mutex);
		(*run) (pkt, arg);
		pthread_mutex_lock(&q->mutex);
	}
	pthread_mutex_unlock(&q->mutex);
}

static pkt_t *
pkt_alloc(unsigned int size)
{
	pkt_t *pkt;

	PMALLOC(pkt);
	if (!pkt)
		return NULL;

	INIT_LIST_HEAD(&pkt->next);
	pkt->pbuff = pkt_buffer_alloc(size);
	if (!pkt->pbuff) {
		FREE(pkt);
		pkt = NULL;
	}
	return pkt;
}

static void
pkt_free(pkt_t *pkt)
{
	pkt_buffer_free(pkt->pbuff);
	FREE(pkt);
}

pkt_t *
pkt_queue_get(pkt_queue_t *q)
{
	pkt_t *pkt;

	pthread_mutex_lock(&q->mutex);
	if (list_empty(&q->queue)) {
		pthread_mutex_unlock(&q->mutex);
		return pkt_alloc(DEFAULT_PKT_BUFFER_SIZE);
	}

	pkt = list_first_entry(&q->queue, pkt_t, next);
	list_del_init(&pkt->next);
	pthread_mutex_unlock(&q->mutex);
	pkt_buffer_reset(pkt->pbuff);
	return pkt;
}

int
__pkt_queue_put(pkt_queue_t *q, pkt_t *pkt)
{
	if (!pkt)
		return -1;

	list_add_tail(&pkt->next, &q->queue);
	return 0;
}

int
pkt_queue_put(pkt_queue_t *q, pkt_t *pkt)
{
	pthread_mutex_lock(&q->mutex);
	__pkt_queue_put(q, pkt);
	pthread_mutex_unlock(&q->mutex);
	return 0;
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
 *	mpkt helpers
 */
int
mpkt_dump(mpkt_t *mpkt, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		printf("-=[ pkt #%d (%d) ]=-\n",
			i, pkt_buffer_len(mpkt->pkt[i]->pbuff));
		dump_buffer(" ", (char *) mpkt->pkt[i]->pbuff->head
			       , pkt_buffer_len(mpkt->pkt[i]->pbuff));
	}

	return 0;
}

int
mpkt_recv(int fd, mpkt_t *mpkt)
{
	int ret, i;

	ret = recvmmsg(fd, mpkt->msgs, mpkt->vlen, MSG_WAITFORONE, NULL);
	if (ret < 0)
		return -1;

	for (i = 0; i < ret; i++)
		pkt_buffer_set_end_pointer(mpkt->pkt[i]->pbuff, mpkt->msgs[i].msg_len);

	return ret;
}

int
mpkt_init(mpkt_t *mpkt, unsigned int vlen)
{
	mpkt->vlen = vlen;
	mpkt->pkt = MALLOC(sizeof(pkt_t) * vlen);
	if (!mpkt->pkt)
		return -1;
	mpkt->msgs = MALLOC(sizeof(struct mmsghdr) * vlen);
	if (!mpkt->msgs) {
		FREE(mpkt->pkt);
		return -1;
	}
	mpkt->iovecs = MALLOC(sizeof(struct iovec) * vlen);
	if (!mpkt->iovecs) {
		FREE(mpkt->pkt);
		FREE(mpkt->msgs);
		return -1;
	}

	return 0;
}

void
mpkt_process(mpkt_t *mpkt, unsigned int vlen, void (*process) (pkt_t *, void *), void *arg)
{
	int i;

	for (i = 0; i < vlen; i++)
		(*process) (mpkt->pkt[i], arg);
}

static void
mpkt_release(mpkt_t *mpkt)
{
	int i;
	for (i=0; i < mpkt->vlen; i++) {
		if (mpkt->pkt[i]) {
			pkt_free(mpkt->pkt[i]);
		}
	}

	FREE(mpkt->pkt);
}

void
mpkt_destroy(mpkt_t *mpkt)
{
	mpkt_release(mpkt);
	FREE(mpkt->msgs);
	FREE(mpkt->iovecs);
}

static int
mpkt_alloc(mpkt_t *mpkt, unsigned int size)
{
	pkt_t *pkt;
	int i;

	for (i=0; i < mpkt->vlen; i++) {
		pkt = pkt_alloc(size);
		if (!pkt)
			return -1;
		mpkt->pkt[i] = pkt;
	}

	return 0;
}

static void
mpkt_prepare(mpkt_t *mpkt)
{
	int i;

	for (i = 0; i < mpkt->vlen; i++) {
		mpkt->iovecs[i].iov_base = mpkt->pkt[i]->pbuff->head;
		mpkt->iovecs[i].iov_len = pkt_buffer_size(mpkt->pkt[i]->pbuff);
		mpkt->msgs[i].msg_hdr.msg_iov = &mpkt->iovecs[i];
		mpkt->msgs[i].msg_hdr.msg_iovlen = 1;
	}
}

void
mpkt_reset(mpkt_t *mpkt)
{
	int i;

	for (i = 0; i < mpkt->vlen; i++)
		pkt_buffer_reset(mpkt->pkt[i]->pbuff);
}

int
__pkt_queue_mget(pkt_queue_t *q, mpkt_t *mpkt)
{
	pkt_t *pkt, *_pkt;
	int ret, i, idx = 0;

	if (list_empty(&q->queue)) {
		ret = mpkt_alloc(mpkt, DEFAULT_PKT_BUFFER_SIZE);
		if (ret < 0) {
			mpkt_release(mpkt);
			return -1;
		}

		goto end;
	}

	list_for_each_entry_safe(pkt, _pkt, &q->queue, next) {
		if (idx >= mpkt->vlen) {
			goto end;
		}

		list_del_init(&pkt->next);
		pkt_buffer_reset(pkt->pbuff);
		mpkt->pkt[idx++] = pkt;

	}

	/* Not fully filled */
	for (i=idx; i < mpkt->vlen; i++) {
		pkt = pkt_alloc(DEFAULT_PKT_BUFFER_SIZE);
		if (!pkt) {
			mpkt_release(mpkt);
			return -1;
		}

		mpkt->pkt[i] = pkt;
	}

  end:
	/* Prepare mpkt */
	mpkt_prepare(mpkt);
	return 0;
}

int
pkt_queue_mget(pkt_queue_t *q, mpkt_t *mpkt)
{
	pthread_mutex_lock(&q->mutex);
	__pkt_queue_mget(q, mpkt);
	pthread_mutex_unlock(&q->mutex);
	return 0;
}

int
__pkt_queue_mput(pkt_queue_t *q, mpkt_t *mpkt)
{
	pkt_t *pkt;
	int i;

	for (i=0; i < mpkt->vlen; i++) {
		pkt = mpkt->pkt[i];
		if (pkt) {
			list_add_tail(&pkt->next, &q->queue);
			mpkt->pkt[i] = NULL;
		}
	}

	return 0;
}

int
pkt_queue_mput(pkt_queue_t *q, mpkt_t *mpkt)
{
	pthread_mutex_lock(&q->mutex);
	__pkt_queue_mput(q, mpkt);
	pthread_mutex_unlock(&q->mutex);

	return 0;
}


/*
 *	Pkt buffer helpers
 */
ssize_t
pkt_buffer_send(int fd, pkt_buffer_t *b, struct sockaddr_storage *addr)
{
	struct iovec iov = { .iov_base = b->head, .iov_len = pkt_buffer_len(b) };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0
	};

	if (addr->ss_family == AF_INET) {
		msg.msg_name = (struct sockaddr_in *) addr;
		msg.msg_namelen = sizeof(struct sockaddr_in);
	} else if (addr->ss_family == AF_INET6) {
		msg.msg_name = (struct sockaddr_in6 *) addr;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
	} else
		return -1;

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
