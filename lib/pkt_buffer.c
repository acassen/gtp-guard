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

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "memory.h"
#include "utils.h"
#include "pkt_buffer.h"


/*
 *	Pkt helpers
 */
ssize_t
pkt_send(int fd, pkt_queue_t *q, pkt_t *p)
{
	ssize_t ret;

	ret = send(fd, p->pbuff->head, pkt_buffer_len(p->pbuff), 0);
	pkt_queue_put(q, p);
	return ret;
}

ssize_t
pkt_recv(int fd, pkt_t *p)
{
	ssize_t nbytes;

	nbytes = recv(fd, p->pbuff->head, pkt_buffer_size(p->pbuff), 0);
	if (nbytes < 0)
		return -1;

	pkt_buffer_set_end_pointer(p->pbuff, nbytes);
	return nbytes;
}


/*
 *	Pkt queue helpers
 */
void
pkt_queue_run(pkt_queue_t *q, int (*run) (pkt_t *, void *), void *arg)
{
	pkt_t *p, *_p;

	pthread_mutex_lock(&q->mutex);
	list_for_each_entry_safe(p, _p, &q->queue, next) {
		list_del_init(&p->next);

		pthread_mutex_unlock(&q->mutex);
		(*run) (p, arg);
		pthread_mutex_lock(&q->mutex);
	}
	pthread_mutex_unlock(&q->mutex);
}

static pkt_t *
pkt_alloc(unsigned int size)
{
	pkt_t *p;

	PMALLOC(p);
	if (!p)
		return NULL;

	INIT_LIST_HEAD(&p->next);
	p->pbuff = pkt_buffer_alloc(size);
	if (!p->pbuff) {
		FREE(p);
		p = NULL;
	}
	return p;
}

static void
pkt_free(pkt_t *p)
{
	pkt_buffer_free(p->pbuff);
	FREE(p);
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
__pkt_queue_put(pkt_queue_t *q, pkt_t *p)
{
	if (!p)
		return -1;

	list_add_tail(&p->next, &q->queue);
	return 0;
}

int
pkt_queue_put(pkt_queue_t *q, pkt_t *p)
{
	pthread_mutex_lock(&q->mutex);
	__pkt_queue_put(q, p);
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
mpkt_dump(mpkt_t *mp, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		printf("-=[ pkt #%d (%d) ]=-\n",
			i, pkt_buffer_len(mp->pkt[i]->pbuff));
		dump_buffer(" ", (char *) mp->pkt[i]->pbuff->head
			       , pkt_buffer_len(mp->pkt[i]->pbuff));
	}

	return 0;
}

int
mpkt_recv(int fd, mpkt_t *mp)
{
	int ret, i;

	ret = recvmmsg(fd, mp->msgs, mp->vlen, MSG_WAITFORONE, NULL);
	if (ret < 0)
		return -1;

	for (i = 0; i < ret; i++)
		pkt_buffer_set_end_pointer(mp->pkt[i]->pbuff, mp->msgs[i].msg_len);

	return ret;
}

int
mpkt_init(mpkt_t *mp, unsigned int vlen)
{
	mp->vlen = vlen;
	mp->pkt = MALLOC(sizeof(pkt_t) * vlen);
	if (!mp->pkt)
		return -1;
	mp->msgs = MALLOC(sizeof(struct mmsghdr) * vlen);
	if (!mp->msgs) {
		FREE(mp->pkt);
		return -1;
	}
	mp->iovecs = MALLOC(sizeof(struct iovec) * vlen);
	if (!mp->iovecs) {
		FREE(mp->pkt);
		FREE(mp->msgs);
		return -1;
	}

	return 0;
}

void
mpkt_process(mpkt_t *mp, unsigned int vlen, void (*process) (pkt_t *, void *), void *arg)
{
	int i;

	for (i = 0; i < vlen; i++)
		(*process) (mp->pkt[i], arg);
}

static void
mpkt_release(mpkt_t *mp)
{
	int i;
	for (i=0; i < mp->vlen; i++) {
		if (mp->pkt[i]) {
			pkt_free(mp->pkt[i]);
		}
	}

	FREE(mp->pkt);
}

void
mpkt_destroy(mpkt_t *mp)
{
	mpkt_release(mp);
	FREE(mp->msgs);
	FREE(mp->iovecs);
}

static int
mpkt_alloc(mpkt_t *mp, unsigned int size)
{
	pkt_t *pkt;
	int i;

	for (i=0; i < mp->vlen; i++) {
		pkt = pkt_alloc(size);
		if (!pkt)
			return -1;
		mp->pkt[i] = pkt;
	}

	return 0;
}

static void
mpkt_prepare(mpkt_t *mp)
{
	int i;

	for (i = 0; i < mp->vlen; i++) {
		mp->iovecs[i].iov_base = mp->pkt[i]->pbuff->head;
		mp->iovecs[i].iov_len = pkt_buffer_size(mp->pkt[i]->pbuff);
		mp->msgs[i].msg_hdr.msg_iov = &mp->iovecs[i];
		mp->msgs[i].msg_hdr.msg_iovlen = 1;
	}
}

void
mpkt_reset(mpkt_t *mp)
{
	int i;

	for (i = 0; i < mp->vlen; i++)
		pkt_buffer_reset(mp->pkt[i]->pbuff);
}

int
__pkt_queue_mget(pkt_queue_t *q, mpkt_t *mp)
{
	pkt_t *pkt, *_pkt;
	int ret, i, idx = 0;

	if (list_empty(&q->queue)) {
		ret = mpkt_alloc(mp, DEFAULT_PKT_BUFFER_SIZE);
		if (ret < 0) {
			mpkt_release(mp);
			return -1;
		}

		goto end;
	}

	list_for_each_entry_safe(pkt, _pkt, &q->queue, next) {
		if (idx >= mp->vlen) {
			goto end;
		}

		list_del_init(&pkt->next);
		pkt_buffer_reset(pkt->pbuff);
		mp->pkt[idx++] = pkt;

	}

	/* Not fully filled */
	for (i=idx; i < mp->vlen; i++) {
		pkt = pkt_alloc(DEFAULT_PKT_BUFFER_SIZE);
		if (!pkt) {
			mpkt_release(mp);
			return -1;
		}

		mp->pkt[i] = pkt;
	}

  end:
	/* Prepare mpkt */
	mpkt_prepare(mp);
	return 0;
}

int
pkt_queue_mget(pkt_queue_t *q, mpkt_t *mp)
{
	pthread_mutex_lock(&q->mutex);
	__pkt_queue_mget(q, mp);
	pthread_mutex_unlock(&q->mutex);
	return 0;
}

int
__pkt_queue_mput(pkt_queue_t *q, mpkt_t *mp)
{
	pkt_t *pkt;
	int i;

	for (i=0; i < mp->vlen; i++) {
		pkt = mp->pkt[i];
		if (pkt) {
			list_add_tail(&pkt->next, &q->queue);
			mp->pkt[i] = NULL;
		}
	}

	return 0;
}

int
pkt_queue_mput(pkt_queue_t *q, mpkt_t *mp)
{
	pthread_mutex_lock(&q->mutex);
	__pkt_queue_mput(q, mp);
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

	switch (addr->ss_family) {
	case AF_INET:
		msg.msg_name = (struct sockaddr_in *) addr;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		msg.msg_name = (struct sockaddr_in6 *) addr;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;
	default:
		return -1;
	}

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
