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

#pragma once

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "list_head.h"

/* defines */
#define DEFAULT_PKT_BUFFER_SIZE	4096
#define DEFAULT_PKT_QUEUE_SIZE	128

/* pkt related */
struct pkt_buffer {
	unsigned char		*head,
				*data;
	unsigned char		*end;
	unsigned char		*tail;
};

struct pkt {
	struct pkt_buffer	*pbuff;

	struct list_head	next;
};

struct mpkt {
	unsigned int		vlen;
	struct mmsghdr		*msgs;
	struct iovec		*iovecs;
	struct pkt		**pkt;
};

struct pkt_queue {
	pthread_mutex_t		mutex;
	struct list_head	queue;
	int			size;
	int			max_size;
};

static inline unsigned int pkt_buffer_len(struct pkt_buffer *b)
{
	return b->end - b->head;
}

static inline unsigned int pkt_buffer_size(struct pkt_buffer *b)
{
	return b->tail - b->head;
}

static inline unsigned int pkt_buffer_headroom(struct pkt_buffer *b)
{
	return b->data - b->head;
}

static inline unsigned int pkt_buffer_tailroom(struct pkt_buffer *b)
{
	return b->tail - b->end;
}

static inline unsigned char *pkt_buffer_end(struct pkt_buffer *b)
{
	return b->end;
}

static inline void pkt_buffer_reset(struct pkt_buffer *b)
{
	b->data = b->end = b->head;
}

static inline void pkt_buffer_set_end_pointer(struct pkt_buffer *b, unsigned int offset)
{
	b->end = b->head + offset;
}

static inline void pkt_buffer_set_data_pointer(struct pkt_buffer *b, unsigned int offset)
{
	b->data = b->head + offset;
}

static inline void pkt_buffer_put_data(struct pkt_buffer *b, unsigned int offset)
{
	b->data += offset;
}

static inline void pkt_buffer_put_end(struct pkt_buffer *b, unsigned int offset)
{
	b->end += offset;
}

/* Prototypes */
ssize_t pkt_send(int fd, struct pkt_queue *q, struct pkt *p);
ssize_t pkt_recv(int fd, struct pkt *p);
void pkt_queue_run(struct pkt_queue *q, int (*run) (struct pkt *, void *), void *arg);
struct pkt *__pkt_queue_get(struct pkt_queue *q);
struct pkt *pkt_queue_get(struct pkt_queue *q);
int __pkt_queue_put(struct pkt_queue *q, struct pkt *p);
int pkt_queue_put(struct pkt_queue *, struct pkt *p);
int pkt_queue_init(struct pkt_queue *q, int max_size);
int pkt_queue_destroy(struct pkt_queue *q);
int mpkt_dump(struct mpkt *p, int count);
int mpkt_recv(int fd, struct mpkt *mp);
int mpkt_init(struct mpkt *p, unsigned int vlen);
void mpkt_process(struct mpkt *mp, unsigned int, void (*process) (struct pkt *, void *), void *arg);
void mpkt_destroy(struct mpkt *mp);
void mpkt_reset(struct mpkt *mp);
int __pkt_queue_mget(struct pkt_queue *q, struct mpkt *mp);
int pkt_queue_mget(struct pkt_queue *q, struct mpkt *mp);
int __pkt_queue_mput(struct pkt_queue *q, struct mpkt *mp);
int pkt_queue_mput(struct pkt_queue *q, struct mpkt *mp);
ssize_t pkt_buffer_send(int fd, struct pkt_buffer *b, struct sockaddr_storage *addr);
int pkt_buffer_put_zero(struct pkt_buffer *pkt, unsigned int size);
int pkt_buffer_pad(struct pkt_buffer *b, unsigned int size);
struct pkt_buffer *pkt_buffer_alloc(unsigned int size);
void pkt_buffer_free(struct pkt_buffer *b);
