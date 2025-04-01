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

#ifndef _PKT_BUFFER_H
#define _PKT_BUFFER_H

/* defines */
#define DEFAULT_PKT_BUFFER_SIZE	4096

/* pkt related */
typedef struct _pkt_buffer {
	unsigned char		*head,
				*data;
	unsigned char		*end;
	unsigned char		*tail;
} pkt_buffer_t;

typedef struct _pkt {
	pkt_buffer_t		*pbuff;

	list_head_t		next;
} pkt_t;

typedef struct _mpkt {
	unsigned int		vlen;
	struct mmsghdr		*msgs;
	struct iovec		*iovecs;
	pkt_t			**pkt;
} mpkt_t;

typedef struct _pkt_queue {
	pthread_mutex_t		mutex;
	list_head_t		queue;
} pkt_queue_t;

static inline unsigned int pkt_buffer_len(pkt_buffer_t *b)
{
	return b->end - b->head;
}

static inline unsigned int pkt_buffer_size(pkt_buffer_t *b)
{
	return b->tail - b->head;
}

static inline unsigned int pkt_buffer_headroom(pkt_buffer_t *b)
{
	return b->data - b->head;
}

static inline unsigned int pkt_buffer_tailroom(pkt_buffer_t *b)
{
	return b->tail - b->end;
}

static inline unsigned char *pkt_buffer_end(pkt_buffer_t *b)
{
	return b->end;
}

static inline void pkt_buffer_reset(pkt_buffer_t *b)
{
	b->data = b->end = b->head;
}

static inline void pkt_buffer_set_end_pointer(pkt_buffer_t *b, unsigned int offset)
{
	b->end = b->head + offset;
}

static inline void pkt_buffer_set_data_pointer(pkt_buffer_t *b, unsigned int offset)
{
	b->data = b->head + offset;
}

static inline void pkt_buffer_put_data(pkt_buffer_t *b, unsigned int offset)
{
	b->data += offset;
}

static inline void pkt_buffer_put_end(pkt_buffer_t *b, unsigned int offset)
{
	b->end += offset;
}

/* Prototypes */
extern ssize_t pkt_send(int fd, pkt_queue_t *, pkt_t *);
extern ssize_t pkt_recv(int fd, pkt_t *);
extern int mpkt_recv(int, mpkt_t *);
extern void pkt_queue_run(pkt_queue_t *, int (*run) (pkt_t *, void *), void *);
extern pkt_t *pkt_queue_get(pkt_queue_t *);
extern int __pkt_queue_put(pkt_queue_t *, pkt_t *);
extern int pkt_queue_put(pkt_queue_t *, pkt_t *);
extern int mpkt_init(mpkt_t *, unsigned int);
extern void mpkt_process(mpkt_t *, unsigned int, void (*process) (pkt_t *, void *), void *);
extern void mpkt_destroy(mpkt_t *);
extern void mpkt_reset(mpkt_t *);
extern int __pkt_queue_mget(pkt_queue_t *, mpkt_t *);
extern int pkt_queue_mget(pkt_queue_t *, mpkt_t *);
extern int __pkt_queue_mput(pkt_queue_t *, mpkt_t *);
extern int pkt_queue_mput(pkt_queue_t *, mpkt_t *);
extern int pkt_queue_init(pkt_queue_t *);
extern int pkt_queue_destroy(pkt_queue_t *);
extern ssize_t pkt_buffer_send(int, pkt_buffer_t *, struct sockaddr_storage *);
extern int pkt_buffer_put_zero(pkt_buffer_t *, unsigned int);
extern int pkt_buffer_pad(pkt_buffer_t *, unsigned int);
extern pkt_buffer_t *pkt_buffer_alloc(unsigned int);
extern void pkt_buffer_free(pkt_buffer_t *);

#endif
