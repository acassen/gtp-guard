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

#ifndef _PKT_BUFFER_H
#define _PKT_BUFFER_H

/* defines */
typedef struct _pkt_buffer {
	unsigned char		*head,
				*data;
	unsigned char		*end;
	unsigned char		*tail;
} pkt_buffer_t;


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

/* Prototypes */
extern int pkt_buffer_put_zero(pkt_buffer_t *, unsigned int);
extern pkt_buffer_t *pkt_buffer_alloc(unsigned int);
extern void pkt_buffer_free(pkt_buffer_t *);

#endif
