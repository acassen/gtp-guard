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

#ifndef _MPOOL_H
#define _MPOOL_H

/* Defines */
#define MEM_DEFAULT_SIZE	65541
#define MPOOL_DEFAULT_SIZE	10

/* Types */
typedef struct _mem {
	struct _mem	*next;
	struct _mem	*prev;

	void		*data;			/* Raw data pointer */
	unsigned int	size;			/* Raw data size */
	unsigned int	offset;			/* Offset of data used */
	int		type;
} mem_t;

typedef struct _mem_pool {
	mem_t		*head;
	mem_t		*tail;

	unsigned int	count;
} mem_pool_t;


/* Macros */
#define MPOOL_SIZE(P)		((P)->count)
#define MPOOL_ISEMPTY(P)	((P)->count == 0)
#define MPOOL_TAIL(P)		((P)->tail)
#define MPOOL_DATA(P)		((P)->data)


/* Prototypes */
extern void mpool_dump(mem_pool_t *);
extern void mpool_queue_tail(mem_pool_t *, mem_t *);
extern mem_t *mpool_dequeue(mem_pool_t *);
extern mem_t *mpool_allocate_mem(int);
extern mem_t *mpool_dup_mem(mem_t *);
extern mem_t *mpool_create_mem(char *, int);
extern void mpool_release_mem(mem_t *);
extern void mpool_fill(mem_pool_t *, int, int);
extern mem_pool_t *mpool_init(void);
extern void mpool_destroy(mem_pool_t *);
extern void mpool_move(mem_pool_t *, mem_pool_t *);

#endif
