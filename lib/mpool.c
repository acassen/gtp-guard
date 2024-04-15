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

/* global includes */
#include <stdlib.h>
#include <unistd.h>

/* local includes */
#include "memory.h"
#include "mpool.h"


/*
 *	Dump memory pool
 */
void
mpool_dump(mem_pool_t *mpool)
{
	mem_t *mem;
	int i = 0;

	printf("mpool size = %d\n", MPOOL_SIZE(mpool));

	for (mem = mpool->head; mem; mem = mem->next)
		printf(" %.2d size=%d offset=%d\n", ++i, mem->size, mem->offset);
}

/*
 *	Queue memory element
 */
void
mpool_queue_tail(mem_pool_t *mpool, mem_t *mem)
{
	/* Return on empty stuff */
	if (!mpool || !mem)
		return;

	/* Queue this mem */
	mem->prev = mpool->tail;
	mem->next = NULL;

	if (mpool->head == NULL)
		mpool->head = mem;
	else
		mpool->tail->next = mem;

	mpool->tail = mem;
	mpool->count++;
}

/*
 *	Dequeue a memory element
 */
mem_t *
mpool_dequeue(mem_pool_t *mpool)
{
	mem_t *mem;

	/* Queue is empty */
	if (MPOOL_ISEMPTY(mpool))
		return NULL;

	/* Fetch head */
	mem = mpool->head;
	mpool->head = mem->next;
	if (mem->next)
		mem->next->prev = NULL;
	mpool->count--;

	return mem;
}

/*
 *	Allocate new memory element
 */
mem_t *
mpool_allocate_mem(int size)
{
	mem_t *mem = (mem_t *) MALLOC(sizeof(mem_t));
	mem->data = (char *) MALLOC(size);
	mem->size = size;
	return mem;
}

/*
 *	Create a new memory element
 */
mem_t *
mpool_create_mem(char *buffer, int size)
{
	mem_t *mem = (mem_t *) MALLOC(sizeof(mem_t));
	mem->data = (char *) MALLOC(size);
	mem->size = mem->offset = size;
	memcpy(mem->data, buffer, size);
	return mem;
}

/*
 *	Duplicate memory element
 */
mem_t *
mpool_dup_mem(mem_t *mem)
{
	mem_t *new = (mem_t *) MALLOC(sizeof(mem_t));
	new->data = (char *) MALLOC(mem->size);
	new->size = mem->size;
	new->offset = mem->offset;
	memcpy(new->data, mem->data, mem->offset);
	return new;
}


/*
 *	Release a memory element
 */
void
mpool_release_mem(mem_t *mem)
{
	FREE(mem->data);
	FREE(mem);
}

/*
 *	Fill mempool with brand new mem bucket
 */
void
mpool_fill(mem_pool_t *mpool, int count, int size)
{
	mem_t *mem;
	int i;

	/* Pre-allocate pool element */
	for (i=0; i < count; i++) {
		mem = mpool_allocate_mem(size);
		mpool_queue_tail(mpool, mem);
	}
}

/*
 *	Initialize a New memory Pool
 */
mem_pool_t *
mpool_init(void)
{
	mem_pool_t *mpool;

	/* Allocate root pool */
	mpool = (mem_pool_t *) MALLOC(sizeof(mem_pool_t));
	mpool->head = mpool->tail = NULL;

	return mpool;
}

/*
 *	Destroy a memory pool
 */
void
mpool_destroy(mem_pool_t *mpool)
{
	mem_t *mem = NULL;
	mem_t *next = NULL;

	if (!mpool)
		return;

	for (mem = mpool->head; mem; mem = next) {
		next = mem->next;
		mpool_release_mem(mem);
	}

	FREE(mpool);
}

/*
 *	Flush and merge memory pool
 */
void
mpool_move(mem_pool_t *src, mem_pool_t *dst)
{
	mem_t *mem = NULL;

	if (!src || MPOOL_ISEMPTY(src))
		return;

	while ((mem = mpool_dequeue(src)))
		mpool_queue_tail(dst, mem);

	src->tail = src->head = NULL;
	src->count = 0;
}
