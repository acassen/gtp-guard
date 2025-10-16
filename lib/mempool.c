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
 * Authors:     Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2011, 2012, 2013, 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

#include "utils.h"
#include "mempool.h"

/*
 * mpool: light memory pool library.
 *
 * on a mpool context: each malloc() is kept in linked list.
 * when mpool is destroyed,  * everything is released without having
 * to manually free() things.
 *
 * it is possible to pre-allocate a memory area, to limit number of malloc().
 * it works best for short-lived mpool with lots of small alloc.
 *
 *  === basic usage:
 * void foo() {
 *    struct mpool mp = MPOOL_INIT(mp);
 *    mpool_init(&mp);  // alternative to MPOOL_INIT
 *    void *data = mpool_malloc(&mp, 8000);
 *    char *str = mpool_strdup(&mp, "string_to_copy");
 *    for (int i = 0; i < 50; i++)
 *        str = mpool_asprintf(&mp, "string copy %d", i);
 *
 *    // individual free() are possible, but not required and not expected
 *    mpool_free(data);
 *
 *    [...]
 *    mpool_release(&mp);  // free everything !
 * }
 *
 * === object oriented usage:
 *  struct mydata {
 *    struct mpool mp;  // must be the first element
 *    int type;
 *    [...]
 *  };
 *
 *  void foo2() {
 *    struct mydata *d;
 *
 *    d = mpool_new(sizeof(*d));
 *    d->type = 987;
 *    char *str = mpool_strdup(&d->mp, "lalala");
 *    [....]
 *    mpool_release(&d->mp);  // also free d
 *  }
 *
 * === pre-allocation:
 * void foo3() {
 *    struct mpool mp;
 *    mpool_init(&mp);
 *    mpool_prealloc(&mp, 8000);
 *    // following mpool_* are using pre-allocated area (no libc alloc)
 *    for (int i = 0; i < 50; i++)
 *        str = mpool_asprintf(&mp, "string copy %d", i);
 *
 *    void *data = mpool_malloc(&mp, 600);
 *    // works, but preallocated area is not really freed.
 *    mpool_free(data);
 *
 *    // works: when preallocated zone is not big enough, it
 *    // reverts to libc malloc().
 *    void *big_data = mpool_malloc(&mp, 50000);
 *
 *    [...]
 *    mpool_release(&mp);
 * }
 *
 */

#define CHUNK_FL_PREALLOC_AREA		0x01
#define CHUNK_FL_IS_PREALLOCATED	0x02

struct mpool_chunk
{
	struct list_head	list;
	uint32_t		size;
	uint32_t		flags;
	uint8_t			data[0];
};

struct mpool_prealloc_area
{
	uint32_t		idx;
	uint32_t		_reserved;
	uint8_t			data[0];
};


/* allocate a struct, having a mandatory 'struct mpool' on first field. */
void *
mpool_new(size_t size)
{
	struct mpool_chunk *c;
	struct mpool *mp;

	c = calloc(1, sizeof (*c) + size);
	if (unlikely(c == NULL))
		return NULL;
	c->size = size;
	c->flags = 0;
	mp = (struct mpool *)c->data;
	mpool_init(mp);
	list_add(&c->list, &mp->head);

	return c->data;
}

static inline void *
_mpool_alloc(struct mpool *mp, size_t size, bool zeromem)
{
	struct mpool_prealloc_area *pa;
	struct mpool_chunk *c, *sc;
	size_t asize;

	if (!list_empty(&mp->head)) {
		c = list_first_entry(&mp->head, struct mpool_chunk, list);
		if (c->flags & CHUNK_FL_PREALLOC_AREA) {
			pa = (struct mpool_prealloc_area *)c->data;
			asize = ALIGN(size, 8);
			if (pa->idx + sizeof (*c) + asize <= c->size) {
				sc = (struct mpool_chunk *)(pa->data + pa->idx);
				sc->size = asize;
				sc->flags = CHUNK_FL_IS_PREALLOCATED;
				pa->idx += sizeof (*sc) + asize;
				if (zeromem)
					memset(sc->data, 0x00, size);
				return sc->data;
			}
		}
		/* no enough space in prealloc_area, fallback to malloc() */
	}

	if (zeromem)
		c = calloc(1, sizeof (*c) + size);
	else
		c = malloc(sizeof (*c) + size);
	if (unlikely(c == NULL))
		return NULL;
	c->size = size;
	c->flags = 0;
	list_add_tail(&c->list, &mp->head);

	return c->data;
}

void *
mpool_malloc(struct mpool *mp, size_t size)
{
	return _mpool_alloc(mp, size, false);
}

void *
mpool_zalloc(struct mpool *mp, size_t size)
{
	return _mpool_alloc(mp, size, true);
}

void *
mpool_realloc(struct mpool *mp, void *old_data, size_t size)
{
	struct mpool_chunk *oc;
	void *d;

	if (old_data == NULL)
		return _mpool_alloc(mp, size, false);

	oc = container_of(old_data, struct mpool_chunk, data);
	if (oc->size >= size)
		return oc->data;

	d = _mpool_alloc(mp, size, false);
	if (unlikely(d == NULL))
		return NULL;
	memcpy(d, oc->data, oc->size);

	if (!(oc->flags & CHUNK_FL_IS_PREALLOCATED)) {
		list_del(&oc->list);
		free(oc);
	}

	return d;
}

void *
mpool_zrealloc(struct mpool *mp, void *old_data, size_t size)
{
	struct mpool_chunk *oc;
	void *d;

	if (old_data == NULL)
		return _mpool_alloc(mp, size, true);

	oc = container_of(old_data, struct mpool_chunk, data);
	if (oc->size >= size)
		return oc->data;

	d = _mpool_alloc(mp, size, false);
	if (unlikely(d == NULL))
		return NULL;
	memcpy(d, oc->data, oc->size);
	memset(d + oc->size, 0x00, size - oc->size);

	if (!(oc->flags & CHUNK_FL_IS_PREALLOCATED)) {
		list_del(&oc->list);
		free(oc);
	}

	return d;
}

void
mpool_free(void *data)
{
	struct mpool_chunk *c;

	c = container_of(data, struct mpool_chunk, data);
	if (!(c->flags & CHUNK_FL_IS_PREALLOCATED)) {
		list_del(&c->list);
		free(c);
	}
}

void *
mpool_memdup(struct mpool *mp, const void *src, size_t size)
{
	void *out;

	out = _mpool_alloc(mp, size, false);
	if (out)
		memcpy(out, src, size);

	return out;
}

char *
mpool_strdup(struct mpool *mp, const char *src)
{
	int l = strlen(src);
	char *out;

	out = _mpool_alloc(mp, l + 1, false);
	if (out) {
		strcpy(out, src);
		out[l] = 0;
	}

	return out;
}

char *
mpool_asprintf(struct mpool *mp, const char *fmt, ...)
{
	char buf[4096];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	return mpool_strdup(mp, buf);
}

void
mpool_release(struct mpool *mp)
{
	struct mpool_chunk *b, *b_tmp;
	struct list_head thead;

	if (list_empty(&mp->head))
		return;

	thead = mp->head;
	thead.next->prev = &thead;
	thead.prev->next = &thead;
	list_for_each_entry_safe(b, b_tmp, &thead, list) {
		free(b);
	}
}

int
mpool_prealloc(struct mpool *mp, size_t size)
{
	struct mpool_prealloc_area *mpa;
	struct mpool_chunk *b;

	size = ALIGN(size, 8);
	b = malloc(sizeof (*b) + sizeof (*mpa) + size);
	if (unlikely(b == NULL))
		return -1;
	b->size = size;
	b->flags = CHUNK_FL_PREALLOC_AREA;
	mpa = (struct mpool_prealloc_area *)b->data;
	mpa->idx = 0;
	list_add(&b->list, &mp->head);
	return 0;
}
