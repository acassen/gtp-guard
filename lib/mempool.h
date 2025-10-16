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
#pragma once

#include "list_head.h"

#define MPOOL_DEFAULT_SIZE	8192

struct mpool
{
	struct list_head	head;
};

void *mpool_new(size_t size);
void *mpool_malloc(struct mpool *mp, size_t size);
void *mpool_zalloc(struct mpool *mp, size_t size);
void *mpool_realloc(struct mpool *mp, void *old_data, size_t size);
void *mpool_zrealloc(struct mpool *mp, void *old_data, size_t size);
void mpool_free(void *data);
static void mpool_xfree(void *data);
void *mpool_memdup(struct mpool *mp, const void *src, size_t size);
char *mpool_strdup(struct mpool *mp, const char *src);
static char *mpool_xstrdup(struct mpool *mp, const char *src);
char *mpool_asprintf(struct mpool *mp, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

int mpool_prealloc(struct mpool *mp, size_t size);
static void mpool_move(struct mpool *dst, struct mpool *src);

static void mpool_init(struct mpool *mp);
void mpool_release(struct mpool *mp);

#define MPOOL_INIT(name) { { &((name).head), &((name).head) } }

static inline void
mpool_init(struct mpool *mp)
{
	INIT_LIST_HEAD(&mp->head);
}

static inline void
mpool_move(struct mpool *dst, struct mpool *src)
{
	list_splice_init(&src->head, &dst->head);
}

static inline void
mpool_xfree(void *data)
{
	if (data != NULL)
		mpool_free(data);
}

static inline char *
mpool_xstrdup(struct mpool *mp, const char *src)
{
	if (src != NULL)
		return mpool_strdup(mp, src);
	return NULL;
}

