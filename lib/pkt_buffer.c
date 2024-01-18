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
#include "pkt_buffer.h"

int
pkt_buffer_put_zero(pkt_buffer_t *b, unsigned int size)
{
	if (pkt_buffer_tailroom(b) < size)
		return -1;

	memset(b->end, 0, size);
	b->end += size;
	return 0;
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
