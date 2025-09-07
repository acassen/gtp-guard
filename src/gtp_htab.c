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

#include "gtp_htab.h"
#include "memory.h"
#include "list_head.h"


/*
 *	HTAB handling
 */
void
gtp_htab_init(struct gtp_htab *h, size_t size)
{
	h->htab = (struct hlist_head *) MALLOC(sizeof(struct hlist_head) * size);
}

struct gtp_htab *
gtp_htab_alloc(size_t size)
{
	struct gtp_htab *new;

	PMALLOC(new);
	if (!new)
		return NULL;
	gtp_htab_init(new, size);

	return new;
}

void
gtp_htab_destroy(struct gtp_htab *h)
{
	FREE(h->htab);
}

void
gtp_htab_free(struct gtp_htab *h)
{
	FREE(h);
}
