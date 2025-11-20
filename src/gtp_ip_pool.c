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

#include <string.h>

#include "gtp_data.h"
#include "gtp_ip_pool.h"
#include "ip_pool.h"
#include "bitops.h"


/* Extern data */
extern struct data *daemon_data;

/*
 *	IP Pool init
 */
struct gtp_ip_pool *
gtp_ip_pool_get(const char *name)
{
	struct gtp_ip_pool *p;
	size_t len = strlen(name);

	list_for_each_entry(p, &daemon_data->ip_pool, next) {
		if (!memcmp(p->name, name, len)) {
			__sync_add_and_fetch(&p->refcnt, 1);
			return p;
		}
	}

	return NULL;
}

int
gtp_ip_pool_put(struct gtp_ip_pool *p)
{
	if (!p)
		return -1;

	__sync_sub_and_fetch(&p->refcnt, 1);
	return 0;
}


struct gtp_ip_pool *
gtp_ip_pool_alloc(const char *name)
{
	struct gtp_ip_pool *new;

	new = calloc(1, sizeof(*new));
	if (!new)
		return NULL;

        INIT_LIST_HEAD(&new->next);
        strncpy(new->name, name, GTP_NAME_MAX_LEN - 1);
        list_add_tail(&new->next, &daemon_data->ip_pool);
	__set_bit(GTP_IP_POOL_FL_SHUTDOWN, &new->flags);

	return new;
}


int
gtp_ip_pool_free(struct gtp_ip_pool *p)
{
	ip_pool_destroy(p->pool);
	list_head_del(&p->next);
	free(p);
	return 0;
}

int
gtp_ip_pool_destroy(void)
{
	struct gtp_ip_pool *p, *_p;

	list_for_each_entry_safe(p, _p, &daemon_data->ip_pool, next) {
		gtp_ip_pool_free(p);
	}

	return 0;
}

int
gtp_ip_pool_init(void)
{
	return 0;
}
