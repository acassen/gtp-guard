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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <assert.h>

#include "gtp_data.h"
#include "pfcp_router.h"
#include "memory.h"


/* Extern data */
extern data_t *daemon_data;


/*
 *	PFCP utilities
 */
int
pfcp_router_dump(pfcp_router_t *c, char *buffer, size_t bsize)
{
	return 0;
}

pfcp_router_t *
pfcp_router_get_by_name(const char *name)
{
	list_head_t *l = &daemon_data->pfcp_router_ctx;
	pfcp_router_t *c;

	list_for_each_entry(c, l, next) {
		if (!strcmp(c->name, name))
			return c;
	}

	return NULL;
}

pfcp_router_t *
pfcp_router_alloc(const char *name)
{
	pfcp_router_t *c = NULL;

	PMALLOC(c);
	assert(c != NULL);
	snprintf(c->name, GTP_NAME_MAX_LEN, "%s", name);
	list_add_tail(&c->next, &daemon_data->pfcp_router_ctx);

	return c;
}

void
pfcp_router_release(pfcp_router_t *c)
{
	list_del(&c->next);
	free(c);
}


/*
 *	PFCP Router init/pfcp_destroy
 */
int
pfcp_router_init(void)
{
	return 0;
}

int
pfcp_router_destroy(void)
{
	list_head_t *l = &daemon_data->pfcp_router_ctx;
	pfcp_router_t *c, *_c;

	list_for_each_entry_safe(c, _c, l, next) {
		pfcp_router_release(c);
	}

	return 0;
}
