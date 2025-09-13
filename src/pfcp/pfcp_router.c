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

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "gtp_data.h"
#include "pfcp_router.h"
#include "pfcp_server.h"
#include "pfcp_router_hdl.h"
#include "utils.h"
#include "memory.h"


/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Helpers
 */
int
pfcp_router_ingress_init(struct inet_server *s)
{
	return 0;
}

int
pfcp_router_ingress_process(struct inet_server *srv, struct sockaddr_storage *addr_from)
{
	struct pfcp_server *s = srv->ctx;
	int ret;

	ret = pfcp_router_handle(s, addr_from);
	if (ret < 0)
		return -1;

	if (ret != PFCP_ROUTER_DELAYED)
		inet_server_snd(srv, srv->fd, srv->pbuff,
				(struct sockaddr_in *) addr_from);

	return 0;
}



/*
 *	PFCP Router utilities
 */
size_t
pfcp_router_dump(struct pfcp_router *ctx, char *buffer, size_t bsize)
{
	memset(buffer, 0, bsize);

	return 0;
}

bool
pfcp_router_inuse(void)
{
	return !list_empty(&daemon_data->pfcp_router_ctx);
}

void
pfcp_router_foreach(int (*hdl) (struct pfcp_router *, void *), void *arg)
{
	struct list_head *l = &daemon_data->pfcp_router_ctx;
	struct pfcp_router *ctx;

	list_for_each_entry(ctx, l, next)
		(*(hdl)) (ctx, arg);
}

struct pfcp_router *
pfcp_router_get(const char *name)
{
	struct pfcp_router *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->pfcp_router_ctx, next) {
		if (!strncmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

struct pfcp_router *
pfcp_router_init(const char *name)
{
	struct pfcp_router *new;

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
        INIT_LIST_HEAD(&new->next);
        bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);

	list_add_tail(&new->next, &daemon_data->pfcp_router_ctx);

	return new;
}

int
pfcp_router_ctx_server_destroy(struct pfcp_router *ctx)
{
	pfcp_server_destroy(&ctx->s);
	return 0;
}

int
pfcp_router_ctx_destroy(struct pfcp_router *ctx)
{
	list_head_del(&ctx->next);
	return 0;
}

int
pfcp_router_server_destroy(void)
{
	struct pfcp_router *c;

	list_for_each_entry(c, &daemon_data->pfcp_router_ctx, next)
		pfcp_router_ctx_server_destroy(c);

	return 0;
}

int
pfcp_router_destroy(void)
{
	struct pfcp_router *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->pfcp_router_ctx, next) {
		list_head_del(&c->next);
		FREE(c);
	}

	return 0;
}
