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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <errno.h>

#include "gtp_data.h"
#include "gtp_server.h"
#include "gtp_router.h"
#include "gtp_router_hdl.h"
#include "bitops.h"
#include "inet_server.h"
#include "memory.h"
#include "utils.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Helpers
 */
int
gtp_router_ingress_init(struct inet_server *srv)
{
	return 0;
}

int
gtp_router_ingress_process(struct inet_server *srv, struct sockaddr_storage *addr_from)
{
	struct gtp_server *s = srv->ctx;
	int ret;

	ret = __test_bit(GTP_FL_UPF_BIT, &s->flags) ? gtpu_router_handle(s, addr_from) :
						      gtpc_router_handle(s, addr_from);
	if (ret < 0)
		return -1;

	if (ret != GTP_ROUTER_DELAYED)
		inet_server_snd(srv, srv->fd, srv->pbuff,
				(struct sockaddr_in *) addr_from);
	return 0;
}


/*
 *	GTP Router utilities
 */
bool
gtp_router_inuse(void)
{
	return !list_empty(&daemon_data->gtp_router_ctx);
}

void
gtp_router_foreach(int (*hdl) (struct gtp_router *, void *), void *arg)
{
	struct list_head *l = &daemon_data->gtp_router_ctx;
	struct gtp_router *ctx;

	list_for_each_entry(ctx, l, next)
		(*(hdl)) (ctx, arg);
}

struct gtp_router *
gtp_router_get(const char *name)
{
	struct gtp_router *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->gtp_router_ctx, next) {
		if (!strncmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

struct gtp_router *
gtp_router_init(const char *name)
{
	struct gtp_router *new;

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
        INIT_LIST_HEAD(&new->next);
        bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);

	list_add_tail(&new->next, &daemon_data->gtp_router_ctx);

	return new;
}

int
gtp_router_ctx_server_destroy(struct gtp_router *ctx)
{
	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpu);
	return 0;
}

int
gtp_router_ctx_destroy(struct gtp_router *ctx)
{
	list_head_del(&ctx->next);
	return 0;
}

int
gtp_router_server_destroy(void)
{
	struct gtp_router *c;

	list_for_each_entry(c, &daemon_data->gtp_router_ctx, next)
		gtp_router_ctx_server_destroy(c);

	return 0;
}

int
gtp_router_destroy(void)
{
	struct gtp_router *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->gtp_router_ctx, next) {
		list_head_del(&c->next);
		FREE(c);
	}

	return 0;
}
