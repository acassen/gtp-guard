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

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Helpers
 */
int
gtp_router_ingress_init(gtp_server_worker_t *w)
{
	gtp_server_t *srv = w->srv;
	gtp_router_t *ctx = srv->ctx;
	const char *ptype = "rt-gtpc";

	/* Create Process Name */
	if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
		ptype = "rt-upf";
	snprintf(w->pname, 127, "%s-%s-%d"
			 , ctx->name
			 , ptype
			 , w->id);
	prctl(PR_SET_NAME, w->pname, 0, 0, 0, 0);

	return 0;
}

int
gtp_router_ingress_process(gtp_server_worker_t *w, struct sockaddr_storage *addr_from)
{
	gtp_server_t *srv = w->srv;
	int ret;

	ret = __test_bit(GTP_FL_UPF_BIT, &srv->flags) ? gtpu_router_handle(w, addr_from) :
							gtpc_router_handle(w, addr_from);
	if (ret < 0)
		return -1;

	if (ret != GTP_ROUTER_DELAYED)
		gtp_server_send(w, w->fd, (struct sockaddr_in *) addr_from);
	return 0;
}


/*
 *	GTP Router init
 */
gtp_router_t *
gtp_router_get(const char *name)
{
	gtp_router_t *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->gtp_router_ctx, next) {
		if (!strncmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

gtp_router_t *
gtp_router_init(const char *name)
{
	gtp_router_t *new;

	PMALLOC(new);
        INIT_LIST_HEAD(&new->next);
        bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);
        list_add_tail(&new->next, &daemon_data->gtp_router_ctx);

	return new;
}

int
gtp_router_ctx_server_destroy(gtp_router_t *ctx)
{
	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpu);
	return 0;
}

int
gtp_router_ctx_destroy(gtp_router_t *ctx)
{
	list_head_del(&ctx->next);
	return 0;
}

int
gtp_router_server_destroy(void)
{
	gtp_router_t *c;

	list_for_each_entry(c, &daemon_data->gtp_router_ctx, next)
		gtp_router_ctx_server_destroy(c);

	return 0;
}

int
gtp_router_destroy(void)
{
	gtp_router_t *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->gtp_router_ctx, next) {
		gtp_router_ctx_destroy(c);
		FREE(c);
	}

	return 0;
}
