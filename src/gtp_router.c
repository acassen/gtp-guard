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
#include "bitops.h"
#include "utils.h"
#include "timer.h"
#include "mpool.h"
#include "vector.h"
#include "command.h"
#include "list_head.h"
#include "json_writer.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_htab.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_server.h"
#include "gtp_switch.h"
#include "gtp_router.h"
#include "gtp_conn.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Worker
 */
int
gtp_router_ingress_init(gtp_server_worker_t *w)
{
	gtp_server_t *srv = w->srv;
	gtp_router_t *ctx = srv->ctx;
	const char *ptype = "gtpc";

	/* Create Process Name */
	if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
		ptype = "upf";
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
		if (!memcmp(ctx->name, name, len))
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
        strncpy(new->name, name, GTP_NAME_MAX_LEN - 1);
        list_add_tail(&new->next, &daemon_data->gtp_router_ctx);

	/* Init hashtab */
	gtp_htab_init(&new->gtpc_teid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->gtpu_teid_tab, CONN_HASHTAB_SIZE);

	return new;
}


int
gtp_router_ctx_destroy(gtp_router_t *ctx)
{
	gtp_htab_destroy(&ctx->gtpc_teid_tab);
	gtp_htab_destroy(&ctx->gtpu_teid_tab);
	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpu);
	list_head_del(&ctx->next);
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
