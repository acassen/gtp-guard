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
#include "gtp_if.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_switch_hdl.h"
#include "gtp_dpd.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Worker
 */
static void
gtp_switch_fwd_addr_get(gtp_teid_t *teid, struct sockaddr_storage *from, struct sockaddr_in *to)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *) from;

	if (addr4->sin_addr.s_addr == teid->sgw_addr.sin_addr.s_addr) {
		*to = teid->pgw_addr;
	} else {
		*to = teid->sgw_addr;
	}

	if (teid->family == GTP_INIT)
		to->sin_port = htons(GTP_C_PORT);
}

int
gtp_switch_ingress_init(gtp_server_worker_t *w)
{
	gtp_server_t *srv = w->srv;
	gtp_switch_t *ctx = srv->ctx;
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
gtp_switch_ingress_process(gtp_server_worker_t *w, struct sockaddr_storage *addr_from)
{
	gtp_server_t *srv = w->srv;
	struct sockaddr_in addr_to;
	gtp_teid_t *teid;

	/* GTP-U handling */
	if (__test_bit(GTP_FL_UPF_BIT, &srv->flags)) {
		teid = gtpu_handle(w, addr_from);
		if (!teid)
			return -1;

		gtp_server_send(w, w->fd, (struct sockaddr_in *) addr_from);
		return -1;
	}

	/* GTP-C handling */
	teid = gtpc_handle(w, addr_from);
	if (!teid)
		return -1;

	/* Set destination address */
	gtp_switch_fwd_addr_get(teid, addr_from, &addr_to);
	gtp_server_send(w, w->fd
			 , (teid->type == 0xff) ? (struct sockaddr_in *) addr_from : &addr_to);
	gtpc_handle_post(w, teid);

	return 0;
}


/*
 *	GTP Switch init
 */
gtp_switch_t *
gtp_switch_get(const char *name)
{
	gtp_switch_t *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->gtp_ctx, next) {
		if (!memcmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

gtp_switch_t *
gtp_switch_init(const char *name)
{
	gtp_switch_t *new;

	PMALLOC(new);
        INIT_LIST_HEAD(&new->next);
        strncpy(new->name, name, GTP_STR_MAX - 1);
        list_add_tail(&new->next, &daemon_data->gtp_ctx);

	/* Init hashtab */
	gtp_htab_init(&new->gtpc_teid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->gtpu_teid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->vteid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->vsqn_tab, CONN_HASHTAB_SIZE);

	return new;
}


int
gtp_ctx_destroy(gtp_switch_t *ctx)
{
	gtp_htab_destroy(&ctx->gtpc_teid_tab);
	gtp_htab_destroy(&ctx->gtpu_teid_tab);
	gtp_htab_destroy(&ctx->vteid_tab);
	gtp_htab_destroy(&ctx->vsqn_tab);

	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpu);
	gtp_dpd_destroy(&ctx->iptnl);
	list_head_del(&ctx->next);
	return 0;
}

int
gtp_switch_destroy(void)
{
	gtp_switch_t *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->gtp_ctx, next) {
		gtp_ctx_destroy(c);
		FREE(c);
	}

	return 0;
}
