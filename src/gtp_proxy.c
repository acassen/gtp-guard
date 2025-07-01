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
#include <sys/prctl.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Helpers
 */
int
gtp_proxy_gtpc_teid_destroy(gtp_teid_t *teid)
{
	gtp_session_t *s = teid->session;
	gtp_server_t *srv = s->srv;
	gtp_proxy_t *ctx = srv->ctx;

	gtp_vteid_unhash(&ctx->vteid_tab, teid);
	gtp_teid_unhash(&ctx->gtpc_teid_tab, teid);
	gtp_vsqn_unhash(&ctx->vsqn_tab, teid);
	return 0;
}

int
gtp_proxy_gtpu_teid_destroy(gtp_teid_t *teid)
{
	gtp_session_t *s = teid->session;
	gtp_server_t *srv = s->srv;
	gtp_proxy_t *ctx = srv->ctx;

	gtp_vteid_unhash(&ctx->vteid_tab, teid);
	gtp_teid_unhash(&ctx->gtpu_teid_tab, teid);
	return 0;
}

static void
gtp_proxy_fwd_addr_get(gtp_teid_t *teid, struct sockaddr_storage *from, struct sockaddr_in *to)
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
gtp_proxy_ingress_init(gtp_server_t *s)
{
	return 0;
}

int
gtp_proxy_ingress_process(gtp_server_t *s, struct sockaddr_storage *addr_from)
{
	gtp_proxy_t *ctx = s->ctx;
	gtp_server_t *s_egress = &ctx->gtpc_egress;
	struct sockaddr_in addr_to;
	gtp_teid_t *teid;
	int fd = s->fd;

	/* GTP-U handling */
	if (__test_bit(GTP_FL_UPF_BIT, &s->flags)) {
		teid = gtpu_proxy_handle(s, addr_from);
		if (!teid)
			return -1;

		gtp_server_send(s, s->fd, (struct sockaddr_in *) addr_from);
		return 0;
	}

	/* GTP-C handling */
	teid = gtpc_proxy_handle(s, addr_from);
	if (!teid)
		return -1;

	/* Select appropriate socket. If egress channel is configured
	 * then split socket */
	if (__test_bit(GTP_FL_CTL_BIT, &s_egress->flags)) {
		if (__test_bit(GTP_FL_GTPC_INGRESS_BIT, &s->flags))
			fd = ctx->gtpc_egress.fd;
		else if (__test_bit(GTP_FL_GTPC_EGRESS_BIT, &s->flags))
			fd = ctx->gtpc.fd;
		fd = (fd) ? : s->fd;
	}

	/* Set destination address */
	gtp_proxy_fwd_addr_get(teid, addr_from, &addr_to);
	gtp_server_send(s, TEID_IS_DUMMY(teid) ? s->fd : fd
			 , TEID_IS_DUMMY(teid) ? (struct sockaddr_in *) addr_from : &addr_to);
	gtpc_proxy_handle_post(s, teid);

	return 0;
}


/*
 *	GTP Proxy init
 */
gtp_proxy_t *
gtp_proxy_get(const char *name)
{
	gtp_proxy_t *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->gtp_proxy_ctx, next) {
		if (!memcmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

gtp_proxy_t *
gtp_proxy_init(const char *name)
{
	gtp_proxy_t *new;

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
        INIT_LIST_HEAD(&new->next);
        strncpy(new->name, name, GTP_NAME_MAX_LEN - 1);
        list_add_tail(&new->next, &daemon_data->gtp_proxy_ctx);

	/* Init hashtab */
	gtp_htab_init(&new->gtpc_teid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->gtpu_teid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->vteid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->vsqn_tab, CONN_HASHTAB_SIZE);

	return new;
}

int
gtp_proxy_ctx_server_destroy(gtp_proxy_t *ctx)
{
	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpc_egress);
	gtp_server_destroy(&ctx->gtpu);
	gtp_dpd_destroy(&ctx->iptnl);
	return 0;
}

int
gtp_proxy_ctx_destroy(gtp_proxy_t *ctx)
{
	gtp_htab_destroy(&ctx->gtpc_teid_tab);
	gtp_htab_destroy(&ctx->gtpu_teid_tab);
	gtp_htab_destroy(&ctx->vteid_tab);
	gtp_htab_destroy(&ctx->vsqn_tab);
	list_head_del(&ctx->next);
	return 0;
}

int
gtp_proxy_server_destroy(void)
{
	gtp_proxy_t *c;

	list_for_each_entry(c, &daemon_data->gtp_proxy_ctx, next)
		gtp_proxy_ctx_server_destroy(c);

	return 0;
}

int
gtp_proxy_destroy(void)
{
	gtp_proxy_t *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->gtp_proxy_ctx, next) {
		gtp_proxy_ctx_destroy(c);
		FREE(c);
	}

	return 0;
}
