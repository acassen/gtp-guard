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

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "gtp_data.h"
#include "pfcp_router.h"
#include "pfcp_teid.h"
#include "pfcp_server.h"
#include "pfcp_proto_hdl.h"
#include "utils.h"
#include "memory.h"
#include "bitops.h"


/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	PFCP Peer list utilities
 */
struct pfcp_peer_list *
pfcp_peer_list_get(const char *name)
{
	struct pfcp_peer_list *p;
	size_t len = strlen(name);

	list_for_each_entry(p, &daemon_data->pfcp_peers, next) {
		if (!strncmp(p->name, name, len))
			return p;
	}

	return NULL;
}

struct pfcp_peer_list *
pfcp_peer_list_alloc(const char *name)
{
	struct pfcp_peer_list *new;

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&new->next);
	bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);

	list_add_tail(&new->next, &daemon_data->pfcp_peers);

	return new;
}

void
pfcp_peer_list_ctx_destroy(struct pfcp_peer_list *p)
{
	list_del(&p->next);
	FREE(p);
}

void
pfcp_peer_list_destroy(void)
{
	struct pfcp_peer_list *p, *_p;

	list_for_each_entry_safe(p, _p, &daemon_data->pfcp_peers, next)
		pfcp_peer_list_ctx_destroy(p);
}


/*
 *	Helpers
 */
int
pfcp_gtpu_ingress_init(struct inet_server *srv)
{
	return 0;
}

int
pfcp_gtpu_ingress_process(struct inet_server *srv, struct sockaddr_storage *addr_from)
{
	struct gtp_server *s = srv->ctx;
	int ret;

	ret = pfcp_gtpu_hdl(s, addr_from);
	if (ret < 0)
		return -1;

	inet_server_snd(srv, srv->fd, srv->pbuff, (struct sockaddr_in *) addr_from);
	return 0;
}

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

	ret = pfcp_proto_hdl(s, addr_from);
	if (ret < 0)
		return -1;

	if (ret != PFCP_ROUTER_DELAYED)
		inet_server_snd(srv, srv->fd, srv->pbuff, (struct sockaddr_in *) addr_from);

	return 0;
}


/*
 *	PFCP Router utilities
 */
size_t
pfcp_router_dump(struct pfcp_router *ctx, char *buffer, size_t bsize)
{
	int k = 0;

	k += scnprintf(buffer + k, bsize - k, "pfcp-router(%s): '%s'\n",
		       ctx->name, ctx->description);

	return k;
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

static void
pfcp_router_set_up_features(struct pfcp_router *ctx)
{
	/* Header Enrichement */
	ctx->supported_features[0] |= HEEU;

	/* F-TEID Allocation / Release */
	ctx->supported_features[0] |= FTUP;

	/* Framed Routing */
	ctx->supported_features[1] |= FRRT;

	/* Quota Action */
	ctx->supported_features[1] |= QUOAC;

	/* PDI optimised signalling */
	ctx->supported_features[1] |= PDIU;

	/* Sending End Marker packet */
	ctx->supported_features[1] |= EMPU;

	/* Measurement of number of packets */
	ctx->supported_features[2] |= MNOP;

	/* UE IP Address or prefixes allocation */
	ctx->supported_features[2] |= UEIP;

	/* Activation or Deactivation of Pre-Defined PDRs */
	ctx->supported_features[2] |= ADPDP;

	/* Deferred PDR Activation or Deactivation */
	ctx->supported_features[2] |= DPDRA;
}

struct pfcp_router *
pfcp_router_alloc(const char *name)
{
	struct pfcp_router *new;
	time_t now = time(NULL);

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&new->next);
	INIT_LIST_HEAD(&new->bpf_list);
	INIT_LIST_HEAD(&new->static_fwd_rules);
	bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);
	new->seed = poor_prng((unsigned int *) &now);
	new->teid = pfcp_teid_init();
	pfcp_router_set_up_features(new);

	/* by default same as instance name */
	new->recovery_ts = time_now_to_ntp();

	list_add_tail(&new->next, &daemon_data->pfcp_router_ctx);

	return new;
}

void
pfcp_router_ctx_destroy(struct pfcp_router *c)
{
	list_del(&c->bpf_list);
	list_del(&c->next);
	pfcp_server_destroy(&c->s);
	if (__test_bit(PFCP_ROUTER_FL_ALL, &c->flags))
		gtp_server_destroy(&c->gtpu);
	if (__test_bit(PFCP_ROUTER_FL_S1U, &c->flags))
		gtp_server_destroy(&c->gtpu_s1);
	if (__test_bit(PFCP_ROUTER_FL_S5U, &c->flags))
		gtp_server_destroy(&c->gtpu_s5);
	if (__test_bit(PFCP_ROUTER_FL_S8U, &c->flags))
		gtp_server_destroy(&c->gtpu_s8);
	if (__test_bit(PFCP_ROUTER_FL_N9U, &c->flags))
		gtp_server_destroy(&c->gtpu_n9);
	pfcp_teid_destroy(c->teid);
	FREE(c);
}

void
pfcp_router_destroy(void)
{
	struct pfcp_router *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->pfcp_router_ctx, next)
		pfcp_router_ctx_destroy(c);
}
