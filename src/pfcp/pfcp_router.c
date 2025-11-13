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
#include "gtp_interface_rule.h"
#include "pfcp_router.h"
#include "pfcp_teid.h"
#include "pfcp_server.h"
#include "pfcp_proto_hdl.h"
#include "utils.h"
#include "memory.h"
#include "bpf/lib/if_rule-def.h"


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
_rule_set(void *ud, struct gtp_interface *from, bool from_ingress,
	  struct gtp_interface *to, bool add)
{
	struct if_rule_key_base k = {};
	struct gtp_if_rule ifr = {
		.from = from,
		.to = to,
		.key = &k,
		.key_size = sizeof (k),
		.action = from_ingress ? 10 : 11,
		.prio = from_ingress ? 100 : 500,
	};
	gtp_interface_rule_set(&ifr, add);
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
	bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);
	new->seed = poor_prng((unsigned int *) &now);
	new->teid = pfcp_teid_init();
	pfcp_router_set_up_features(new);

	/* by default same as instance name */
	new->recovery_ts = time_now_to_ntp();

	struct gtp_interface_rules_ops irules_ops = {
		.rule_set = _rule_set,
		.ud = new,
	};
	new->irules = gtp_interface_rules_ctx_new(&irules_ops);

	list_add_tail(&new->next, &daemon_data->pfcp_router_ctx);

	return new;
}

int
pfcp_router_ctx_destroy(struct pfcp_router *ctx)
{
	gtp_interface_rules_ctx_release(ctx->irules);
	list_del(&ctx->bpf_list);
	list_head_del(&ctx->next);
	pfcp_server_destroy(&ctx->s);
	pfcp_teid_destroy(ctx->teid);
	return 0;
}

int
pfcp_router_destroy(void)
{
	struct pfcp_router *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->pfcp_router_ctx, next) {
		pfcp_router_ctx_destroy(c);
		FREE(c);
	}

	return 0;
}
