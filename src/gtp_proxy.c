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

#include <arpa/inet.h>
#include <sys/prctl.h>

#include "gtp_data.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_server.h"
#include "gtp_proxy.h"
#include "gtp_dpd.h"
#include "gtp_sqn.h"
#include "gtp_bpf_utils.h"
#include "gtp_proxy_hdl.h"
#include "gtp_bpf_ifrules.h"
#include "bitops.h"
#include "memory.h"
#include "inet_utils.h"
#include "utils.h"
#include "logger.h"
#include "jhash.h"
#include "bpf/lib/gtp_fwd-def.h"

/* Extern data */
extern struct data *daemon_data;


/*
 *	Helpers
 */
int
gtp_proxy_gtpc_teid_destroy(struct gtp_teid *teid)
{
	struct gtp_session *s = teid->session;
	struct gtp_server *srv = s->srv;
	struct gtp_proxy *ctx = srv->ctx;

	gtp_vteid_unhash(ctx->vteid_tab, teid);
	gtp_teid_unhash(ctx->gtpc_teid_tab, teid);
	gtp_vsqn_unhash(ctx->vsqn_tab, teid);
	return 0;
}

int
gtp_proxy_gtpu_teid_destroy(struct gtp_teid *teid)
{
	struct gtp_session *s = teid->session;
	struct gtp_server *srv = s->srv;
	struct gtp_proxy *ctx = srv->ctx;

	gtp_vteid_unhash(ctx->vteid_tab, teid);
	gtp_teid_unhash(ctx->gtpu_teid_tab, teid);
	return 0;
}

static void
gtp_proxy_fwd_addr_get(struct gtp_teid *teid, struct sockaddr_storage *from, struct sockaddr_in *to)
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
gtp_proxy_ingress_init(struct inet_server *srv)
{
	return 0;
}

int
gtp_proxy_ingress_process(struct inet_server *srv, struct sockaddr_storage *addr_from)
{
	struct gtp_server *s = srv->ctx;
	struct gtp_proxy *ctx = s->ctx;
	struct gtp_server *s_egress = &ctx->gtpc_egress;
	struct sockaddr_in addr_to;
	struct gtp_teid *teid;
	int fd = srv->fd;

	/* GTP-U handling */
	if (__test_bit(GTP_FL_UPF_BIT, &s->flags)) {
		teid = gtpu_proxy_handle(s, addr_from);
		if (!teid)
			return -1;

		inet_server_snd(srv, srv->fd, srv->pbuff, (struct sockaddr_in *) addr_from);
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
			fd = ctx->gtpc_egress.s.fd;
		else if (__test_bit(GTP_FL_GTPC_EGRESS_BIT, &s->flags))
			fd = ctx->gtpc.s.fd;
	}

	/* Set destination address */
	gtp_proxy_fwd_addr_get(teid, addr_from, &addr_to);
	inet_server_snd(srv, TEID_IS_DUMMY(teid) ? srv->fd : fd, srv->pbuff,
			TEID_IS_DUMMY(teid) ? (struct sockaddr_in *) addr_from : &addr_to);
	gtpc_proxy_handle_post(s, teid);

	return 0;
}


/*
 *	Interface rules
 */

static int
_show_key(const struct gtp_if_rule *r, char *buf, int size, bool short_out)
{
	const struct if_rule_key *k = r->key;
	char sb[128], db[128];

	if (!k->saddr && !k->daddr) {
		*buf = 0;
		return 0;
	}
	if (short_out)
		return scnprintf(buf, size, "daddr:%s",
				 inet_ntop(AF_INET, &k->daddr, db, sizeof (db)));
	return scnprintf(buf, size, "src_addr:%s dst_addr:%s",
			 inet_ntop(AF_INET, &k->saddr, sb, sizeof (sb)),
			 inet_ntop(AF_INET, &k->daddr, db, sizeof (db)));
}

static void
_set_tun_rules(struct gtp_proxy *ctx, bool add, bool ingress, uint32_t addr)
{
	struct gtp_interface *tun = ctx->ipip_iface;
	bool xlat_before = false, xlat_after = false;
	uint32_t local;

	if (ctx->bpf_ifrules == NULL)
		return;

	if ((ctx->ipip_xlat == 2 && ingress) ||
	    (ctx->ipip_xlat == 1 && !ingress) ||
	    ctx->ipip_xlat == 3)
		xlat_before = true;
	if ((ctx->ipip_xlat == 1 && ingress) ||
	    (ctx->ipip_xlat == 2 && !ingress) ||
	    ctx->ipip_xlat == 3)
		xlat_after = true;

	if (ingress || (local = inet_sockaddrip4(&ctx->gtpu_egress.s.addr)) == (uint32_t)-1)
		local = inet_sockaddrip4(&ctx->gtpu.s.addr);

	/* rule to put into tunnel */
	struct if_rule_key k = {
		.saddr = addr,
		.daddr = local,
	};
	struct gtp_if_rule ifr = {
		.bir = ctx->bpf_ifrules,
		.prio = 100,
		.key_stringify = _show_key,
		.key = &k,
		.key_size = sizeof (k),
		.action = xlat_before ? XDP_GTPFWD_GTPU_XLAT : XDP_GTPFWD_GTPU_NOXLAT,
		.force_ifindex = tun->ifindex,
	};
	gtp_bpf_ifrules_set(&ifr, add);

	/* rules from tunnel */
	k.b.tun_local = addr_toip4(&tun->tunnel_local);
	k.b.tun_remote = addr_toip4(&tun->tunnel_remote);
	k.b.flags = IF_RULE_FL_TUNNEL_IPIP;

	if (!xlat_before) {
		/* same packet, will xlat */
		struct gtp_if_rule ifr = {
			.bir = ctx->bpf_ifrules,
			.from = tun,
			.prio = 100,
			.key_stringify = _show_key,
			.key = &k,
			.key_size = sizeof (k),
			.action = XDP_GTPFWD_TUN_XLAT,
		};
		gtp_bpf_ifrules_set(&ifr, add);
	}

	if (xlat_after) {
		/* xlat'ed on other side  */
		k.saddr = local;
		k.daddr = addr;
		struct gtp_if_rule ifr = {
			.bir = ctx->bpf_ifrules,
			.from = tun,
			.prio = 100,
			.key_stringify = _show_key,
			.key = &k,
			.key_size = sizeof (k),
			.action = XDP_GTPFWD_TUN_NOXLAT,
		};
		gtp_bpf_ifrules_set(&ifr, add);
	}
}


int
gtp_proxy_rules_remote_exists(struct gtp_proxy *ctx, __be32 addr, bool *egress)
{
	struct gtp_proxy_remote_addr *a;
	uint32_t h;

	h = jhash_1word(addr, 0) % GTP_PROXY_REMOTE_ADDR_HSIZE;
	hlist_for_each_entry(a, &ctx->ipip_ingress_tab[h], hlist) {
		if (a->addr == addr) {
			*egress = false;
			return 0;
		}
	}
	hlist_for_each_entry(a, &ctx->ipip_egress_tab[h], hlist) {
		if (a->addr == addr) {
			*egress = true;
			return 0;
		}
	}

	return -1;
}

void
gtp_proxy_rules_remote_set(struct gtp_proxy *ctx, __be32 addr,
			   int action, bool egress)
{
	struct gtp_proxy_remote_addr *a;
	struct hlist_head *head;
	uint32_t h;

	log_message(LOG_DEBUG, "gtp_proxy'%s': %s %s addr: 0x%x\n",
		    ctx->name, action == RULE_ADD ? "add" : "del",
		    egress ? "egress" : "ingress", addr);

	h = jhash_1word(addr, 0) % GTP_PROXY_REMOTE_ADDR_HSIZE;
	head = egress ? &ctx->ipip_egress_tab[h] : &ctx->ipip_ingress_tab[h];
	hlist_for_each_entry(a, head, hlist) {
		if (a->addr == addr) {
			if (action == RULE_DEL) {
				hlist_del(&a->hlist);
				free(a);
				goto apply;
			}
			return;
		}
	}
	if (action == RULE_DEL)
		return;

	a = malloc(sizeof (*a));
	if (a == NULL)
		return;
	a->addr = addr;
	hlist_add_head(&a->hlist, head);

 apply:
	/* apply on already bound rules */
	if (ctx->ipip_iface != NULL && ctx->ipip_rules_set) {
		printf("new teid remote add:%d ingress:%d addr:%x\n",
		       action == RULE_ADD, !egress, addr);
		_set_tun_rules(ctx, action == RULE_ADD, !egress, addr);
	}
}

void
gtp_proxy_rules_tun_set(struct gtp_proxy *ctx)
{
	struct gtp_proxy_remote_addr *a;
	bool set = ctx->ipip_bind && !ctx->ipip_dead;
	int i;

	if (ctx->ipip_iface == NULL || set == ctx->ipip_rules_set)
		return;

	for (i = 0; i < GTP_PROXY_REMOTE_ADDR_HSIZE; i++) {
		hlist_for_each_entry(a, &ctx->ipip_ingress_tab[i], hlist) {
			printf(" consider ingress addr %x\n", a->addr);
			_set_tun_rules(ctx, set, true, a->addr);
		}
	}

	for (i = 0; i < GTP_PROXY_REMOTE_ADDR_HSIZE; i++) {
		hlist_for_each_entry(a, &ctx->ipip_egress_tab[i], hlist) {
			printf(" consider egress addr %x\n", a->addr);
			_set_tun_rules(ctx, set, false, a->addr);
		}
	}

	printf("%s: done\n", __func__);

	ctx->ipip_rules_set = set;
}

void
gtp_proxy_iface_tun_event_cb(struct gtp_interface *iface,
			     enum gtp_interface_event type,
			     void *ud, void *arg)
{
	struct gtp_proxy *ctx = ud;

	log_message(LOG_DEBUG, "iface:%s ipip event %d\n", iface->ifname, type);

	switch (type) {
	case GTP_INTERFACE_EV_PRG_START:
		ctx->ipip_bind = true;
		break;
	case GTP_INTERFACE_EV_PRG_STOP:
	case GTP_INTERFACE_EV_DESTROYING:
		ctx->ipip_bind = false;
		break;
	default:
		return;
	}

	gtp_proxy_rules_tun_set(ctx);

	if (type == GTP_INTERFACE_EV_DESTROYING)
		ctx->ipip_iface = NULL;
}

struct gtp_proxy *
gtp_proxy_get(const char *name)
{
	struct gtp_proxy *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->gtp_proxy_ctx, next) {
		if (!memcmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

struct gtp_proxy *
gtp_proxy_alloc(const char *name)
{
	struct gtp_proxy *ctx;

	PMALLOC(ctx);
	if (!ctx) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&ctx->next);
	INIT_LIST_HEAD(&ctx->iptnl.decap_pfx_vlan);
	strncpy(ctx->name, name, GTP_NAME_MAX_LEN - 1);
	list_add_tail(&ctx->next, &daemon_data->gtp_proxy_ctx);

	/* Init hashtab */
	ctx->gtpc_teid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	ctx->gtpu_teid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	ctx->vteid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	ctx->vsqn_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));

	ctx->ipip_ingress_tab = calloc(GTP_PROXY_REMOTE_ADDR_HSIZE,
				       sizeof (struct hlist_head));
	ctx->ipip_egress_tab = calloc(GTP_PROXY_REMOTE_ADDR_HSIZE,
				      sizeof (struct hlist_head));

	return ctx;
}

static void
gtp_proxy_ctx_server_stop(struct gtp_proxy *ctx)
{
	struct gtp_proxy_remote_addr *a;
	struct hlist_node *tmp;
	int i;

	if (ctx->ipip_iface) {
		gtp_interface_unregister_event(ctx->ipip_iface,
					       gtp_proxy_iface_tun_event_cb,
					       ctx);
		gtp_proxy_iface_tun_event_cb(ctx->ipip_iface,
					     GTP_INTERFACE_EV_DESTROYING,
					     ctx, NULL);
	}
	if (ctx->bpf_prog != NULL) {
		ctx->bpf_prog = NULL;
		ctx->bpf_data = NULL;
		ctx->bpf_ifrules = NULL;
		list_del(&ctx->bpf_list);
	}

	for (i = 0; i < GTP_PROXY_REMOTE_ADDR_HSIZE; i++) {
		hlist_for_each_entry_safe(a, tmp, &ctx->ipip_ingress_tab[i], hlist) {
			hlist_del(&a->hlist);
			free(a);
		}
		hlist_for_each_entry_safe(a, tmp, &ctx->ipip_egress_tab[i], hlist) {
			hlist_del(&a->hlist);
			free(a);
		}
	}

	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpc_egress);
	gtp_server_destroy(&ctx->gtpu);
	gtp_server_destroy(&ctx->gtpu_egress);
	gtp_dpd_destroy(ctx);
}

void
gtp_proxy_ctx_destroy(struct gtp_proxy *ctx)
{
	gtp_proxy_ctx_server_stop(ctx);
	free(ctx->ipip_ingress_tab);
	free(ctx->ipip_egress_tab);
	free(ctx->gtpc_teid_tab);
	free(ctx->gtpu_teid_tab);
	free(ctx->vteid_tab);
	free(ctx->vsqn_tab);
	list_del(&ctx->next);
	FREE(ctx);
}

void
gtp_proxy_server_stop(void)
{
	struct gtp_proxy *c;

	list_for_each_entry(c, &daemon_data->gtp_proxy_ctx, next)
		gtp_proxy_ctx_server_stop(c);
}

void
gtp_proxy_destroy(void)
{
	struct gtp_proxy *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->gtp_proxy_ctx, next)
		gtp_proxy_ctx_destroy(c);
}
