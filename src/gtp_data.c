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
#include <pthread.h>
#include <sys/stat.h>
#include <net/if.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;


/*
 *	Mirroring rules
 */
gtp_mirror_rule_t *
gtp_mirror_rule_get(const struct sockaddr_storage *addr, uint8_t protocol, int ifindex)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r;

	list_for_each_entry(r, l, next) {
		if (sockstorage_equal(addr, &r->addr) &&
		    r->protocol == protocol &&
		    r->ifindex == ifindex) {
			return r;
		}
	}

	return NULL;
}

gtp_mirror_rule_t *
gtp_mirror_rule_add(const struct sockaddr_storage *addr, uint8_t protocol, int ifindex)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r;

	PMALLOC(r);
	INIT_LIST_HEAD(&r->next);
	r->addr = *addr;
	r->protocol = protocol;
	r->ifindex = ifindex;

	list_add_tail(&r->next, l);

	return r;
}

void
gtp_mirror_rule_del(gtp_mirror_rule_t *r)
{
	list_head_del(&r->next);
}

void
gtp_mirror_action(int action, int ifindex)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r;
	int ret;

	list_for_each_entry(r, l, next) {
		if (r->ifindex == ifindex &&
		    ((action == RULE_ADD && !r->active) ||
		     (action == RULE_DEL && r->active))) {
			ret = gtp_xdp_mirror_action(action, r);
			if (!ret)
				r->active = (action == RULE_ADD);
		}
	}
}

static int
gtp_mirror_destroy(void)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r, *_r;

	list_for_each_entry_safe(r, _r, l, next) {
		list_head_del(&r->next);
		FREE(r);
	}

	return 0;
}

int
gtp_mirror_vty(vty_t *vty)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r;
	char ifname[IF_NAMESIZE];

	list_for_each_entry(r, l, next) {
		vty_out(vty, " mirror %s port %u protocol %s interface %s%s"
			   , inet_sockaddrtos(&r->addr)
			   , ntohs(inet_sockaddrport(&r->addr))
			   , (r->protocol == IPPROTO_UDP) ? "UDP" : "TCP"
			   , if_indextoname(r->ifindex, ifname)
			   , VTY_NEWLINE);
	}

	return 0;
}


/*
 *	BPF opts related
 */
gtp_bpf_opts_t *
gtp_bpf_opts_alloc(void)
{
	gtp_bpf_opts_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);

	return new;
}

int
gtp_bpf_opts_add(gtp_bpf_opts_t *opts, list_head_t *l)
{
	list_add_tail(&opts->next, l);
	return 0;
}

int
gtp_bpf_opts_exist(list_head_t *l, int argc, const char **argv)
{
	gtp_bpf_opts_t *opts;
	int ifindex;

	if (argc < 2)
		return 0;

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex)
		return 0;

	list_for_each_entry(opts, l, next) {
		if (opts->ifindex == ifindex &&
		    !strncmp(opts->filename, argv[0], GTP_STR_MAX_LEN))
			return 1;
	}

	return 0;
}


void
gtp_bpf_opts_destroy(list_head_t *l, void (*bpf_unload) (gtp_bpf_opts_t *))
{
	gtp_bpf_opts_t *opts, *_opts;

	list_for_each_entry_safe(opts, _opts, l, next) {
		(*bpf_unload) (opts);
		list_head_del(&opts->next);
		FREE(opts);
	}

	INIT_LIST_HEAD(l);
}

int
gtp_bpf_opts_load(gtp_bpf_opts_t *opts, vty_t *vty, int argc, const char **argv,
		     int (*bpf_load) (gtp_bpf_opts_t *))
{
	int err, ifindex;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return -1;
	}

	bsd_strlcpy(opts->filename, argv[0], GTP_STR_MAX_LEN-1);
	ifindex = if_nametoindex(argv[1]);
	if (argc == 3)
		bsd_strlcpy(opts->progname, argv[2], GTP_STR_MAX_LEN-1);
	if (!ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[1]
			   , VTY_NEWLINE);
		return -1;
	}
	opts->ifindex = ifindex;
	opts->vty = vty;

	err = (*bpf_load) (opts);
	if (err) {
		vty_out(vty, "%% Error loading eBPF program:%s on ifindex:%d%s"
			   , opts->filename
			   , opts->ifindex
			   , VTY_NEWLINE);
		/* Reset data */
		memset(opts, 0, sizeof(gtp_bpf_opts_t));
		return -1;
	}

	log_message(LOG_INFO, "Success loading eBPF program:%s on ifindex:%d"
			    , opts->filename
			    , opts->ifindex);
	return 0;
}

int
gtp_bpf_opts_config_write(vty_t *vty, const char *cmd, gtp_bpf_opts_t *opts)
{
	char ifname[IF_NAMESIZE];

	if (opts->progname[0]) {
		vty_out(vty, "%s %s interface %s progname %s%s"
			   , cmd
			   , opts->filename
			   , if_indextoname(opts->ifindex, ifname)
			   , opts->progname
			   , VTY_NEWLINE);
		return 0;
	}

	vty_out(vty, "%s %s interface %s%s"
		   , cmd
		   , opts->filename
		   , if_indextoname(opts->ifindex, ifname)
		   , VTY_NEWLINE);
	return 0;
}

int
gtp_bpf_opts_list_config_write(vty_t *vty, const char *cmd, list_head_t *l)
{
	gtp_bpf_opts_t *opts;

	list_for_each_entry(opts, l, next)
		gtp_bpf_opts_config_write(vty, cmd, opts);

	return 0;
}


/*
 *	Daemon Control Block helpers
 */
data_t *
alloc_daemon_data(void)
{
	data_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->xdp_gtp_route);
	INIT_LIST_HEAD(&new->mirror_rules);
	INIT_LIST_HEAD(&new->ip_vrf);
	INIT_LIST_HEAD(&new->pppoe);
	INIT_LIST_HEAD(&new->pppoe_bundle);
	INIT_LIST_HEAD(&new->gtp_apn);
	INIT_LIST_HEAD(&new->gtp_switch_ctx);
	INIT_LIST_HEAD(&new->gtp_router_ctx);

	return new;
}

void
free_daemon_data(void)
{
	if (__test_bit(GTP_FL_GTP_FORWARD_LOADED_BIT, &daemon_data->flags))
		gtp_xdp_fwd_unload(&daemon_data->xdp_gtp_forward);
	if (__test_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags))
		gtp_xdp_mirror_unload(&daemon_data->xdp_mirror);
	if (__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags))
		gtp_bpf_opts_destroy(&daemon_data->xdp_gtp_route, gtp_xdp_rt_unload);
	gtp_switch_server_destroy();
	gtp_router_server_destroy();
	gtp_request_destroy();
	gtp_pppoe_bundle_destroy();
	gtp_pppoe_destroy();
	gtp_sessions_destroy();
	gtp_conn_destroy();
	gtp_switch_destroy();
	gtp_router_destroy();
	gtp_xdp_destroy();
	gtp_teid_destroy();
	gtp_mirror_destroy();
	gtp_vrf_destroy();
	gtp_apn_destroy();
	FREE(daemon_data);
}

