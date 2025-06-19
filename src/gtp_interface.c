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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libbpf.h>
#include <btf.h>

/* local includes */
#include "gtp_guard.h"

/* Local data */
pthread_mutex_t gtp_interfaces_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Extern data */
extern data_t *daemon_data;

/*
 *	Interface metrics
 *
 * We are supporting Prometheus text-based-format:
 * https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
 */
static void
gtp_interface_metrics_foreach_interface(int (*hdl) (gtp_interface_t *, void *,
						    const char *, int, __u8, __u8),
					void *arg, const char *var, int var_type,
					__u8 type, __u8 direction)
{
	list_head_t *l = &daemon_data->interfaces;
	gtp_interface_t *iface;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry(iface, l, next) {
		__sync_add_and_fetch(&iface->refcnt, 1);
		(*(hdl)) (iface, arg, var, var_type, type, direction);
		__sync_sub_and_fetch(&iface->refcnt, 1);
	}
	pthread_mutex_unlock(&gtp_interfaces_mutex);
}

static int
gtp_pkt_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->packets);
}
static int
gtp_pkt_dropped_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->dropped_packets);
}
static int
gtp_bytes_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->bytes);
}
static int
gtp_bytes_dropped_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->dropped_bytes);
}

static int
gtp_interface_metrics_var_dump(gtp_interface_t *iface, void *arg,
			       const char *var, int var_type,
			       __u8 type, __u8 direction)
{
	gtp_bpf_prog_t *p = daemon_data->xdp_gtp_route;
	FILE *fp = arg;

	fprintf(fp, "%s{interface=\"%s\"} "
		  , var, iface->description);
	gtp_bpf_rt_metrics_dump(p, (var_type == METRIC_PACKET) ? gtp_pkt_dump :
								 gtp_bytes_dump
				 , fp, iface->ifindex, type, direction);
	fprintf(fp, "%s{interface=\"%s\",type=\"dropped\"} "
		  , var, iface->description);
	gtp_bpf_rt_metrics_dump(p, (var_type == METRIC_PACKET) ? gtp_pkt_dropped_dump :
								 gtp_bytes_dropped_dump
				 , fp, iface->ifindex, type, direction);
	return 0;
}

static int
gtp_interface_metrics_tmpl_dump(FILE *fp, const char *var, int var_type,
				const char *desc, const char *type,
				__u8 metric_type, __u8 direction)
{
	fprintf(fp, "#HELP %s %s\n#TYPE %s %s\n", var, desc, var, type);
	gtp_interface_metrics_foreach_interface(gtp_interface_metrics_var_dump,
						fp, var, var_type, metric_type, direction);
	fprintf(fp, "\n");
	return 0;
}

static const struct {
	const char	*var;
	int		var_type;
	const char	*description;
	const char	*type;
	__u8		metric_type;
	__u8		direction;
} gtp_interface_metrics_set[] = {
	{ "gtpguard_gtp_in_packet_total", METRIC_PACKET,
	  "Count of received GTP packets", "counter", IF_METRICS_GTP, IF_DIRECTION_RX },

	{ "gtpguard_gtp_in_byte_total",	METRIC_BYTE,
	  "Count of received GTP bytes", "counter", IF_METRICS_GTP, IF_DIRECTION_RX},

	{ "gtpguard_gtp_out_packet_total", METRIC_PACKET,
	  "Count of transmitted GTP packets", "counter", IF_METRICS_GTP, IF_DIRECTION_TX },

	{ "gtpguard_gtp_out_byte_total", METRIC_BYTE,
	  "Count of transmitted GTP bytes", "counter", IF_METRICS_GTP, IF_DIRECTION_TX},

	{ "gtpguard_pppoe_in_packet_total", METRIC_PACKET,
	  "Count of received PPPoE packets", "counter", IF_METRICS_PPPOE, IF_DIRECTION_RX},

	{ "gtpguard_pppoe_in_byte_total", METRIC_BYTE,
	  "Count of received PPPoE bytes", "counter", IF_METRICS_PPPOE, IF_DIRECTION_RX},

	{ "gtpguard_pppoe_out_packet_total", METRIC_PACKET,
	  "Count of transmitted PPPoE packets", "counter", IF_METRICS_PPPOE, IF_DIRECTION_TX},

	{ "gtpguard_pppoe_out_byte_total", METRIC_BYTE,
	  "Count of transmitted PPPoE bytes", "counter", IF_METRICS_PPPOE, IF_DIRECTION_TX},

	{ NULL, 0, NULL, NULL, 0, 0}
};

int
gtp_interface_metrics_dump(FILE *fp)
{
	int i;

	for (i = 0; gtp_interface_metrics_set[i].var; i++) {
		gtp_interface_metrics_tmpl_dump(fp,
						gtp_interface_metrics_set[i].var,
						gtp_interface_metrics_set[i].var_type,
						gtp_interface_metrics_set[i].description,
						gtp_interface_metrics_set[i].type,
						gtp_interface_metrics_set[i].metric_type,
						gtp_interface_metrics_set[i].direction);
	}

	return 0;
}


/*
 *	Interface helpers
 */
void
gtp_interface_foreach_interface(int (*hdl) (gtp_interface_t *, void *),
				void *arg)
{
	list_head_t *l = &daemon_data->interfaces;
	gtp_interface_t *iface;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry(iface, l, next) {
		__sync_add_and_fetch(&iface->refcnt, 1);
		(*(hdl)) (iface, arg);
		__sync_sub_and_fetch(&iface->refcnt, 1);
	}
	pthread_mutex_unlock(&gtp_interfaces_mutex);
}

gtp_interface_t *
gtp_interface_get(const char *name)
{
	list_head_t *l = &daemon_data->interfaces;
	gtp_interface_t *iface;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry(iface, l, next) {
		if (!strncmp(iface->ifname, name, strlen(name))) {
			pthread_mutex_unlock(&gtp_interfaces_mutex);
			__sync_add_and_fetch(&iface->refcnt, 1);
			return iface;
		}
	}
	pthread_mutex_unlock(&gtp_interfaces_mutex);

	return NULL;
}

gtp_interface_t *
gtp_interface_get_by_ifindex(int ifindex)
{
	list_head_t *l = &daemon_data->interfaces;
	gtp_interface_t *iface;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry(iface, l, next) {
		if (iface->ifindex == ifindex) {
			pthread_mutex_unlock(&gtp_interfaces_mutex);
			__sync_add_and_fetch(&iface->refcnt, 1);
			return iface;
		}
	}
	pthread_mutex_unlock(&gtp_interfaces_mutex);

	return NULL;
}

gtp_interface_t *
gtp_interface_get_by_direct_tx(ip_address_t *addr)
{
	list_head_t *l = &daemon_data->interfaces;
	gtp_interface_t *iface;
	ip_address_t *addr_iface;
	bool addr_equal = false;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry(iface, l, next) {
		addr_iface = &iface->direct_tx_gw;
		if (!addr_iface->family)
			continue;

		if (addr_iface->family != addr->family)
			continue;

		switch (addr->family) {
		case AF_INET:
			addr_equal = __ip4_addr_equal(&addr_iface->u.sin_addr,
						      &addr->u.sin_addr);
			break;
		case AF_INET6:
			addr_equal = __ip6_addr_equal(&addr_iface->u.sin6_addr,
						      &addr->u.sin6_addr);
			break;
		}

		if (addr_equal) {
			pthread_mutex_unlock(&gtp_interfaces_mutex);
			__sync_add_and_fetch(&iface->refcnt, 1);
			return iface;
		}
	}
	pthread_mutex_unlock(&gtp_interfaces_mutex);

	return NULL;
}


int
gtp_interface_put(gtp_interface_t *iface)
{
	__sync_sub_and_fetch(&iface->refcnt, 1);
	return 0;
}

gtp_interface_t *
gtp_interface_alloc(const char *name, int ifindex)
{
	gtp_interface_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	bsd_strlcpy(new->ifname, name, GTP_STR_MAX_LEN - 1);
	new->ifindex = ifindex;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_add_tail(&new->next, &daemon_data->interfaces);
	pthread_mutex_unlock(&gtp_interfaces_mutex);

	return new;
}

int
gtp_interface_unload_bpf(gtp_interface_t *iface)
{
	if (iface->bpf_prog)
		gtp_bpf_prog_unload(iface->bpf_prog);
	if (iface->bpf_lnk)
		bpf_link__destroy(iface->bpf_lnk);
	iface->bpf_prog = NULL;
	iface->bpf_lnk = NULL;
	return 0;
}

int
gtp_interface_destroy(gtp_interface_t *iface)
{
	pthread_mutex_lock(&gtp_interfaces_mutex);
	gtp_interface_unload_bpf(iface);
	list_head_del(&iface->next);
	FREE(iface);
	pthread_mutex_unlock(&gtp_interfaces_mutex);
	return 0;
}

int
gtp_interfaces_destroy(void)
{
	list_head_t *l = &daemon_data->interfaces;
	gtp_interface_t *iface, *_iface;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry_safe(iface, _iface, l, next) {
		gtp_interface_unload_bpf(iface);
		list_head_del(&iface->next);
		FREE(iface);
	}
	pthread_mutex_unlock(&gtp_interfaces_mutex);
	return 0;
}
