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


/*
 *	Interface helpers
 */
void
gtp_interface_foreach_interface(int (*hdl) (gtp_interface_t *, void *), void *arg)
{
	gtp_interface_t *iface;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		__sync_add_and_fetch(&iface->refcnt, 1);
		(*(hdl)) (iface, arg);
		__sync_sub_and_fetch(&iface->refcnt, 1);
	}
	pthread_mutex_unlock(&gtp_interfaces_mutex);
}

gtp_interface_t *
gtp_interface_get(const char *name)
{
	gtp_interface_t *iface;

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (!strncmp(iface->ifname, name, strlen(name))) {
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
gtp_interface_alloc(const char *name)
{
	gtp_interface_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	bsd_strlcpy(new->ifname, name, GTP_STR_MAX_LEN - 1);

	pthread_mutex_lock(&gtp_interfaces_mutex);
	list_add_tail(&new->next, &daemon_data->interfaces);
	pthread_mutex_unlock(&gtp_interfaces_mutex);

	return new;
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
