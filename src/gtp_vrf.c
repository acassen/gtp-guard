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
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	IP VRF init
 */
ip_vrf_t *
gtp_ip_vrf_get(const char *name)
{
	ip_vrf_t *vrf;
	size_t len = strlen(name);

	list_for_each_entry(vrf, &daemon_data->ip_vrf, next) {
		if (!memcmp(vrf->name, name, len))
			return vrf;
	}

	return NULL;
}

ip_vrf_t *
gtp_ip_vrf_alloc(const char *name)
{
	ip_vrf_t *new;

	PMALLOC(new);
        INIT_LIST_HEAD(&new->next);
        strncpy(new->name, name, GTP_NAME_MAX_LEN - 1);
        list_add_tail(&new->next, &daemon_data->ip_vrf);

	return new;
}


int
gtp_ip_vrf_destroy(ip_vrf_t *vrf)
{
	list_head_del(&vrf->next);
	return 0;
}

int
gtp_vrf_destroy(void)
{
	ip_vrf_t *vrf, *_vrf;

	list_for_each_entry_safe(vrf, _vrf, &daemon_data->ip_vrf, next) {
		gtp_ip_vrf_destroy(vrf);
		FREE(vrf);
	}

	return 0;
}

int
gtp_vrf_init(void)
{
	return 0;
}