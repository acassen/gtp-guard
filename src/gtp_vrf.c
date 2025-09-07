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

#include <string.h>

#include "gtp_data.h"
#include "gtp_vrf.h"
#include "memory.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	IP VRF init
 */
struct ip_vrf *
gtp_ip_vrf_get(const char *name)
{
	struct ip_vrf *vrf;
	size_t len = strlen(name);

	list_for_each_entry(vrf, &daemon_data->ip_vrf, next) {
		if (!memcmp(vrf->name, name, len))
			return vrf;
	}

	return NULL;
}

struct ip_vrf *
gtp_ip_vrf_alloc(const char *name)
{
	struct ip_vrf *new;

	PMALLOC(new);
        INIT_LIST_HEAD(&new->next);
        strncpy(new->name, name, GTP_NAME_MAX_LEN - 1);
        list_add_tail(&new->next, &daemon_data->ip_vrf);

	return new;
}


int
gtp_ip_vrf_destroy(struct ip_vrf *vrf)
{
	list_head_del(&vrf->next);
	return 0;
}

int
gtp_vrf_destroy(void)
{
	struct ip_vrf *vrf, *_vrf;

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
