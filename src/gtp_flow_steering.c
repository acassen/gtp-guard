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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "utils.h"
#include "gtp_data.h"
#include "gtp_flow_steering.h"


/* Extern data */
extern struct data *daemon_data;


struct gtp_flow_steering_policy *
gtp_flow_steering_get(const char *name)
{
	struct gtp_flow_steering_policy *fsp;

	list_for_each_entry(fsp, &daemon_data->flow_steering, next) {
		if (!strncmp(fsp->name, name, GTP_NAME_MAX_LEN - 1))
			return fsp;
	}
	return NULL;
}

struct gtp_flow_steering_policy *
gtp_flow_steering_alloc(const char *name)
{
	struct gtp_flow_steering_policy *new;

	new = calloc(1, sizeof(*new));
	if (!new)
		return NULL;

	bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN - 1);
	INIT_LIST_HEAD(&new->next);
	list_add_tail(&new->next, &daemon_data->flow_steering);
	return new;
}

int
gtp_flow_steering_free(struct gtp_flow_steering_policy *fsp)
{
	int i;

	if (!fsp || fsp->refcnt)
		return -1;

	for (i = 0; i < fsp->nr_maps; i++) {
		if (fsp->maps[i].rp)
			fsp->maps[i].rp->refcnt--;
	}

	free(fsp->maps);
	free(fsp->queue_ids);
	list_del(&fsp->next);
	free(fsp);
	return 0;
}

int
gtp_flow_steering_destroy(void)
{
	struct gtp_flow_steering_policy *fsp, *tmp;

	list_for_each_entry_safe(fsp, tmp, &daemon_data->flow_steering, next) {
		fsp->refcnt = 0;
		gtp_flow_steering_free(fsp);
	}
	return 0;
}

int
gtp_flow_steering_bind_rp(struct gtp_flow_steering_policy *fsp,
			  struct gtp_range_partition *rp)
{
	struct gtp_flow_steering_map *new_maps;

	new_maps = realloc(fsp->maps, (fsp->nr_maps + 1) * sizeof(*new_maps));
	if (!new_maps) {
		errno = ENOMEM;
		return -1;
	}

	fsp->maps = new_maps;
	fsp->maps[fsp->nr_maps].rp = rp;
	fsp->nr_maps++;
	rp->refcnt++;
	return 0;
}

int
gtp_flow_steering_unbind_rp(struct gtp_flow_steering_policy *fsp,
			    const char *rp_name)
{
	int i;

	for (i = 0; i < fsp->nr_maps; i++) {
		if (!fsp->maps[i].rp)
			continue;
		if (strncmp(fsp->maps[i].rp->name, rp_name, GTP_NAME_MAX_LEN - 1))
			continue;

		fsp->maps[i].rp->refcnt--;
		/* Compact array */
		memmove(&fsp->maps[i], &fsp->maps[i + 1],
			(fsp->nr_maps - i - 1) * sizeof(*fsp->maps));
		fsp->nr_maps--;
		return 0;
	}
	return -1;
}
