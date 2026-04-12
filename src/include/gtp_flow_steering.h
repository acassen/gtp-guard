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
#pragma once

#include <stdint.h>
#include "gtp_stddef.h"
#include "gtp_range_partition.h"
#include "list_head.h"

/* Binds one range-partition to this policy */
struct gtp_flow_steering_map {
	struct gtp_range_partition	*rp;
};

struct gtp_flow_steering_policy {
	char				name[GTP_NAME_MAX_LEN];
	uint32_t			*queue_ids;
	int				nr_queue_ids;
	struct gtp_flow_steering_map	*maps;
	int				nr_maps;
	int				refcnt;
	struct list_head		next;
};

/* Prototypes */
struct gtp_flow_steering_policy *gtp_flow_steering_get(const char *name);
struct gtp_flow_steering_policy *gtp_flow_steering_alloc(const char *name);
int gtp_flow_steering_free(struct gtp_flow_steering_policy *fsp);
int gtp_flow_steering_destroy(void);
int gtp_flow_steering_bind_rp(struct gtp_flow_steering_policy *fsp,
			      struct gtp_range_partition *rp);
int gtp_flow_steering_unbind_rp(struct gtp_flow_steering_policy *fsp,
				const char *rp_name);
