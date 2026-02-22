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

#include "gtp_stddef.h"
#include "ip_pool.h"
#include "list_head.h"

/* flags */
enum gtp_ip_pool_flags {
	GTP_IP_POOL_FL_SHUTDOWN,
};

struct gtp_ip_pool {
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	struct ip_pool		*pool;
	int			refcnt;

	struct list_head	next;
	unsigned long		flags;
};

/* Prototypes */
struct gtp_ip_pool *gtp_ip_pool_get(const char *name);
int gtp_ip_pool_put(struct gtp_ip_pool *p);
struct gtp_ip_pool *gtp_ip_pool_alloc(const char *name);
int gtp_ip_pool_free(struct gtp_ip_pool *p);
int gtp_ip_pool_destroy(void);
int gtp_ip_pool_init(void);
