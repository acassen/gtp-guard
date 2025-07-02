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
#pragma once

enum cgn_flags {
	CGN_FL_SHUTDOWN_BIT,
};

typedef struct _cgn {
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];

	/* metrics */

	list_head_t		next;

	unsigned long		flags;
} cgn_t;

/* Prototypes */
extern void cgn_foreach(int (*hdl) (cgn_t *, void *), void *);
extern cgn_t *cgn_get_by_name(const char *);
extern int cgn_release(cgn_t *);
extern cgn_t *cgn_alloc(const char *);
extern int cgn_init(void);
extern int cgn_destroy(void);

