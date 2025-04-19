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
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"





gtp_cdr_spool_t *
gtp_cdr_spool_alloc(void)
{
	gtp_cdr_spool_t *n;
	gtp_cdr_file_t *f;

	PMALLOC(n);
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	f = gtp_cdr_file_alloc();
	n->cdr_file = f;
	f->spool = n;
	return n;
}

int
gtp_cdr_spool_destroy(gtp_cdr_spool_t *s)
{
	gtp_cdr_file_destroy(s->cdr_file);
	FREE(s);
	return 0;
}
