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
#include <linux/if_packet.h>
#include <sys/prctl.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	CGN utilities
 */
void
cgn_foreach(int (*hdl) (cgn_t *, void *), void *arg)
{
	list_head_t *l = &daemon_data->cgn;
	cgn_t *cgn;

	list_for_each_entry(cgn, l, next)
		(*(hdl)) (cgn, arg);
}

cgn_t *
cgn_get_by_name(const char *name)
{
	list_head_t *l = &daemon_data->cgn;
	cgn_t *cgn;

	list_for_each_entry(cgn, l, next) {
		if (!strncmp(cgn->name, name, GTP_NAME_MAX_LEN)) {
			return cgn;
		}
	}

	return NULL;
}

static int
cgn_add(cgn_t *cgn)
{
	list_add_tail(&cgn->next, &daemon_data->cgn);
	return 0;
}



cgn_t *
cgn_alloc(const char *name)
{
	cgn_t *new = NULL;

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
	bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN);
	INIT_LIST_HEAD(&new->next);
	cgn_add(new);

	return new;
}

int
cgn_release(cgn_t *cgn)
{
	/*... all destroy stuffs ...*/
	list_head_del(&cgn->next);
	FREE(cgn);
	return 0;
}

int
cgn_init(void)
{
	return 0;
}

int
cgn_destroy(void)
{
	list_head_t *l = &daemon_data->cgn;
	cgn_t *cgn, *_cgn;

	list_for_each_entry_safe(cgn, _cgn, l, next)
		cgn_release(cgn);
	return 0;
}
