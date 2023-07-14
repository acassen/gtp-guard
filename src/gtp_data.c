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
#include <pthread.h>
#include <sys/stat.h>

/* local includes */
#include "memory.h"
#include "utils.h"
#include "timer.h"
#include "mpool.h"
#include "vector.h"
#include "list_head.h"
#include "json_writer.h"
#include "vty.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_session.h"
#include "gtp_xdp.h"

/* Extern data */
extern data_t *daemon_data;

/*
 *	Daemon Control Block helpers
 */
data_t *
alloc_daemon_data(void)
{
        data_t *new = (data_t *) MALLOC(sizeof(data_t));
        INIT_LIST_HEAD(&new->gtp_apn);
        INIT_LIST_HEAD(&new->gtp_ctx);

        return new;
}

void
free_daemon_data(void)
{
	if (strlen(daemon_data->xdp_filename))
		gtp_xdp_unload_fwd(daemon_data->xdp_ifindex);
	FREE(daemon_data);
}

