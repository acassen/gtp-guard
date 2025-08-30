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

#include "gtp_data.h"
#include "gtp_proxy.h"
#include "gtp_router.h"
#include "gtp_request.h"
#include "gtp_conn.h"
#include "gtp_session.h"
#include "gtp_bpf.h"
#include "gtp_mirror.h"
#include "gtp_interface.h"
#include "memory.h"


/* Extern data */
extern data_t *daemon_data;


/*
 *	Daemon Control Block helpers
 */
data_t *
alloc_daemon_data(void)
{
	data_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->mirror);
	INIT_LIST_HEAD(&new->ip_vrf);
	INIT_LIST_HEAD(&new->bpf_progs);
	INIT_LIST_HEAD(&new->interfaces);
	INIT_LIST_HEAD(&new->pppoe);
	INIT_LIST_HEAD(&new->pppoe_bundle);
	INIT_LIST_HEAD(&new->cgn);
	INIT_LIST_HEAD(&new->gtp_apn);
	INIT_LIST_HEAD(&new->gtp_cdr);
	INIT_LIST_HEAD(&new->gtp_proxy_ctx);
	INIT_LIST_HEAD(&new->gtp_router_ctx);
	pppoe_init();

	return new;
}

void
free_daemon_data(void)
{
	gtp_proxy_server_destroy();
	gtp_router_server_destroy();
	gtp_request_destroy();
	gtp_metrics_destroy();
	pppoe_bundle_destroy();
	pppoe_destroy();
	gtp_conn_destroy();
	gtp_sessions_destroy();
	gtp_proxy_destroy();
	gtp_router_destroy();
	gtp_bpf_destroy();
	gtp_teid_destroy();
	gtp_vrf_destroy();
	gtp_mirrors_destroy();
	gtp_interfaces_destroy();
	gtp_bpf_progs_destroy();
	gtp_cdr_spool_destroy(NULL);
	gtp_apn_destroy();
	FREE(daemon_data);
}
