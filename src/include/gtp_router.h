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

#ifndef _GTP_ROUTER_H
#define _GTP_ROUTER_H

#define GTP_ROUTER_DELAYED	2

typedef struct _gtp_router {
	char			name[GTP_NAME_MAX_LEN];
	gtp_server_t		gtpc;
	gtp_server_t		gtpu;

	gtp_htab_t		gtpc_teid_tab;	/* GTP-C teid hashtab */
	gtp_htab_t		gtpu_teid_tab;	/* GTP-U teid hashtab */
	uint32_t		seqnum;		/* Global context Seqnum */

	unsigned long		flags;
	uint32_t		refcnt;

	list_head_t		next;
} gtp_router_t;


/* Prototypes */
extern int gtp_router_gtpc_teid_destroy(gtp_teid_t *);
extern int gtp_router_gtpu_teid_destroy(gtp_teid_t *);
extern int gtp_router_ingress_init(gtp_server_worker_t *);
extern int gtp_router_ingress_process(gtp_server_worker_t *, struct sockaddr_storage *);
extern gtp_router_t *gtp_router_get(const char *);
extern gtp_router_t *gtp_router_init(const char *);
extern int gtp_router_ctx_destroy(gtp_router_t *);
extern int gtp_router_server_destroy(void);
extern int gtp_router_destroy(void);
extern int gtp_router_vty_init(void);

#endif
