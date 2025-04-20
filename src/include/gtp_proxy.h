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

#ifndef _GTP_PROXY_H
#define _GTP_PROXY_H

/* GTP Switching context */
typedef struct _socket_pair {
	int	*fd_ingress;
	int	*fd_egress;
} socket_pair_t;

typedef struct _gtp_proxy {
	char			name[GTP_NAME_MAX_LEN];
	gtp_server_t		gtpc;
	gtp_server_t		gtpc_egress;
	socket_pair_t		*gtpc_socket_pair;
	gtp_server_t		gtpu;
	gtp_server_t		gtpu_egress;
	int			session_delete_to;

	gtp_htab_t		gtpc_teid_tab;	/* GTP-C teid hashtab */
	gtp_htab_t		gtpu_teid_tab;	/* GTP-U teid hashtab */
	gtp_htab_t		vteid_tab;	/* virtual teid hashtab */
	gtp_htab_t		vsqn_tab;	/* virtual Seqnum hashtab */
	uint32_t		seqnum;		/* Global context Seqnum */

	gtp_naptr_t		*pgw;
	struct sockaddr_storage	pgw_addr;

	gtp_iptnl_t		iptnl;

	unsigned long		flags;
	uint32_t		refcnt;

	list_head_t		next;
} gtp_proxy_t;


/* Prototypes */
extern int gtp_proxy_gtpc_teid_destroy(gtp_teid_t *);
extern int gtp_proxy_gtpu_teid_destroy(gtp_teid_t *);
extern int gtp_proxy_ingress_init(gtp_server_worker_t *);
extern int gtp_proxy_ingress_process(gtp_server_worker_t *, struct sockaddr_storage *);
extern gtp_proxy_t *gtp_proxy_get(const char *);
extern gtp_proxy_t *gtp_proxy_init(const char *);
extern int gtp_proxy_gtpc_socketpair_init(gtp_server_t *);
extern int gtp_proxy_ctx_server_destroy(gtp_proxy_t *);
extern int gtp_proxy_ctx_destroy(gtp_proxy_t *);
extern int gtp_proxy_server_destroy(void);
extern int gtp_proxy_destroy(void);
extern int gtp_proxy_vty_init(void);

#endif
