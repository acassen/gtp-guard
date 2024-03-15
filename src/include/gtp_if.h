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

#ifndef _GTP_IF_H
#define _GTP_IF_H

/* Defines */
#define IF_DEFAULT_CONNECTION_KEEPIDLE		20
#define IF_DEFAULT_CONNECTION_KEEPCNT		2
#define IF_DEFAULT_CONNECTION_KEEPINTVL		10

/* Prototypes */
extern int if_setsockopt_reuseaddr(int, int);
extern int if_setsockopt_nolinger(int, int);
extern int if_setsockopt_tcpcork(int, int);
extern int if_setsockopt_nodelay(int, int);
extern int if_setsockopt_keepalive(int, int);
extern int if_setsockopt_tcp_keepidle(int, int);
extern int if_setsockopt_tcp_keepcnt(int, int);
extern int if_setsockopt_tcp_keepintvl(int, int);
extern int if_setsockopt_rcvtimeo(int, int);
extern int if_setsockopt_sndtimeo(int, int);
extern int if_setsockopt_reuseport(int, int);
extern int if_setsockopt_hdrincl(int);
extern int if_setsockopt_broadcast(int);
extern int if_setsockopt_promisc(int, int, bool);
extern int if_setsockopt_attach_bpf(int, int);
extern int if_setsockopt_no_receive(int *);
extern int if_setsockopt_rcvbuf(int *, int);
extern int if_setsockopt_bindtodevice(int *, const char *);
extern int if_setsockopt_priority(int *, int);

#endif
