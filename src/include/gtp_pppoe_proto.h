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

#ifndef _GTP_PPPOE_PROTO_H
#define _GTP_PPPOE_PROTO_H

#define PPPOEDEBUG(a)	do {				\
	if (__test_bit(GTP_CONN_F_DEBUG, &c->flags))	\
		log_message a;				\
} while(0)

/* Prototypes */
extern void pppoe_dispatch_disc_pkt(gtp_pppoe_t *, gtp_pkt_t *);
extern int pppoe_timeout(gtp_pppoe_session_t *);
extern int pppoe_connect(gtp_pppoe_session_t *);
extern int pppoe_abort_connect(gtp_pppoe_session_t *);
extern int pppoe_disconnect(gtp_pppoe_session_t *);
extern int pppoe_send_padi(gtp_pppoe_session_t *);

#endif