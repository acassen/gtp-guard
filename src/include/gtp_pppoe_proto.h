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
extern pkt_t *pppoe_eth_pkt_get(spppoe_t *, const struct ether_addr *, const uint16_t);
extern void pppoe_dispatch_disc_pkt(gtp_pppoe_t *, pkt_t *);
extern void pppoe_dispatch_session_pkt(gtp_pppoe_t *, pkt_t *);
extern int pppoe_timeout(void *);
extern int pppoe_connect(spppoe_t *);
extern int pppoe_abort_connect(spppoe_t *);
extern int pppoe_disconnect(spppoe_t *);
extern int pppoe_send_padi(spppoe_t *);

#endif
