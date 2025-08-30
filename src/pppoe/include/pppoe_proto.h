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

#include <net/ethernet.h>
#include "pkt_buffer.h"
#include "pppoe_session.h"

/* Prototypes */
extern pkt_t *pppoe_eth_pkt_get(spppoe_t *, const struct ether_addr *, const uint16_t);
extern void pppoe_dispatch_disc_pkt(pppoe_t *, pkt_t *);
extern void pppoe_dispatch_session_pkt(pppoe_t *, pkt_t *);
extern void pppoe_timeout(thread_t *);
extern int pppoe_connect(spppoe_t *);
extern int pppoe_abort_connect(spppoe_t *);
extern int pppoe_disconnect(spppoe_t *);
extern int pppoe_send_padi(spppoe_t *);
extern int pppoe_proto_init(void);
extern int pppoe_proto_destroy(void);
