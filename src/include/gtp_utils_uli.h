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

#include "gtp_apn.h"

/* GTPv1 */
extern int gtp1_ie_uli_update(struct pkt_buffer *, struct gtp_plmn *, struct sockaddr_in *);

/* GTPv2 */
struct gtp_id_ecgi *gtp_ie_uli_extract_ecgi(struct gtp_ie_uli *);
int gtp_id_ecgi_str(struct gtp_id_ecgi *, char *, size_t);
int gtp_ie_uli_update(struct pkt_buffer *, struct gtp_plmn *, struct sockaddr_in *);
