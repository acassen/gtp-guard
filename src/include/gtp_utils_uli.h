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

#ifndef _GTP_UTILS_ULI_H
#define _GTP_UTILS_ULI_H

/* GTPv1 */
extern int gtp1_ie_uli_update(pkt_buffer_t *, gtp_plmn_t *, struct sockaddr_in *);

/* GTPv2 */
extern gtp_id_ecgi_t *gtp_ie_uli_extract_ecgi(gtp_ie_uli_t *);
extern int gtp_id_ecgi_str(gtp_id_ecgi_t *, char *, size_t);
extern int gtp_ie_uli_update(pkt_buffer_t *, gtp_plmn_t *, struct sockaddr_in *);

#endif
