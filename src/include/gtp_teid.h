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

#ifndef _GTP_TEID_H
#define _GTP_TEID_H

/* Prototypes */
extern int gtp_teid_put(gtp_teid_t *);
extern gtp_teid_t *gtp_teid_get(gtp_htab_t *, gtp_ie_f_teid_t *);
extern gtp_teid_t *gtp_teid_alloc(gtp_htab_t *, gtp_ie_f_teid_t *, gtp_ie_eps_bearer_id_t *);
extern int gtp_teid_unhash(gtp_htab_t *, gtp_teid_t *);
extern void gtp_teid_bind(gtp_teid_t *, gtp_teid_t *);
extern int gtp_teid_masq(gtp_ie_f_teid_t *, struct sockaddr_storage *, uint32_t);
extern int gtp_teid_restore(gtp_teid_t *, gtp_ie_f_teid_t *);
extern void gtp_teid_dump(gtp_teid_t *);
extern int gtp_vteid_alloc(gtp_htab_t *, gtp_teid_t *, unsigned int *);
extern int gtp_vteid_unhash(gtp_htab_t *, gtp_teid_t *);
extern gtp_teid_t *gtp_vteid_get(gtp_htab_t *, uint32_t);
extern gtp_teid_t *gtp_vsqn_get(gtp_htab_t *, uint32_t);
extern int gtp_vsqn_unhash(gtp_htab_t *, gtp_teid_t *);
extern int gtp_vsqn_alloc(gtp_srv_worker_t *, gtp_teid_t *);
extern int gtp_vsqn_update(gtp_srv_worker_t *, gtp_teid_t *);
extern int gtp_sqn_update(gtp_srv_worker_t *, gtp_teid_t *);
extern int gtp_sqn_masq(gtp_srv_worker_t *, gtp_teid_t *);
extern int gtp_sqn_restore(gtp_srv_worker_t *, gtp_teid_t *);

#endif
