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

enum {
	RULE_ADD = 0,
	RULE_UPDATE,
	RULE_DEL,
	RULE_LIST
};

#define GTP_XDP_STRERR_BUFSIZE	128
#define GTP_INGRESS	0
#define GTP_EGRESS	1

/* Prototypes */
extern int gtp_bpf_ll_attr_update(struct bpf_map *, uint32_t, uint16_t, uint16_t);
extern struct bpf_map *gtp_bpf_load_map(struct bpf_object *, const char *);
extern int gtp_bpf_init(void);
extern int gtp_bpf_destroy(void);
