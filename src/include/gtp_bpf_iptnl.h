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

struct gtp_iptnl_rule {
	__be32	selector_addr;
	__be32	local_addr;
	__be32	remote_addr;
	__be16	encap_vlan_id;
	__be16	decap_vlan_id;
	__u8	flags;
} __attribute__ ((__aligned__(8)));

/* Prototypes */
extern int gtp_bpf_iptnl_action(int, gtp_iptnl_t *, struct bpf_map *);
extern int gtp_bpf_iptnl_vty(vty_t *, struct bpf_map *);
