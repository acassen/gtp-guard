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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#pragma once

#include <linux/pkt_cls.h>

struct gtp_mirror_rule {
	__be32		addr;
	__be16		port;
	__u8		protocol;
	int		ifindex;
} __attribute__ ((__aligned__(8)));

#define MAX_MIRROR_ENTRIES 100U


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MIRROR_ENTRIES);
	__type(key, __be32);
	__type(value, struct gtp_mirror_rule);
} mirror_rules SEC(".maps");
