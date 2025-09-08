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

#include <linux/types.h>
#include "vty.h"
#include "gtp_teid.h"
#include "gtp_bpf_prog.h"
#include "gtp_iptnl.h"

enum {
	XDP_FWD_MAP_TEID = 0,
	XDP_FWD_MAP_IPFRAG,
	XDP_FWD_MAP_IPTNL,
	XDP_FWD_MAP_IF_LLATTR,
	XDP_FWD_MAP_CNT
};

#define GTP_FWD_FL_INGRESS	(1 << 0)
#define GTP_FWD_FL_EGRESS	(1 << 1)
#define GTP_FWD_FL_DIRECT_TX	(1 << 2)

struct gtp_teid_rule {
	__be32	vteid;
	__be32	teid;
	__be32	dst_addr;

	/* Some stats */
	__u64	packets;
	__u64	bytes;
	__u8	flags;
} __attribute__ ((__aligned__(8)));

/* Prototypes */
int gtp_bpf_fwd_teid_action(int, struct gtp_teid *);
int gtp_bpf_fwd_teid_vty(struct vty *, struct gtp_teid *);
int gtp_bpf_fwd_vty(struct gtp_bpf_prog *, void *);
int gtp_bpf_fwd_teid_bytes(struct gtp_teid *, uint64_t *);
int gtp_bpf_fwd_iptnl_action(int, struct gtp_iptnl *, struct gtp_bpf_prog *);
int gtp_bpf_fwd_iptnl_vty(struct gtp_bpf_prog *, void *);
