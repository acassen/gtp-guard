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

#ifndef _GTP_XDP_RT_H
#define _GTP_XDP_RT_H

enum {
	XDP_RT_MAP_TEID_INGRESS = 0,
	XDP_RT_MAP_TEID_EGRESS,
	XDP_RT_MAP_IPTNL,
	XDP_RT_MAP_CNT
};

#define GTP_RT_FL_IPIP		(1 << 0)
#define GTP_RT_FL_PPP		(1 << 1)

struct ip_rt_key {
	__u32		id;
	__u32		addr;
};

struct gtp_rt_rule {
	__be32	teid;
	__be32	addr;
	__be32	dst_key;

	/* Some stats */
	__u64	packets;
	__u64	bytes;

	__u8	flags;
} __attribute__ ((__aligned__(8)));

/* Prototypes */
extern int gtp_xdp_rt_load(gtp_bpf_opts_t *);
extern void gtp_xdp_rt_unload(gtp_bpf_opts_t *);
extern int gtp_xdp_rt_teid_action(int, gtp_teid_t *, int);
extern int gtp_xdp_rt_teid_vty(vty_t *, __be32);
extern int gtp_xdp_rt_vty(vty_t *);
extern int gtp_xdp_rt_iptnl_action(int, gtp_iptnl_t *);
extern int gtp_xdp_rt_iptnl_vty(vty_t *);

#endif
