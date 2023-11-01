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

#ifndef _GTP_XDP_H
#define _GTP_XDP_H

#include <stddef.h>

enum {
	XDPFWD_RULE_ADD = 0,
	XDPFWD_RULE_UPDATE,
	XDPFWD_RULE_DEL,
	XDPFWD_RULE_LIST
};

enum {
	XDPFWD_MAP_TEID = 0,
	XDPFWD_MAP_IPFRAG,
	XDPFWD_MAP_IPTNL,
	XDPFWD_MAP_CNT
};

#define XDP_PATH_MAX 128

typedef struct _xdp_exported_maps {
	struct bpf_map	*map;
} xdp_exported_maps_t;

struct gtp_teid_rule {
	__be32	vteid;
	__be32	teid;
	__be32	dst_addr;

	/* Some stats */
	__u64	packets;
	__u64	bytes;
	__u8	direction;
} __attribute__ ((__aligned__(8)));
#define GTP_INGRESS	0
#define GTP_EGRESS	1

struct gtp_iptnl_rule {
	__be32	selector_addr;
	__be32	local_addr;
	__be32	remote_addr;
	__be16	encap_vlan_id;
	__be16	decap_vlan_id;
	__u8	flags;
} __attribute__ ((__aligned__(8)));


/* Prototypes */
extern int gtp_xdp_fwd_load(gtp_bpf_opts_t *);
extern void gtp_xdp_fwd_unload(gtp_bpf_opts_t *);
extern int gtp_xdp_fwd_teid_action(int, gtp_teid_t *, int);
extern int gtp_xdp_fwd_teid_vty(vty_t *, __be32);
extern int gtp_xdp_fwd_vty(vty_t *);
extern int gtp_xdp_iptnl_action(int, gtp_iptnl_t *);
extern int gtp_xdp_iptnl_vty(vty_t *);
extern int gtp_xdp_iptnl_teid_vty(vty_t *);
extern int gtp_xdp_mirror_load(gtp_bpf_opts_t *);
extern void gtp_xdp_mirror_unload(gtp_bpf_opts_t *);
extern int gtp_xdp_init(void);
extern int gtp_xdp_destroy(void);

#endif
