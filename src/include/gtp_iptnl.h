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

/* IP-IP tunneling related */
#define IPTNL_FL_TRANSPARENT_INGRESS_ENCAP	(1 << 0)
#define IPTNL_FL_TRANSPARENT_EGRESS_ENCAP	(1 << 1)
#define IPTNL_FL_TRANSPARENT_EGRESS_BYPASS	(1 << 2)
#define IPTNL_FL_DPD				(1 << 3)
#define IPTNL_FL_DEAD				(1 << 4)
#define IPTNL_FL_UNTAG_VLAN			(1 << 5)
#define IPTNL_FL_TAG_VLAN			(1 << 6)

typedef struct _pfx_vlan {
	prefix_t		pfx;
	uint16_t		vlan_id;

	list_head_t		next;
} pfx_vlan_t;

typedef struct _gtp_iptnl {
	/* Dead-Peer-Detection */
	int			fd_in;
	int			fd_out;
	thread_ref_t		r_thread;
	uint8_t			recv_buffer[GTP_BUFFER_SIZE];
	size_t			recv_buffer_size;
	uint8_t			send_buffer[GTP_BUFFER_SIZE];
	size_t			send_buffer_size;
	unsigned long		credit;
	unsigned long		expire;
	size_t			payload_len;

	/* Tunnel declaration */
	int			ifindex;
	uint32_t		selector_addr;
	uint32_t		dpd_saddr;
	uint32_t		local_addr;
	uint32_t		remote_addr;
	uint16_t		encap_vlan_id;
	uint16_t		decap_vlan_id;
	list_head_t		decap_pfx_vlan;

	uint8_t			flags;
} gtp_iptnl_t;


/* Prototypes */
extern pfx_vlan_t *pfx_vlan_alloc(void);
extern int pfx_vlan_add(gtp_iptnl_t *, pfx_vlan_t *);
extern int pfx_vlan_free(pfx_vlan_t *);
