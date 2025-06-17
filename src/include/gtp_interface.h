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

#ifndef _GTP_INTERFACE_H
#define _GTP_INTERFACE_H

/* Flags */
enum gtp_interface_flags {
	GTP_INTERFACE_FL_METRICS_GTP_BIT,
	GTP_INTERFACE_FL_METRICS_PPPOE_BIT,
	GTP_INTERFACE_FL_METRICS_IPIP_BIT,
	GTP_INTERFACE_FL_DIRECT_TX_GW_BIT,
	GTP_INTERFACE_FL_SHUTDOWN_BIT,
};

/* BPF prog structure */
typedef struct _gtp_interface {
	char			ifname[IF_NAMESIZE];
	uint8_t			hw_addr[ETH_ALEN];
	uint8_t			hw_addr_len;
	ip_address_t		direct_tx_gw;
	uint8_t			direct_tx_hw_addr[ETH_ALEN];
	int			ifindex;
	char			description[GTP_STR_MAX_LEN];
	gtp_bpf_prog_t		*bpf_prog;
	struct bpf_link		*bpf_lnk;

	list_head_t		next;

	int			refcnt;
	unsigned long		flags;
} gtp_interface_t;

/* Prototypes */
extern int gtp_interface_unload_bpf(gtp_interface_t *);
extern int gtp_interface_destroy(gtp_interface_t *);
extern void gtp_interface_foreach_interface(int (*hdl) (gtp_interface_t *, void *), void *);
extern gtp_interface_t *gtp_interface_get(const char *);
extern gtp_interface_t *gtp_interface_get_by_ifindex(int);
extern gtp_interface_t *gtp_interface_get_by_direct_tx(ip_address_t *);
extern int gtp_interface_put(gtp_interface_t *);
extern gtp_interface_t *gtp_interface_alloc(const char *, int);
extern int gtp_interfaces_destroy(void);

#endif
