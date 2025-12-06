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

#include <stdint.h>
#include <linux/netlink.h>
#include "thread.h"

/* types definitions */
struct nl_handle {
	int			fd;
	uint32_t		nl_pid;
	__u32			seq;
	struct thread		*thread;
};


/* Defines */
#define NL_DEFAULT_BUFSIZE	(64*1024)

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) ((void *)(((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

#ifndef NDA_RTA
#define NDA_RTA(r) ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#define RTA_TAIL(rta)	(struct rtattr *) (char *)(rta) + RTA_ALIGN((rta)->rta_len)

/* Prototypes */
int gtp_netlink_link_create_veth(const char *name, const char *peer_name);
int gtp_netlink_link_delete(int ifindex);
int gtp_netlink_if_lookup(int ifindex);
int gtp_netlink_init(void);
void gtp_netlink_destroy(void);
