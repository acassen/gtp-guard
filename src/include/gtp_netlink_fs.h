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
#include <linux/tc_act/tc_skbedit.h>

#include "gtp_interface.h"
#include "gtp_flow_steering.h"
#include "vty.h"


/* Compat: older kernels may lack these */
#ifndef TCA_FLOWER_KEY_ENC_KEY_ID_MASK
#define TCA_FLOWER_KEY_ENC_KEY_ID_MASK	107
#endif

#ifndef TCA_CLS_FLAGS_SKIP_SW
#define TCA_CLS_FLAGS_SKIP_SW		(1 << 1)
#endif

#ifndef TCA_ACT_FLAGS
#define TCA_ACT_FLAGS			7
#endif

#ifndef TCA_ACT_FLAGS_SKIP_SW
#define TCA_ACT_FLAGS_SKIP_SW		(1 << 2)
#endif

/* Flower priority base, reserves 1-99 for other uses */
#define FS_FLOWER_PRIO_BASE		100


/* Prototypes */
int gtp_netlink_fs_install(struct gtp_interface *iface,
			   struct gtp_flow_steering_policy *fsp);
int gtp_netlink_fs_uninstall(struct gtp_interface *iface,
			     struct gtp_flow_steering_policy *fsp);
void gtp_netlink_fs_show(struct vty *vty, struct gtp_interface *iface,
			 struct gtp_interface_flow_steering *ifs);
