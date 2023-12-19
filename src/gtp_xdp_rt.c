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

/* system includes */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libbpf.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;

/* Local data */
static xdp_exported_maps_t xdp_rt_maps[XDP_RT_MAP_CNT];


/*
 *	XDP RT BPF related
 */
int
gtp_xdp_rt_load(gtp_bpf_opts_t *opts)
{
	struct bpf_map *map;
	int err;

	err = gtp_xdp_load(opts);
	if (err < 0)
		return -1;

	/* MAP ref for faster access */
	map = gtp_bpf_load_map(opts->bpf_obj, "teid_egress");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_TEID_EGRESS].map = map;

	map = gtp_bpf_load_map(opts->bpf_obj, "teid_ingress");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_TEID_INGRESS].map = map;

	map = gtp_bpf_load_map(opts->bpf_obj, "iptnl_info");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_IPTNL].map = map;

	return 0;
}

void
gtp_xdp_rt_unload(gtp_bpf_opts_t *opts)
{
	gtp_xdp_unload(opts);
}


/*
 *	TEID Routing handling
 */
int
gtp_xdp_rt_teid_action(int action, gtp_teid_t *t, int direction)
{
	return 0;
}

int
gtp_xdp_rt_teid_vty(vty_t *vty, __be32 id)
{
	return 0;
}