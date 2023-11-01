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

#ifndef _GTP_DATA_H
#define _GTP_DATA_H

/* Default values */
#define GTP_STR_MAX_LEN		128
#define GTP_NAMESERVER_PORT	53

/* Flags */
enum daemon_flags {
	GTP_FL_STOP_BIT,
	GTP_FL_GTPU_LOADED_BIT,
	GTP_FL_MIRROR_LOADED_BIT,
};

/* Main control block */
typedef struct _gtp_bpf_opts {
	char			filename[GTP_STR_MAX_LEN];
	char			progname[GTP_STR_MAX_LEN];
	int			ifindex;
	char			pin_root_path[GTP_STR_MAX_LEN];
	struct bpf_object	*bpf_obj;
	struct bpf_link		*bpf_lnk;
	vty_t			*vty;
} gtp_bpf_opts_t;

typedef struct _data {
	char			realm[GTP_STR_MAX_LEN];
	struct sockaddr_storage	nameserver;
	gtp_req_channel_t	request_channel;
	gtp_bpf_opts_t		xdp_gtpu;
	gtp_bpf_opts_t		xdp_mirror;
	char			restart_counter_filename[GTP_STR_MAX_LEN];
	uint8_t			restart_counter;

	/* APN resolver */
	list_head_t		gtp_apn;

	/* GTP switching context */
	list_head_t		gtp_ctx;

	unsigned long		flags;
} data_t;

/* Prototypes */
extern data_t *alloc_daemon_data(void);
extern void free_daemon_data(void);

#endif
