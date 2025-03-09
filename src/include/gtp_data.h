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

#ifndef _GTP_DATA_H
#define _GTP_DATA_H

/* Default values */
#define GTP_STR_MAX_LEN		128
#define GTP_NAME_MAX_LEN	64
#define GTP_NAMESERVER_PORT	53
#define GTP_DEFAULT_THREAD_CNT	10
#define GTP_BUFFER_SIZE		4096
#define GTP_PNAME		128


/* Flags */
enum daemon_flags {
	GTP_FL_STOP_BIT,
	GTP_FL_GTP_ROUTE_LOADED_BIT,
	GTP_FL_GTP_FORWARD_LOADED_BIT,
	GTP_FL_MIRROR_LOADED_BIT,
	GTP_FL_PPP_RPS_LOADED_BIT,
	GTP_FL_RESTART_COUNTER_LOADED_BIT,
};

/* Main control block */
typedef struct _gtp_bpf_maps {
	struct bpf_map		*map;
} gtp_bpf_maps_t;

typedef struct _gtp_bpf_opts {
	char			filename[GTP_STR_MAX_LEN];
	char			progname[GTP_STR_MAX_LEN];
	int			ifindex;
	char			pin_root_path[GTP_STR_MAX_LEN];
	struct bpf_object	*bpf_obj;
	struct bpf_link		*bpf_lnk;
	gtp_bpf_maps_t		*bpf_maps;
	vty_t			*vty;

	list_head_t		next;
} gtp_bpf_opts_t;

typedef struct _gtp_mirror_rule {
	struct sockaddr_storage	addr;
	uint8_t			protocol;
	int			ifindex;
	bool			active;

	list_head_t		next;
} gtp_mirror_rule_t;

typedef struct _data {
	char			realm[GTP_STR_MAX_LEN];
	struct sockaddr_storage	nameserver;
	gtp_req_channel_t	request_channel;
	list_head_t		xdp_gtp_route;
	gtp_bpf_opts_t		xdp_gtp_forward;
	gtp_bpf_opts_t		xdp_mirror;
	gtp_bpf_opts_t		bpf_ppp_rps;
	char			restart_counter_filename[GTP_STR_MAX_LEN];
	uint8_t			restart_counter;

	list_head_t		mirror_rules;
	list_head_t		pppoe;
	list_head_t		pppoe_bundle;
	list_head_t		ip_vrf;
	list_head_t		gtp_apn;
	list_head_t		gtp_switch_ctx;
	list_head_t		gtp_router_ctx;

	unsigned long		flags;
} data_t;


/* Prototypes */
extern gtp_mirror_rule_t *gtp_mirror_rule_get(const struct sockaddr_storage *, uint8_t, int);
extern gtp_mirror_rule_t *gtp_mirror_rule_add(const struct sockaddr_storage *, uint8_t, int);
extern void gtp_mirror_rule_del(gtp_mirror_rule_t *);
extern void gtp_mirror_action(int, int);
extern int gtp_mirror_vty(vty_t *);
extern gtp_bpf_opts_t *gtp_bpf_opts_alloc(void);
extern int gtp_bpf_opts_add(gtp_bpf_opts_t *, list_head_t *);
extern int gtp_bpf_opts_exist(list_head_t *, int, const char **);
extern void gtp_bpf_opts_destroy(list_head_t *, void (*bpf_unload) (gtp_bpf_opts_t *));
extern int gtp_bpf_opts_load(gtp_bpf_opts_t *, vty_t *, int, const char **,
			     int (*bpf_load) (gtp_bpf_opts_t *));
extern int gtp_bpf_opts_config_write(vty_t *, const char *, gtp_bpf_opts_t *);
extern int gtp_bpf_opts_list_config_write(vty_t *, const char *, list_head_t *);
extern data_t *alloc_daemon_data(void);
extern void free_daemon_data(void);

#endif
