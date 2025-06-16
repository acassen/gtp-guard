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

#ifndef _GTP_BPF_H
#define _GTP_BPF_H

enum {
	RULE_ADD = 0,
	RULE_UPDATE,
	RULE_DEL,
	RULE_LIST
};

#define GTP_XDP_STRERR_BUFSIZE	128
#define XDP_PATH_MAX	128
#define GTP_INGRESS	0
#define GTP_EGRESS	1

typedef struct _gtp_bpf_prog {
	char			name[GTP_STR_MAX_LEN];
	char			path[GTP_PATH_MAX_LEN];
	char			progname[GTP_STR_MAX_LEN];
	struct bpf_object	*bpf_obj;
	struct bpf_program	*bpf_prog;
	gtp_bpf_maps_t		*bpf_maps;

	list_head_t		next;
} gtp_bpf_prog_t;

/* Prototypes */
extern int gtp_bpf_mac_learning_vty(vty_t *, struct bpf_map *);
extern struct bpf_map *gtp_bpf_load_map(struct bpf_object *, const char *);
extern struct bpf_program *gtp_bpf_load_prog(gtp_bpf_opts_t *);
extern int gtp_bpf_load(gtp_bpf_opts_t *);
extern void gtp_bpf_unload(gtp_bpf_opts_t *);
extern int gtp_bpf_prog_deattach(struct bpf_link *);
extern struct bpf_link *gtp_bpf_prog_attach(gtp_bpf_prog_t *, int);
extern int gtp_bpf_prog_load(gtp_bpf_prog_t *);
extern void gtp_bpf_prog_unload(gtp_bpf_prog_t *p);
extern int gtp_bpf_init(void);
extern int gtp_bpf_destroy(void);

#endif
