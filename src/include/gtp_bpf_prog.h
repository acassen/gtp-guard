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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

typedef struct _gtp_bpf_prog gtp_bpf_prog_t;

/* BPF prog template */
typedef struct _gtp_bpf_prog_tpl {
	char			name[GTP_STR_MAX_LEN];
	char			def_path[GTP_PATH_MAX_LEN];
	char			def_progname[GTP_STR_MAX_LEN];

	int (*opened)(gtp_bpf_prog_t *, struct bpf_object *);
	int (*loaded)(gtp_bpf_prog_t *, struct bpf_object *);

	list_head_t		next;
} gtp_bpf_prog_tpl_t;


/* Flags */
enum gtp_bpf_prog_flags {
	GTP_BPF_PROG_FL_SHUTDOWN_BIT,
};

/* BPF prog structure */
typedef struct _gtp_bpf_prog {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	char			path[GTP_PATH_MAX_LEN];
	char			progname[GTP_STR_MAX_LEN];
	struct bpf_object	*bpf_obj;
	struct bpf_program	*bpf_prog;
	gtp_bpf_maps_t		*bpf_maps;
	const gtp_bpf_prog_tpl_t *tpl;

	list_head_t		next;

	int			refcnt;
	unsigned long		flags;
} gtp_bpf_prog_t;


/* Prototypes */
extern struct bpf_link *gtp_bpf_prog_attach(gtp_bpf_prog_t *, int);
extern int gtp_bpf_prog_deattach(struct bpf_link *);
extern int gtp_bpf_prog_load(gtp_bpf_prog_t *);
extern void gtp_bpf_prog_unload(gtp_bpf_prog_t *);
extern int gtp_bpf_prog_destroy(gtp_bpf_prog_t *p);
extern void gtp_bpf_prog_foreach_prog(int (*hdl) (gtp_bpf_prog_t *, void *), void *);
extern gtp_bpf_prog_t *gtp_bpf_prog_get(const char *);
extern int gtp_bpf_prog_put(gtp_bpf_prog_t *);
extern gtp_bpf_prog_t *gtp_bpf_prog_alloc(const char *);
extern int gtp_bpf_progs_destroy(void);
void gtp_bpf_prog_tpl_register(gtp_bpf_prog_tpl_t *tpl);
const gtp_bpf_prog_tpl_t *gtp_bpf_prog_tpl_get(const char *name);
