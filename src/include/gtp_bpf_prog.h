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

#include <stdint.h>
#include "list_head.h"
#include "libbpf.h"
#include "gtp_stddef.h"

typedef struct gtp_bpf_prog gtp_bpf_prog_t;
typedef struct gtp_interface gtp_interface_t;

typedef struct gtp_bpf_prog_var
{
	const char *name;
	const void *value;
	uint32_t size;
} gtp_bpf_prog_var_t;

/* BPF program mode & type */
typedef enum {
	BPF_PROG_MODE_GTP_FORWARD,
	BPF_PROG_MODE_GTP_ROUTE,
	BPF_PROG_MODE_GTP_MIRROR,
	BPF_PROG_MODE_CGN,
	BPF_PROG_MODE_MAX,
} gtp_bpf_prog_mode_t;

enum {
	GTP_BPF_PROG_TYPE_XDP = 0,
	GTP_BPF_PROG_TYPE_TC,
	GTP_BPF_PROG_TYPE_MAX,
};

/* BPF prog template */
typedef struct gtp_bpf_prog_tpl {
	gtp_bpf_prog_mode_t	mode;
	char			description[GTP_STR_MAX_LEN];
	char			def_progname[GTP_STR_MAX_LEN];

	/* load bpf program on the latest moment: on xdp_attach */
	bool			load_on_attach;

	int (*bind_itf)(gtp_bpf_prog_t *, gtp_interface_t *);
	int (*opened)(gtp_bpf_prog_t *, struct bpf_object *);
	int (*loaded)(gtp_bpf_prog_t *, struct bpf_object *);

	void (*direct_tx_lladdr_updated)(gtp_bpf_prog_t *, gtp_interface_t *);

	list_head_t		next;
} gtp_bpf_prog_tpl_t;


/* Flags */
enum gtp_bpf_prog_flags {
	GTP_BPF_PROG_FL_SHUTDOWN_BIT,
};

/* BPF prog structure */
typedef struct gtp_bpf_maps {
	struct bpf_map		*map;
} gtp_bpf_maps_t;

typedef struct gtp_bpf_prog {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	char			path[GTP_PATH_MAX_LEN];
	char			progname[GTP_STR_MAX_LEN];
	int			type;
	struct bpf_object	*bpf_obj;
	struct bpf_program	*bpf_prog;
	gtp_bpf_maps_t		*bpf_maps;
	const gtp_bpf_prog_tpl_t *tpl;
	void			*data;

	list_head_t		next;

	int			refcnt;
	unsigned long		flags;
} gtp_bpf_prog_t;

typedef struct gtp_bpf_prog_attr {
	gtp_bpf_prog_t		*prog;
	struct bpf_link		*lnk;
} gtp_bpf_prog_attr_t;


/* Prototypes */
int gtp_bpf_prog_obj_update_var(struct bpf_object *,
				const gtp_bpf_prog_var_t *);
int gtp_bpf_prog_attr_reset(gtp_bpf_prog_attr_t *);
void gtp_bpf_prog_detach_tc(gtp_bpf_prog_t *, gtp_interface_t *);
int gtp_bpf_prog_attach_tc(gtp_bpf_prog_t *, gtp_interface_t *);
int gtp_bpf_prog_detach_xdp(struct bpf_link *);
struct bpf_link *gtp_bpf_prog_attach_xdp(gtp_bpf_prog_t *, gtp_interface_t *);
int gtp_bpf_prog_deattach(struct bpf_link *);
int gtp_bpf_prog_open(gtp_bpf_prog_t *);
int gtp_bpf_prog_load(gtp_bpf_prog_t *);
void gtp_bpf_prog_unload(gtp_bpf_prog_t *);
int gtp_bpf_prog_destroy(gtp_bpf_prog_t *p);
void gtp_bpf_prog_foreach_prog(int (*hdl) (gtp_bpf_prog_t *, void *),
			       void *, gtp_bpf_prog_mode_t);
gtp_bpf_prog_t *gtp_bpf_prog_get(const char *);
int gtp_bpf_prog_put(gtp_bpf_prog_t *);
gtp_bpf_prog_t *gtp_bpf_prog_alloc(const char *);
int gtp_bpf_progs_destroy(void);
const char *gtp_bpf_prog_tpl_mode2str(gtp_bpf_prog_mode_t);
void gtp_bpf_prog_tpl_register(gtp_bpf_prog_tpl_t *);
const gtp_bpf_prog_tpl_t *gtp_bpf_prog_tpl_get(gtp_bpf_prog_mode_t);
