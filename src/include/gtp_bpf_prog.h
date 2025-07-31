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
#include "vty.h"
#include "list_head.h"
#include "libbpf.h"
#include "gtp_stddef.h"

#define BPF_PROG_TPL_MAX	6

struct gtp_bpf_prog;
struct gtp_interface;
struct bpf_object;

struct gtp_bpf_prog_var {
	const char *name;
	const void *value;
	uint32_t size;
};

/* BPF program type */
enum {
	GTP_BPF_PROG_TYPE_XDP = 0,
	GTP_BPF_PROG_TYPE_TC,
	GTP_BPF_PROG_TYPE_MAX,
};

/* BPF prog template */
struct gtp_bpf_prog_tpl {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	char			def_progname[GTP_STR_MAX_LEN];

	int (*bind_itf) (struct gtp_bpf_prog *, struct gtp_interface *);
	int (*opened) (struct gtp_bpf_prog *, struct bpf_object *);
	int (*loaded) (struct gtp_bpf_prog *, struct bpf_object *);

	void (*direct_tx_lladdr_updated)(struct gtp_bpf_prog *, struct gtp_interface *);

	void (*vty_iface_show)(struct gtp_bpf_prog *, struct gtp_interface *, struct vty *);

	struct list_head		next;
};


/* Flags */
enum gtp_bpf_prog_flags {
	GTP_BPF_PROG_FL_SHUTDOWN_BIT,
};

/* BPF prog structure */
struct gtp_bpf_maps {
	struct bpf_map		*map;
};

struct gtp_bpf_prog {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	char			path[GTP_PATH_MAX_LEN];
	char			progname[GTP_STR_MAX_LEN];
	int			type;
	struct bpf_object	*bpf_obj;
	struct bpf_program	*bpf_prog;
	struct gtp_bpf_maps	*bpf_maps;
	const struct gtp_bpf_prog_tpl *tpl[BPF_PROG_TPL_MAX];
	int			tpl_n;
	void			*data;

	struct list_head	next;

	int			refcnt;
	unsigned long		flags;
};

struct gtp_bpf_prog_attr {
	struct gtp_bpf_prog	*prog;
	struct bpf_link		*lnk;
};


/* Prototypes */
int gtp_bpf_prog_obj_update_var(struct bpf_object *,
				const struct gtp_bpf_prog_var *);
int gtp_bpf_prog_attr_reset(struct gtp_bpf_prog_attr *);
void gtp_bpf_prog_detach_tc(struct gtp_bpf_prog *, struct gtp_interface *);
int gtp_bpf_prog_attach_tc(struct gtp_bpf_prog *, struct gtp_interface *);
int gtp_bpf_prog_detach_xdp(struct bpf_link *);
struct bpf_link *gtp_bpf_prog_attach_xdp(struct gtp_bpf_prog *, struct gtp_interface *);
int gtp_bpf_prog_deattach(struct bpf_link *);
int gtp_bpf_prog_open(struct gtp_bpf_prog *);
int gtp_bpf_prog_load(struct gtp_bpf_prog *);
void gtp_bpf_prog_unload(struct gtp_bpf_prog *);
int gtp_bpf_prog_destroy(struct gtp_bpf_prog *p);
void gtp_bpf_prog_foreach_prog(int (*hdl) (struct gtp_bpf_prog *, void *),
			       void *, const char *);
struct gtp_bpf_prog *gtp_bpf_prog_get(const char *);
int gtp_bpf_prog_put(struct gtp_bpf_prog *);
struct gtp_bpf_prog *gtp_bpf_prog_alloc(const char *);
int gtp_bpf_progs_destroy(void);
void gtp_bpf_prog_tpl_register(struct gtp_bpf_prog_tpl *);
const struct gtp_bpf_prog_tpl *gtp_bpf_prog_tpl_get(const char *);

static inline bool
gtp_bpf_prog_has_tpl_mode(struct gtp_bpf_prog *p, const char *mode)
{
	int i;

	for (i = 0; i < p->tpl_n; i++)
		if (!strcmp(mode, p->tpl[i]->name))
			return true;
	return false;
}
