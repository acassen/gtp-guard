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

struct gtp_bpf_prog_var {
	const char *name;
	const void *value;
	uint32_t size;
};


/* BPF prog template */
struct gtp_bpf_prog_tpl {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	size_t			udata_alloc_size;

	int (*opened)(struct gtp_bpf_prog *, void *);
	int (*loaded)(struct gtp_bpf_prog *, void *);

	int (*iface_bind)(struct gtp_bpf_prog *, void *, struct gtp_interface *);
	void (*iface_unbind)(struct gtp_bpf_prog *, void *, struct gtp_interface *);

	void (*vty_iface_show)(struct gtp_bpf_prog *, struct gtp_interface *, struct vty *);

	struct list_head		next;
};


/* Flags */
enum gtp_bpf_prog_flags {
	GTP_BPF_PROG_FL_SHUTDOWN_BIT,
	GTP_BPF_PROG_FL_LOAD_ERR_BIT,
};

struct gtp_bpf_prog_obj {
	struct bpf_object	*obj;
	struct bpf_program	*tc;
	struct bpf_program	*xdp;
};

struct gtp_bpf_prog {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	char			path[GTP_PATH_MAX_LEN];
	char			tc_progname[GTP_STR_MAX_LEN];
	char			xdp_progname[GTP_STR_MAX_LEN];
	const struct gtp_bpf_prog_tpl *tpl[BPF_PROG_TPL_MAX];
	void			*tpl_data[BPF_PROG_TPL_MAX];
	int			tpl_n;
	struct gtp_bpf_prog_obj	run;	/* bpf running */
	struct gtp_bpf_prog_obj	load;	/* bpf being loaded */

	struct list_head	next;

	int			watch_id;
	int			refcnt;
	unsigned long		flags;
};


/* Prototypes */
int gtp_bpf_prog_obj_update_var(struct bpf_object *,
 			       const struct gtp_bpf_prog_var *);
int gtp_bpf_prog_attach(struct gtp_bpf_prog *, struct gtp_interface *);
void gtp_bpf_prog_detach(struct gtp_bpf_prog *, struct gtp_interface *);
int gtp_bpf_prog_open(struct gtp_bpf_prog *);
void gtp_bpf_prog_unload(struct gtp_bpf_prog *);
int gtp_bpf_prog_destroy(struct gtp_bpf_prog *);
int gtp_bpf_prog_tpl_data_set(struct gtp_bpf_prog *, const char *, void *);
void gtp_bpf_prog_foreach_prog(int (*hdl) (struct gtp_bpf_prog *, void *),
 			      void *, const char *);
struct gtp_bpf_prog *gtp_bpf_prog_get(const char *);
int gtp_bpf_prog_put(struct gtp_bpf_prog *);
struct gtp_bpf_prog *gtp_bpf_prog_alloc(const char *);
int gtp_bpf_progs_init(void);
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

static inline void *
gtp_bpf_prog_tpl_data_get(struct gtp_bpf_prog *p, const char *mode)
{
	int i;

	if (p == NULL)
		return NULL;
	for (i = 0; i < p->tpl_n; i++)
		if (!strcmp(mode, p->tpl[i]->name))
			return p->tpl_data[i];
	return NULL;
}
