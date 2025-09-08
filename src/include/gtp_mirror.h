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

#include <stdbool.h>
#include <sys/socket.h>
#include "gtp_bpf_prog.h"

/* Flags */
enum gtp_mirror_flags {
	GTP_MIRROR_FL_SHUTDOWN_BIT,
};

/* mirror structure */
struct gtp_mirror_rule {
	struct sockaddr_storage	addr;
	uint8_t			protocol;
	int			ifindex;
	bool			active;

	struct list_head	next;
};

struct gtp_mirror {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	struct gtp_bpf_prog	*bpf_prog;
	struct list_head	rules;

	struct list_head	next;

	int			refcnt;
	unsigned long		flags;
};


/* Prototypes */
struct gtp_mirror_rule *gtp_mirror_rule_get(struct gtp_mirror *,
					    const struct sockaddr_storage *,
					    uint8_t, int);
struct gtp_mirror_rule *gtp_mirror_rule_add(struct gtp_mirror *,
					    const struct sockaddr_storage *,
					    uint8_t, int);
void gtp_mirror_rule_del(struct gtp_mirror_rule *);
void gtp_mirror_brd_action(int, int);
void gtp_mirror_load_bpf(struct gtp_mirror *);
void gtp_mirror_unload_bpf(struct gtp_mirror *);
void gtp_mirror_foreach(int (*hdl) (struct gtp_mirror *, void *), void *);
struct gtp_mirror *gtp_mirror_get(const char *);
int gtp_mirror_put(struct gtp_mirror *m);
struct gtp_mirror *gtp_mirror_alloc(const char *);
int gtp_mirror_destroy(struct gtp_mirror *);
int gtp_mirrors_destroy(void);
