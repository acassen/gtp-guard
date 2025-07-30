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

/* Flags */
enum gtp_mirror_flags {
	GTP_MIRROR_FL_SHUTDOWN_BIT,
};

/* mirror structure */
typedef struct _gtp_mirror_rule {
	struct sockaddr_storage	addr;
	uint8_t			protocol;
	int			ifindex;
	bool			active;

	list_head_t		next;
} gtp_mirror_rule_t;

typedef struct _gtp_mirror {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	gtp_bpf_prog_t		*bpf_prog;
	list_head_t		rules;

	list_head_t		next;

	int			refcnt;
	unsigned long		flags;
} gtp_mirror_t;


/* Prototypes */
extern gtp_mirror_rule_t *gtp_mirror_rule_get(gtp_mirror_t *,
					      const struct sockaddr_storage *,
					      uint8_t, int);
extern gtp_mirror_rule_t *gtp_mirror_rule_add(gtp_mirror_t *,
					      const struct sockaddr_storage *,
					      uint8_t, int);
extern void gtp_mirror_rule_del(gtp_mirror_rule_t *);
extern void gtp_mirror_action(gtp_mirror_t *, int, int);
extern void gtp_mirror_brd_action(int, int);
extern void gtp_mirror_foreach(int (*hdl) (gtp_mirror_t *, void *), void *);
extern gtp_mirror_t *gtp_mirror_get(const char *);
extern int gtp_mirror_put(gtp_mirror_t *m);
extern gtp_mirror_t *gtp_mirror_alloc(const char *);
extern int gtp_mirror_destroy(gtp_mirror_t *);
extern int gtp_mirrors_destroy(void);