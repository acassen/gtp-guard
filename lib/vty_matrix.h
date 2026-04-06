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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#pragma once

#include "vty_gauge.h"
#include "vty.h"

#define MATRIX_LABEL_LEN    5	/* recommended label_width for gauge cells */
#define MATRIX_DEFAULT_COLS 4

/* One cell in the grid.  value is the per-cell scalar (e.g. load ratio).
 * The render callback receives the entry and the shared opts from matrix_opts. */
struct matrix_entry {
	char	label[16];
	void	(*render)(struct vty *vty, const char *label,
			  const struct matrix_entry *e, void *arg);
	float	value;
};

/* Layout + shared widget opts.  arg is passed as-is to every render call. */
struct matrix_opts {
	int	cols;	/* cells per row, 0 = MATRIX_DEFAULT_COLS */
	void	*arg;	/* shared widget opts (e.g. struct gauge_opts *) */
};

/* Prototypes */
struct matrix_opts *matrix_gauge_opts_alloc(int cols, enum gauge_style style);
void vty_matrix_gauge_render(struct vty *vty, const char *label,
			     const struct matrix_entry *e, void *arg);
void vty_matrix(struct vty *vty, const char *title,
		const struct matrix_entry *entries, int n,
		const struct matrix_opts *opts);
