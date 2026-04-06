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

#include "vty_matrix.h"

/*
 *	Matrix helpers
 */
struct matrix_opts *
matrix_gauge_opts_alloc(int cols, enum gauge_style style)
{
	struct matrix_opts *o;
	struct gauge_opts *g;

	o = calloc(1, sizeof(*o) + sizeof(*g));
	if (!o)
		return NULL;
	g = (struct gauge_opts *)(o + 1);

	*g = (struct gauge_opts) {
		.style = style,
		.color_mode = GAUGE_COLOR_TRUE,
		.width = 8,
		.label_width = MATRIX_LABEL_LEN,
		.left = "[", .right = "]",
	};
	*o = (struct matrix_opts) {
		.cols = cols,
		.arg = g,
	};
	return o;
}


/*
 *	VTY helpers
 */
void
vty_matrix_gauge_render(struct vty *vty, const char *label,
			const struct matrix_entry *e, void *arg)
{
	vty_gauge_emit(vty, label, e->value, arg);
}

void
vty_matrix(struct vty *vty, const char *title,
	   const struct matrix_entry *entries, int n,
	   const struct matrix_opts *opts)
{
	int cols = opts->cols ? : MATRIX_DEFAULT_COLS;
	int col, i;

	if (title)
		vty_out(vty, " %s%s%s", title, VTY_NEWLINE, VTY_NEWLINE);

	for (i = 0; i < n; i++) {
		col = i % cols;
		if (col)
			vty_out(vty, "  ");

		entries[i].render(vty, entries[i].label, &entries[i], opts->arg);

		if (col == cols - 1 || i == n - 1)
			vty_out(vty, "%s", VTY_NEWLINE);
	}
}
