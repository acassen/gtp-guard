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

#include <stdint.h>
#include "vty.h"

/* Color modes */
enum gauge_color_mode {
	GAUGE_COLOR_256 = 0,	/* 256-color palette steps (default) */
	GAUGE_COLOR_TRUE,	/* 24-bit true-color interpolation   */
};

/* Display styles */
enum gauge_style {
	GAUGE_ASCII = 0,	/* '#' filled, '.' empty */
	GAUGE_BLOCK,		/* solid Unicode block █, color-coded */
	GAUGE_BRAILLE,		/* braille filled bar, 8 sub-levels per cell, color-coded */
	GAUGE_THIN,		/* thin line ━, color-coded */
	GAUGE_DOT,		/* filled/empty circles ●/○, color-coded */
	GAUGE_BLOCK_GRAPH,	/* scrolling ▁▂▃▄▅▆▇█ graph, color-coded */
	GAUGE_BRAILLE_GRAPH,	/* 2×4 braille dot graph, color-coded */
};

/* History ring buffer for time-sliding graphs */
#define GAUGE_HISTORY_MAX	256
struct gauge_history {
	float		samples[GAUGE_HISTORY_MAX];
	int		head;		/* index of next write slot */
	int		count;		/* number of valid samples, up to GAUGE_HISTORY_MAX */
};

/* Per-command display options — caller-allocated, opaque to vty. */
#define GAUGE_DEFAULT_WIDTH		40
#define GAUGE_DEFAULT_LABEL_WIDTH	10
struct gauge_opts {
	enum gauge_style		style;
	enum gauge_color_mode		color_mode;
	int				width;		/* bar width, 0 = GAUGE_DEFAULT_WIDTH */
	int				label_width;	/* label padding, 0 = GAUGE_DEFAULT_LABEL_WIDTH */
	const char			*left;		/* left delimiter, NULL = none */
	const char			*right;		/* right delimiter, NULL = none */
	const struct gauge_history	*h;		/* history for graph styles, NULL = none */
};

/* matrix_entry is defined in vty_matrix.h; forward-declare for vty_gauge_render. */
struct matrix_entry;

/* Prototypes */
const char *vty_ratio_color(float ratio, enum gauge_color_mode mode);
void gauge_history_push(struct gauge_history *h, float ratio);
enum gauge_style gauge_style_parse(const char *s);
struct gauge_opts *gauge_opts_alloc(enum gauge_style style);
void vty_gauge_emit(struct vty *vty, const char *label, float ratio,
		    const struct gauge_opts *opts);
void vty_gauge(struct vty *vty, const char *label, float ratio,
	       const struct gauge_opts *opts);
