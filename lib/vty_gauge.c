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

#include <stdio.h>
#include "utils.h"
#include "vty_gauge.h"

typedef const char *(*gauge_color_fn_t) (float);


/*
 *	True color interpolation
 *
 * source of inspiration for this is btop ;) without the
 * gamma correction (too overkill for our tiny needs here)
 */
struct color {
	float r, g, b;
};

static const struct color color_palette[] = {
	{ 119, 202, 155 },	/* green      */
	{ 203, 192, 108 },	/* yellow-ish */
	{ 220,  76,  76 },	/* red        */
};

static struct color
color_lerp(struct color start, struct color end, float frac)
{
	struct color out;

	out.r = start.r + (end.r - start.r) * frac;
	out.g = start.g + (end.g - start.g) * frac;
	out.b = start.b + (end.b - start.b) * frac;
	return out;
}

static struct color
color_gradient(float frac)
{
	int seg, nstops = ARRAY_SIZE(color_palette);
	float pos;

	if (frac <= 0.0f)
		return color_palette[0];
	if (frac >= 1.0f)
		return color_palette[nstops - 1];

	pos = frac * (nstops - 1);
	seg = (int) pos;
	return color_lerp(color_palette[seg], color_palette[seg + 1],
			  pos - seg);
}

static const char *
ratio_color_gradient(float ratio)
{
	static char buf[20];
	struct color c = color_gradient(ratio);

	snprintf(buf, sizeof(buf), "\033[38;2;%d;%d;%dm"
		    , (int)c.r, (int)c.g, (int)c.b);
	return buf;
}


/*
 *	7-step gradient using 256-color codes
 *
 * less computational, this is the default to be used if
 * color_mode is not explicit.
 */
#define COLOR_RESET	"\033[0m"
static const struct {
	float		threshold;
	const char	*ansi;
} ratio_colors[] = {
	{ 0.14f, "\033[38;5;22m"  },	/* deep green */
	{ 0.28f, "\033[38;5;28m"  },	/* moss       */
	{ 0.42f, "\033[38;5;58m"  },	/* olive      */
	{ 0.57f, "\033[38;5;100m" },	/* khaki      */
	{ 0.71f, "\033[38;5;144m" },	/* sand       */
	{ 0.85f, "\033[38;5;173m" },	/* rust       */
	{ 1.01f, "\033[38;5;131m" },	/* brick      */
#if 0
	/* This one is cold to warm... */
	{ 0.14f, "\033[38;5;23m"  },	/* deep teal  */
	{ 0.28f, "\033[38;5;30m"  },	/* teal       */
	{ 0.42f, "\033[38;5;37m"  },	/* aqua       */
	{ 0.57f, "\033[38;5;73m"  },	/* soft cyan  */
	{ 0.71f, "\033[38;5;186m" },	/* pale sand  */
	{ 0.85f, "\033[38;5;210m" },	/* soft coral */
	{ 1.01f, "\033[38;5;203m" },	/* muted red  */
#endif
};

static const char *
ratio_color(float ratio)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ratio_colors); i++)
		if (ratio < ratio_colors[i].threshold)
			return ratio_colors[i].ansi;
	return ratio_colors[ARRAY_SIZE(ratio_colors) - 1].ansi;
}


/*
 *	History ring buffer
 */
void
gauge_history_push(struct gauge_history *h, float ratio)
{
	h->samples[h->head] = ratio;
	h->head = (h->head + 1) % GAUGE_HISTORY_MAX;
	if (h->count < GAUGE_HISTORY_MAX)
		h->count++;
}

/* Return the i oldest sample (0 = oldest). */
static float
history_get(const struct gauge_history *h, int i)
{
	int idx = (h->head - h->count + i + GAUGE_HISTORY_MAX) % GAUGE_HISTORY_MAX;
	return h->samples[idx];
}


/*
 *	Braille UTF-8 glyph helper
 *
 * Encodes U+2800+mask as a 3-byte UTF-8 sequence into out.
 */
static void
braille_glyph(uint8_t mask, char *out)
{
	out[0] = '\xe2';
	out[1] = (char)(0xa0 | (mask >> 6));
	out[2] = (char)(0x80 | (mask & 0x3f));
	out[3] = '\0';
}


/*
 *	Option 1 — ASCII bar
 */
static void
gauge_ascii(struct vty *vty, const char *label, float ratio,
	    const struct gauge_history *h __attribute__((unused)), int width,
	    const char *left, const char *right,
	    gauge_color_fn_t color_fn __attribute__((unused)))
{
	char bar[width + 1];
	int filled, i;

	filled = (int)(ratio * width);
	for (i = 0; i < width; i++)
		bar[i] = (i < filled) ? '#' : '.';
	bar[width] = '\0';

	vty_out(vty, "%-10s  %s%s%s %5.1f%%%s",
		label, left, bar, right, ratio * 100.0f, VTY_NEWLINE);
}


/*
 *	Option 2 — solid block bar
 *
 * Filled cells use the full block U+2588, empty cells use space.
 * The filled portion is colored green/yellow/red by ratio level.
 * Each codepoint encodes as 3 UTF-8 bytes.
 */

/* U+2588 FULL BLOCK, UTF-8: e2 96 88 */
#define BLOCK_FULL	"\xe2\x96\x88"
#define BLOCK_EMPTY	" "

static void
gauge_block(struct vty *vty, const char *label, float ratio,
	    const struct gauge_history *h __attribute__((unused)), int width,
	    const char *left, const char *right, gauge_color_fn_t color_fn)
{
	int filled, i;

	filled = (int)(ratio * width);

	vty_out(vty, "%-10s  %s%s", label, left, color_fn(ratio));
	for (i = 0; i < filled; i++)
		vty_out(vty, BLOCK_FULL);
	vty_out(vty, COLOR_RESET);
	for (i = filled; i < width; i++)
		vty_out(vty, BLOCK_EMPTY);
	vty_out(vty, "%s %5.1f%%%s", right, ratio * 100.0f, VTY_NEWLINE);
}


/*
 *	Option 3 — braille filled bar
 *
 * Each cell holds a 2×4 braille dot matrix. Dots are filled left column
 * first (top to bottom), then right column, giving 8 sub-levels per cell.
 * This yields 8× the resolution of a plain block bar.
 *
 * Fill sequence (mask values), left column first:
 *   0x00 ⠀  0x01 ⠁  0x03 ⠃  0x07 ⠇
 *   0x47 ⡇  0x4f ⡏  0x5f ⡟  0x7f ⡿  0xff ⣿
 */
static void
gauge_braille(struct vty *vty, const char *label, float ratio,
	      const struct gauge_history *h __attribute__((unused)), int width,
	      const char *left, const char *right, gauge_color_fn_t color_fn)
{
	static const uint8_t fill[9] = {
		0x00, 0x01, 0x03, 0x07, 0x47, 0x4f, 0x5f, 0x7f, 0xff,
	};
	int dots, full_cells, partial, i;
	char glyph[4];

	dots = (int)(ratio * width * 8);
	full_cells = dots / 8;
	partial = dots % 8;

	vty_out(vty, "%-10s  %s%s", label, left, color_fn(ratio));
	for (i = 0; i < full_cells; i++) {
		braille_glyph(fill[8], glyph);
		vty_out(vty, "%s", glyph);
	}
	if (partial && full_cells < width) {
		braille_glyph(fill[partial], glyph);
		vty_out(vty, "%s", glyph);
	}
	vty_out(vty, COLOR_RESET);
	for (i = full_cells + (partial ? 1 : 0); i < width; i++)
		vty_out(vty, " ");
	vty_out(vty, "%s %5.1f%%%s", right, ratio * 100.0f, VTY_NEWLINE);
}


/*
 *	Option 4 — thin line bar
 *
 * Gives a lighter visual weight than the full block bar.
 */

/* U+2501 BOX DRAWINGS HEAVY HORIZONTAL, UTF-8: e2 94 81 */
#define BLOCK_THIN	"\xe2\x94\x81"

static void
gauge_thin(struct vty *vty, const char *label, float ratio,
	   const struct gauge_history *h __attribute__((unused)), int width,
	   const char *left, const char *right, gauge_color_fn_t color_fn)
{
	int filled, i;

	filled = (int)(ratio * width);

	vty_out(vty, "%-10s  %s%s", label, left, color_fn(ratio));
	for (i = 0; i < filled; i++)
		vty_out(vty, BLOCK_THIN);
	vty_out(vty, COLOR_RESET);
	for (i = filled; i < width; i++)
		vty_out(vty, " ");
	vty_out(vty, "%s %5.1f%%%s", right, ratio * 100.0f, VTY_NEWLINE);
}


/*
 *	Option 5 — dot bar
 *
 * Filled dots use U+25CF BLACK CIRCLE, empty use U+25CB WHITE CIRCLE.
 */

/* U+25CF BLACK CIRCLE, UTF-8: e2 97 8f */
#define DOT_FULL	"\xe2\x97\x8f"
/* U+25CB WHITE CIRCLE, UTF-8: e2 97 8b */
#define DOT_EMPTY	"\xe2\x97\x8b"

static void
gauge_dot(struct vty *vty, const char *label, float ratio,
	  const struct gauge_history *h __attribute__((unused)), int width,
	  const char *left, const char *right, gauge_color_fn_t color_fn)
{
	int filled, i;

	filled = (int)(ratio * width);

	vty_out(vty, "%-10s  %s%s", label, left, color_fn(ratio));
	for (i = 0; i < filled; i++)
		vty_out(vty, DOT_FULL);
	vty_out(vty, COLOR_RESET);
	for (i = filled; i < width; i++)
		vty_out(vty, DOT_EMPTY);
	vty_out(vty, "%s %5.1f%%%s", right, ratio * 100.0f, VTY_NEWLINE);
}


/*
 *	Option 6 - Block graph
 *
 * Uses the 8 Unicode vertical block elements (U+2581..U+2588) to encode
 * ratio in 8 levels. Each cell is one sample, the bar scrolls left as new
 * samples arrive. The graph is 'width' columns wide, if fewer samples are
 * available the left side is padded with spaces.
 */
static void
gauge_block_graph(struct vty *vty, const char *label, float ratio,
		  const struct gauge_history *h, int width,
		  const char *left, const char *right, gauge_color_fn_t color_fn)
{
	/*
	 * Block elements U+2581..U+2588, UTF-8 encoded.
	 * Index 0 = ▁ (1/8), index 7 = █ (8/8).
	 */
	static const char *blocks[8] = {
		"\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
		"\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88",
	};
	int pad, samples, i, lvl;
	float s;

	samples = h->count < width ? h->count : width;
	pad = width - samples;

	vty_out(vty, "%-10s  %s", label, left);
	for (i = 0; i < pad; i++)
		vty_out(vty, " ");

	/* oldest sample is at position (count - samples) */
	for (i = h->count - samples; i < h->count; i++) {
		s = history_get(h, i);
		lvl = (int)(s * 8.0f);
		if (lvl > 7) lvl = 7;
		if (lvl < 0) lvl = 0;
		vty_out(vty, "%s%s" COLOR_RESET, color_fn(s), blocks[lvl]);
	}

	vty_out(vty, "%s %5.1f%%%s", right, ratio * 100.0f, VTY_NEWLINE);
}


/*
 *	Option 7 — braille dot graph
 *
 * Each terminal cell holds a 2×4 braille dot matrix (U+2800..U+28FF).
 * Left column carries the older of the two samples, right column the newer.
 * Rows 0..3 map to ratio thresholds 75%, 50%, 25%, 12.5% from top to bottom,
 * giving 4 discrete levels per column.  A dot is lit if the sample exceeds
 * the row's threshold.
 *
 * Braille bit layout (Unicode standard):
 *   dot1(bit0)  dot4(bit3) : top row
 *   dot2(bit1)  dot5(bit4)
 *   dot3(bit2)  dot6(bit5)
 *   dot7(bit6)  dot8(bit7) : bottom row
 *
 * UTF-8 encoding of U+2800+mask (3 bytes, mask 0..255):
 *   byte1: 0xE2
 *   byte2: 0xA0 | (mask >> 6)   : selects U+28{00,40,80,C0} quadrant
 *   byte3: 0x80 | (mask & 0x3F) : offset within quadrant
 */

/* Dot bits for left and right columns, top to bottom. */
static const uint8_t braille_left[4]  = { 0x01, 0x02, 0x04, 0x40 };
static const uint8_t braille_right[4] = { 0x08, 0x10, 0x20, 0x80 };

/* Threshold for each row (fraction of full scale), top = highest. */
static const float braille_thresh[4] = { 0.75f, 0.50f, 0.25f, 0.125f };

static void
gauge_braille_graph(struct vty *vty, const char *label, float ratio,
		    const struct gauge_history *h, int width,
		    const char *left, const char *right, gauge_color_fn_t color_fn)
{
	int needed = 2 * width;
	int samples = h->count < needed ? h->count : needed;
	int pad_cells = width - (samples + 1) / 2;
	int base = h->count - samples;
	int cell, row;

	vty_out(vty, "%-10s  %s", label, left);
	for (cell = 0; cell < pad_cells; cell++)
		vty_out(vty, " ");

	for (cell = 0; cell < width - pad_cells; cell++) {
		int li = base + cell * 2;
		int ri = li + 1;
		float ls = (li < h->count) ? history_get(h, li) : 0.0f;
		float rs = (ri < h->count) ? history_get(h, ri) : 0.0f;
		float col_ratio = (rs > ls) ? rs : ls;
		uint8_t mask = 0;
		char glyph[4];

		for (row = 0; row < 4; row++) {
			if (ls >= braille_thresh[row])
				mask |= braille_left[row];
			if (rs >= braille_thresh[row])
				mask |= braille_right[row];
		}

		braille_glyph(mask, glyph);
		vty_out(vty, "%s%s" COLOR_RESET, color_fn(col_ratio), glyph);
	}

	vty_out(vty, "%s %5.1f%%%s", right, ratio * 100.0f, VTY_NEWLINE);
}


/*
 *	VTY helper
 */
static const struct {
	void (*fn) (struct vty *, const char *, float,
		    const struct gauge_history *, int,
		    const char *, const char *, gauge_color_fn_t);
} vty_gauge_hdl[] = {
	[GAUGE_ASCII]		= { gauge_ascii },
	[GAUGE_BLOCK]		= { gauge_block },
	[GAUGE_BRAILLE]		= { gauge_braille },
	[GAUGE_THIN]		= { gauge_thin },
	[GAUGE_DOT]		= { gauge_dot },
	[GAUGE_BLOCK_GRAPH]	= { gauge_block_graph },
	[GAUGE_BRAILLE_GRAPH]	= { gauge_braille_graph },
};

static const gauge_color_fn_t color_fns[] = {
	[GAUGE_COLOR_256]  = ratio_color,
	[GAUGE_COLOR_TRUE] = ratio_color_gradient,
};

void
vty_gauge(struct vty *vty, const char *label, float ratio,
	  const struct gauge_opts *opts)
{
	int width = opts->width ? : GAUGE_DEFAULT_WIDTH;
	const char *left = opts->left ? : "";
	const char *right = opts->right ? : "";
	gauge_color_fn_t color_fn = ratio_color;

	if (opts->style >= ARRAY_SIZE(vty_gauge_hdl))
		return;

	if (ratio < 0.0f)
		ratio = 0.0f;
	if (ratio > 1.0f)
		ratio = 1.0f;

	if (opts->color_mode < ARRAY_SIZE(color_fns))
		color_fn = color_fns[opts->color_mode];

	vty_gauge_hdl[opts->style].fn(vty, label, ratio, opts->h,
				      width, left, right, color_fn);
}
