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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

#include "utils.h"
#include "table.h"


/*	Style
 *
 *  TL TH TV TH TR  <- Top
 *  HL    HV    HR  <- Header
 *  SL SH SV SH SR  <- Separator
 *  RL    RV    RR  <- Row
 *  BL BH BV BH BR  <- Bottom
 */
enum border_pos {
	TL = 0, TV, TR, TH,
	HL, HV, HR,
	SL, SV, SR, SH,
	RL, RV, RR,
	BL, BV, BR, BH
};

static const char *table_style[][18] = {
	/* STYLE_ASCII */
	{ "+", "+", "+", "-",
	  "|", "|", "|",
	  "+", "+", "+", "-",
	  "|", "|", "|",
	  "+", "+", "+", "-",
	},
	/* STYLE_DOTTED */
	{ ".", ".", ".", ".",
	  ":", ":", ":",
	  ".", ".", ".", ".",
	  ":", ":", ":",
	  ".", ".", ".", ".",
	},
	/* STYLE_SINGLE_LINE */
	{ "┌", "┬", "┐", "─",
	  "│", "│", "│",
	  "├", "┼", "┤", "─",
	  "│", "│", "│",
	  "└", "┴", "┘", "─",
	},
	/* STYLE_SINGLE_LINE_ROUNDED */
	{ "╭", "┬", "╮", "─",
	  "│", "│", "│",
	  "├", "┼", "┤", "─",
	  "│", "│", "│",
	  "╰", "┴", "╯", "─",
	},
	/* STYLE_SINGLE_LINE_BORDERLESS */
	{ "", "", "", "",
	  "", "│", "",
  	  "", "┼", "", "─",
	  "", "│", "",
	  "", "", "", "",
	},
	/* STYLE_DOUBLE_LINE */
	{ "╔", "╦", "╗", "═", 
	  "║", "║", "║",
	  "╠", "╬", "╣", "═",
	  "║", "║", "║",
	  "╚", "╩", "╝", "═",
	},
	/* STYLE_DOUBLE_LINE_BORDER */
	{ "╔", "╤", "╗", "═", 
	  "║", "│", "║",
	  "╟", "┼", "╢", "─",
	  "║", "│", "║",
	  "╚", "╧", "╝", "═",
	},
	/* STYLE_DOUBLE_LINE_BORDERLESS */
	{ "", "", "", "", 
	  "", "║", "",
	  "", "╬", "", "═",
	  "", "║", "",
	  "", "", "", "",
	},
	/* STYLE_BOLD */
	{ "┏", "┳", "┓", "━", 
	  "┃", "┃", "┃",
	  "┣", "╋", "┫", "━",
	  "┃", "┃", "┃",
	  "┗", "┻", "┛", "━",
	},
	/* STYLE_BOLD_BORDERLESS */
	{ "", "", "", "", 
	  "", "┃", "",
	  "", "╋", "", "━",
	  "", "┃", "",
	  "", "", "", "",
	},
	/* STYLE_BOLD_BORDER */
	{ "┏", "┯", "┓", "━", 
	  "┃", "│", "┃",
	  "┠", "┼", "┨", "─",
	  "┃", "│", "┃",
	  "┗", "┷", "┛", "━",
	},
	/* STYLE_BOLD_TITLE */
	{ "┏", "┳", "┓", "━", 
	  "┃", "┃", "┃",
	  "┣", "╇", "┫", "━",
	  "┃", "│", "┃",
	  "┗", "┷", "┛", "━",
	},
	/* STYLE_BOLD_TITLE_LIGHT */
	{ "┏", "┯", "┓", "━", 
	  "┃", "│", "┃",
	  "┣", "┿", "┫", "━",
	  "┃", "│", "┃",
	  "┗", "┷", "┛", "━",
	},
	/* STYLE_STRONG */
	{ "▛", "▀", "▜", "▀", 
	  "▌", "┃", "▐",
	  "▌", "╋", "▐", "━",
	  "▌", "┃", "▐",
	  "▙", "▄", "▟", "▄",
	},
};


/*
 *	Table Formatter
 */
struct table *
table_init(int num_columns, enum table_style style)
{
	struct table *tbl;
	size_t cells_size;

	if (num_columns <= 0 || num_columns > TABLE_MAX_COLUMNS)
		return NULL;

	/* Allocate table structure */
	tbl = calloc(1, sizeof(struct table));
	if (!tbl)
		return NULL;

	tbl->num_columns = num_columns;
	tbl->num_rows = 0;
	tbl->max_rows = TABLE_INITIAL_ROWS;
	tbl->style = style;

	/* Allocate initial cells array */
	cells_size = TABLE_INITIAL_ROWS * num_columns * sizeof(struct table_cell);
	tbl->cells = calloc(1, cells_size);
	if (!tbl->cells) {
		free(tbl);
		return NULL;
	}

	/* Initialize column widths to title length (will be updated) */
	memset(tbl->columns, 0, sizeof(tbl->columns));

	return tbl;
}

int
table_set_column(struct table *tbl, ...)
{
	struct table_column *column;
	va_list args;
	size_t len;
	int col;

	if (!tbl)
		return -1;

	va_start(args, tbl);
	for (col = 0; col < tbl->num_columns; col++) {
		column = &tbl->columns[col];
		len = bsd_strlcpy(column->title, va_arg(args, const char *),
				  TABLE_MAX_CELL_LEN);
		tbl->columns[col].width = len;
		tbl->columns[col].align = ALIGN_LEFT;  /* Default alignment */
	}
	va_end(args);

	return 0;
}

int
table_set_header_align(struct table *tbl, ...)
{
	va_list args;
	int col;

	if (!tbl)
		return -1;

	va_start(args, tbl);
	for (col = 0; col < tbl->num_columns; col++)
		tbl->columns[col].h_align = va_arg(args, enum table_align);
	va_end(args);

	return 0;
}

int
table_set_column_align(struct table *tbl, ...)
{
	va_list args;
	int col;

	if (!tbl)
		return -1;

	va_start(args, tbl);
	for (col = 0; col < tbl->num_columns; col++)
		tbl->columns[col].align = va_arg(args, enum table_align);
	va_end(args);

	return 0;
}

static int
table_row_resize(struct table *tbl)
{
	struct table_cell *new_cells;
	size_t new_max_rows;
	size_t new_cells_size;

	if (tbl->num_rows < tbl->max_rows)
		return 0;

	/* increase by TABLE_INITIAL_ROWS the capacity */
	new_max_rows = tbl->max_rows + TABLE_INITIAL_ROWS;
	new_cells_size = new_max_rows * tbl->num_columns * sizeof(struct table_cell);

	new_cells = realloc(tbl->cells, new_cells_size);
	if (!new_cells)
		return -1;

	/* Zero out the new memory */
	memset(new_cells + (tbl->max_rows * tbl->num_columns), 0,
	       (new_max_rows - tbl->max_rows) * tbl->num_columns * sizeof(struct table_cell));

	tbl->cells = new_cells;
	tbl->max_rows = new_max_rows;
	return 0;
}

static void
table_add_cell(struct table *tbl, int col, const char *str)
{
	struct table_cell *cell = &tbl->cells[tbl->num_rows * tbl->num_columns + col];
	int len = bsd_strlcpy(cell->data, str, TABLE_MAX_CELL_LEN);

	/* Update column width if necessary */
	if (len > tbl->columns[col].width)
		tbl->columns[col].width = len;
}


int
table_add_row(struct table *tbl, ...)
{
	va_list args;
	int col;

	if (!tbl || table_row_resize(tbl))
		return -1;

	va_start(args, tbl);
	for (col = 0; col < tbl->num_columns; col++)
		table_add_cell(tbl, col, va_arg(args, const char *));
	va_end(args);

	tbl->num_rows++;
	return 0;
}

static int
table_fmt_num_cols(const char *fmt)
{
	const char *pos = fmt;
	size_t sep = 0;

	for (;; sep++, pos++) {
		pos = strchr(pos, '|');
		if (pos == NULL)
			break;
	}

	return sep + 1;
}

int
table_add_row_fmt(struct table *tbl, const char *fmt, ...)
{
	int fmt_col = table_fmt_num_cols(fmt);
	char *pos = tbl->buffer;
	const char *cp = tbl->buffer;
	va_list ap;
	int ret, col;

	if (!tbl || table_row_resize(tbl) || fmt_col != tbl->num_columns)
		return -1;

	va_start(ap, fmt);
	ret = vsnprintf(tbl->buffer, sizeof(tbl->buffer), fmt, ap);
	va_end(ap);

	if (ret < 0)
		return -1;

	for (col = 0; col < tbl->num_columns && pos; col++, cp = pos) {
		pos = strchr(pos, '|');
		if (pos != NULL)
			*pos++ = '\0';
		table_add_cell(tbl, col, cp);
	}

	tbl->num_rows++;
	return ret;
}

static int
table_format_separator(struct table *tbl, unsigned char *dst, size_t dsize,
		       size_t *pos, int idx)
{
	const char **style = table_style[tbl->style];
	int col, i;

	*pos += scnprintf((char *)dst + *pos, dsize - *pos, "%s", style[idx]);
	for (col = 0; col < tbl->num_columns; col++) {
		for (i = 0; i < (int)tbl->columns[col].width + 2; i++)
			*pos += scnprintf((char *)dst + *pos, dsize - *pos, "%s", style[idx+3]);

		/* skip last eol */
		if (col+1 == tbl->num_columns)
			continue;

		*pos += scnprintf((char *)dst + *pos, dsize - *pos, "%s", style[idx+1]);
	}
	*pos += scnprintf((char *)dst + *pos, dsize - *pos, "%s\n", style[idx+2]);
	return 0;
}

static int
table_format_row(struct table *tbl, unsigned char *dst, size_t dsize, size_t *pos,
		 struct table_cell *row_cells, bool is_header, int idx)
{
	const char **style = table_style[tbl->style];
	const char *text;
	int col, width, padding_left, padding_right, text_len;
	enum table_align align;

	*pos += scnprintf((char *)dst + *pos, dsize - *pos, "%s", style[idx]);
	for (col = 0; col < tbl->num_columns; col++) {
		text = (is_header) ? tbl->columns[col].title :
				    row_cells[col].data;
		width = (int)tbl->columns[col].width;
		align = (is_header) ? tbl->columns[col].h_align :
				      tbl->columns[col].align;
		text_len = strlen(text);

		/* Calculate padding based on alignment */
		switch (align) {
		case ALIGN_LEFT:
			*pos += scnprintf((char *)dst + *pos, dsize - *pos, " %-*s ",
					  width, text);
			break;
		case ALIGN_RIGHT:
			*pos += scnprintf((char *)dst + *pos, dsize - *pos, " %*s ",
					  width, text);
			break;
		case ALIGN_CENTER:
			padding_left = (width - text_len) / 2;
			padding_right = width - text_len - padding_left;
			*pos += scnprintf((char *)dst + *pos, dsize - *pos, " %*s%s%*s ",
					  padding_left, "", text, padding_right, "");
			break;
		}

		/* skip last eol */
		if (col+1 == tbl->num_columns)
			continue;

		*pos += scnprintf((char *)dst + *pos, dsize - *pos, "%s", style[idx+1]);

	}
	*pos += scnprintf((char *)dst + *pos, dsize - *pos, "%s\n", style[idx+2]);
	return 0;
}

static int
table_format_header(struct table *tbl, unsigned char *dst, size_t dsize, size_t *pos)
{
	table_format_separator(tbl, dst, dsize, pos, TL);
	table_format_row(tbl, dst, dsize, pos, NULL, true, HL);
	table_format_separator(tbl, dst, dsize, pos, SL);
	return 0;
}

ssize_t
table_format(struct table *tbl, unsigned char *dst, size_t dsize)
{
	size_t pos = 0;
	int row;

	if (!tbl || !dst || !dsize)
		return -1;

	/* Header */
	table_format_header(tbl, dst, dsize, &pos);

	/* Data rows */
	for (row = 0; row < tbl->num_rows; row++) {
		struct table_cell *row_cells = &tbl->cells[row * tbl->num_columns];
		table_format_row(tbl, dst, dsize, &pos, row_cells, false, RL);
	}

	/* Bottom separator */
	table_format_separator(tbl, dst, dsize, &pos, BL);

	return pos;
}

int
table_vty_out(struct table *tbl, struct vty *vty)
{
	unsigned char *dst = (unsigned char *) tbl->buffer;
	size_t dsize = TABLE_BUFFER_SIZE;
	size_t pos = 0;
	int row;

	if (!tbl || !vty)
		return -1;

	/* Header */
	table_format_header(tbl, dst, dsize, &pos);
	vty_out(vty, "%s", dst);
	pos = 0;

	/* Data rows */
	for (row = 0; row < tbl->num_rows; row++) {
		struct table_cell *row_cells = &tbl->cells[row * tbl->num_columns];
		table_format_row(tbl, dst, dsize, &pos, row_cells, false, RL);
		vty_out(vty, "%s", dst);
		pos = 0;
	}

	/* Bottom separator */
	table_format_separator(tbl, dst, dsize, &pos, BL);
	vty_out(vty, "%s", dst);
	return 0;
}

void
table_destroy(struct table *tbl)
{
	if (!tbl)
		return;

	if (tbl->cells)
		free(tbl->cells);

	free(tbl);
}
