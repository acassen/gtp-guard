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
#pragma once

#include <stddef.h>
#include <sys/types.h>

#define TABLE_MAX_COLUMNS	16
#define TABLE_INITIAL_ROWS	8
#define TABLE_MAX_CELL_LEN	128

enum table_style {
	STYLE_ASCII = 0,
	STYLE_DOTTED,
	STYLE_SINGLE_LINE,
	STYLE_SINGLE_LINE_ROUNDED,
	STYLE_SINGLE_LINE_BORDERLESS,
	STYLE_DOUBLE_LINE,
	STYLE_DOUBLE_LINE_BORDER,
	STYLE_DOUBLE_LINE_BORDERLESS,
	STYLE_BOLD,
	STYLE_BOLD_BORDERLESS,
	STYLE_BOLD_BORDER,
	STYLE_BOLD_TITLE,
	STYLE_BOLD_TITLE_LIGHT,
	STYLE_STRONG,
	STYLE_MAX,
};

enum table_align {
	ALIGN_LEFT = 0,
	ALIGN_CENTER,
	ALIGN_RIGHT,
};

struct table_column {
	char title[TABLE_MAX_CELL_LEN];
	size_t width;
	enum table_align h_align;
	enum table_align align;
};

struct table_cell {
	char data[TABLE_MAX_CELL_LEN];
};

struct table {
	enum table_style style;
	struct table_column columns[TABLE_MAX_COLUMNS];
	int num_columns;

	struct table_cell *cells;
	int num_rows;
	int max_rows;
};

/* Prototypes */
struct table *table_init(int num_columns, enum table_style style);
int table_set_column(struct table *tbl, ...);
int table_set_header_align(struct table *tbl, ...);
int table_set_column_align(struct table *tbl, ...);
int table_add_row(struct table *tbl, ...);
int table_add_row_fmt(struct table *tbl, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
ssize_t table_format(struct table *tbl, unsigned char *dst, size_t dsize);
void table_destroy(struct table *tbl);
