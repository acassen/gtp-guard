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

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include "disk.h"
#include "gtp_stddef.h"

/* Defines */
#define GTP_CDR_MAGIC			0xe6e6
#define GTP_CDR_DEFAULT_FSIZE		10*1024*1024
#define GTP_CDR_DEFAULT_ROLLPERIOD	7200

/* File data structures */
struct gtp_cdr_file_header {
	uint32_t		flen;
	uint32_t		hlen;
	uint16_t		magic;
	uint16_t		reserved;
	uint64_t		file_creation_ts;
	uint32_t		cdr_count;
} __attribute__((packed));

struct gtp_cdr_header {
	uint16_t		clen;
	uint16_t		magic;
	uint8_t			reserved;
} __attribute__((packed));

struct gtp_cdr_file {
	char			dst_path[GTP_PATH_MAX_LEN];
	struct tm		date;
	time_t			create_time;
	time_t			roll_time;
	struct gtp_cdr_spool	*spool;		/* backpointer */

	struct map_file		*file;
	uint8_t			file_seq;
};


/* Prototypes */
int gtp_cdr_file_header_init(struct gtp_cdr_file *);
int gtp_cdr_file_write(struct gtp_cdr_file *, const void *, size_t);
int gtp_cdr_file_create(struct gtp_cdr_file *);
int gtp_cdr_file_close(struct gtp_cdr_file *);
struct gtp_cdr_file *gtp_cdr_file_alloc(void);
int gtp_cdr_file_destroy(struct gtp_cdr_file *f);
