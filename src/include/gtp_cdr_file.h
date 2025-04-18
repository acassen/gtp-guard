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

#ifndef _GTP_CDR_FILE_H
#define _GTP_CDR_FILE_H

/* Flags */
enum gtp_cdr_file_flags {
	GTP_CDR_FILE_FL_ASYNC_BIT,
};

/* Defines */
#define GTP_CDR_MAGIC			0x0707
#define GTP_CDR_DEFAULT_FSIZE		10*1024*1024
#define GTP_CDR_DEFAULT_ROLLPERIOD	7200

/* File data structures */
typedef struct _gtp_cdr_file_header {
	uint32_t		flen;
	uint32_t		hlen;
	uint16_t		magic;
	uint16_t		reserved;
	uint64_t		file_creation_ts;
	uint32_t		cdr_count;
} __attribute__((packed)) gtp_cdr_file_header_t;

typedef struct _gtp_cdr_header {
	uint16_t		clen;
	uint16_t		magic;
} __attribute__((packed)) gtp_cdr_header_t;

typedef struct _gtp_cdr_spool {
	char			desc[GTP_STR_MAX_LEN];
	char			document_root[GTP_PATH_MAX_LEN];
	char			archive_root[GTP_PATH_MAX_LEN];
	char			dst_path[GTP_PATH_MAX_LEN];
	char			prefix[GTP_NAME_MAX_LEN];
	int			roll_period;
	size_t			cdr_file_size;

	struct tm		date;
	time_t			create_time;
	time_t			roll_time;

	map_file_t		*cdr_file;
	uint8_t			cdr_file_seq;

	unsigned long		flags;
} gtp_cdr_spool_t;

/* Prototypes */
extern int gtp_cdr_file_header_init(gtp_cdr_spool_t *);
extern int gtp_cdr_file_write(gtp_cdr_spool_t *, const void *, size_t);
extern int gtp_cdr_file_create(gtp_cdr_spool_t *);
extern int gtp_cdr_file_close(gtp_cdr_spool_t *);
extern int gtp_cdr_file_spool_destroy(gtp_cdr_spool_t *);

#endif
