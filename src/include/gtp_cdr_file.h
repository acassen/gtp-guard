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

/* Defines */
#define GTP_CDR_MAGIC			0xe6e6
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
	uint8_t			reserved;
} __attribute__((packed)) gtp_cdr_header_t;

typedef struct _gtp_cdr_file {
	char			dst_path[GTP_PATH_MAX_LEN];
	struct tm		date;
	time_t			create_time;
	time_t			roll_time;
	struct _gtp_cdr_spool	*spool;		/* backpointer */

	map_file_t		*file;
	uint8_t			file_seq;
} gtp_cdr_file_t;


/* Prototypes */
extern int gtp_cdr_file_header_init(gtp_cdr_file_t *);
extern int gtp_cdr_file_write(gtp_cdr_file_t *, const void *, size_t);
extern int gtp_cdr_file_create(gtp_cdr_file_t *);
extern int gtp_cdr_file_close(gtp_cdr_file_t *);
extern gtp_cdr_file_t *gtp_cdr_file_alloc(void);
extern int gtp_cdr_file_destroy(gtp_cdr_file_t *f);

#endif
