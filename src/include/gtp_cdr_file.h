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

/* Spool */
typedef struct _gtp_cdr_spool {
	char			desc[GTP_STR_MAX_LEN];
	char			document_root[GTP_PATH_MAX_LEN];
	char			archive_root[GTP_PATH_MAX_LEN];
	char			prefix[GTP_NAME_MAX_LEN];
	int			roll_period;

	struct dirent		**spool_cdr;
	struct tm		date;
	time_t			create_time;
	time_t			roll_time;
	time_t			open_time;
	time_t			close_time;

	map_file_t		*cdr_file;
} gtp_cdr_spool_t;

/* Prototypes */

#endif
