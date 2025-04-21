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

#ifndef _GTP_DISK_H
#define _GTP_DISK_H

/* defines */
#define GTP_DISK_ASYNC	0
#define GTP_DISK_SYNC	1

/* Map file */
typedef struct _map_file {
	char			path[GTP_PATH_MAX_LEN];
	struct stat		fstat;
	int			fd;
	void			*map;
} map_file_t;

/* Prototypes */
extern int gtp_disk_open(map_file_t *, size_t);
extern int gtp_disk_close(map_file_t *);
extern int gtp_disk_resize(map_file_t *, size_t);
extern int gtp_disk_rm(const char *);
extern int gtp_disk_mv(char *, char *);
extern int gtp_disk_chown(const char *, uid_t, gid_t);
extern int gtp_disk_msync_offset(map_file_t *, off_t, size_t, int);
extern int gtp_disk_write(map_file_t *, off_t, const void *, size_t);
extern int gtp_disk_write_sync(map_file_t *, off_t, const void *, size_t);
extern int gtp_disk_write_async(map_file_t *, off_t, const void *, size_t);
extern int gtp_disk_write_restart_counter(void);
extern int gtp_disk_read_restart_counter(void);

#endif
