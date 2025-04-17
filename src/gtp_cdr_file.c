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

/* system includes */
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


static int
gtp_cdr_file_header_sync(gtp_cdr_spool_t *s)
{
	map_file_t *map_file = s->cdr_file;
	int hlen = sizeof(gtp_cdr_file_header_t);
	int sync = __test_bit(GTP_CDR_FILE_FL_ASYNC_BIT, &s->flags) ? GTP_DISK_ASYNC :
								      GTP_DISK_SYNC;
	return gtp_disk_msync_offset(map_file, 0, hlen, sync);
}

int
gtp_cdr_file_header_init(gtp_cdr_spool_t *s)
{
	map_file_t *map_file = s->cdr_file;
	gtp_cdr_file_header_t *h;
	int hlen = sizeof(gtp_cdr_file_header_t);

	if (!map_file || !map_file->map)
		return -1;

	h = (gtp_cdr_file_header_t *) map_file->map;
	h->flen = htonl(hlen);
	h->hlen = h->flen;
	h->magic = GTP_CDR_MAGIC;
	h->file_creation_ts = htobe64(s->create_time);

	return gtp_cdr_file_header_sync(s);
}

int
gtp_cdr_file_write(gtp_cdr_spool_t *s, const void *buf, size_t bsize)
{
	map_file_t *map_file = s->cdr_file;
	gtp_cdr_file_header_t *h = (gtp_cdr_file_header_t *) map_file->map;
	gtp_cdr_header_t *cdrh;
	off_t offset = ntohl(h->flen);
	int err, sync;

	/* Write CDR */
	cdrh = (gtp_cdr_header_t *) ((uint8_t *)map_file->map + offset);
	cdrh->clen = htons(bsize);
	cdrh->magic = GTP_CDR_MAGIC;
	err = gtp_disk_write(map_file, offset + sizeof(gtp_cdr_header_t), buf, bsize);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant write cdr into file:[%s] (%m)"
				    , __FUNCTION__
				    , map_file->path);
		return -1;
	}

	sync = __test_bit(GTP_CDR_FILE_FL_ASYNC_BIT, &s->flags) ? GTP_DISK_ASYNC :
								  GTP_DISK_SYNC;
	err = gtp_disk_msync_offset(map_file, offset
					    , bsize + sizeof(gtp_cdr_header_t)
					    , sync);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant sync cdr into file:[%s] (%m)"
				    , __FUNCTION__
				    , map_file->path);
		return -1;
	}

	/* Update file header */
	offset += sizeof(gtp_cdr_header_t) + bsize;
	h->flen = htonl(offset);
	h->cdr_count = htonl(ntohl(h->cdr_count) + 1);

	return gtp_cdr_file_header_sync(s);
}

static int
gtp_cdr_file_build_name(gtp_cdr_spool_t *s, map_file_t *map_file)
{
	struct tm *date = &s->date;
	char filename[256];
	int err;

	err = strftime(filename, sizeof(filename), "%Y%m%d%H%M%S", date);
	err = (!err) ? -1 : snprintf(map_file->path, GTP_PATH_MAX_LEN, "%s/%s%s"
						   , s->document_root
						   , (s->prefix[0]) ? "cdr_" : s->prefix
						   , filename);
	return (err < 0);
}

static map_file_t *
gtp_cdr_file_open(gtp_cdr_spool_t *s)
{
	struct tm *date = &s->date;
	map_file_t *n;
	time_t t;
	int err;

	if (s->cdr_file) {
		errno = EEXIST;
		return NULL;
	}

	PMALLOC(n);
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	/* Current time init */
	t = time(NULL);
	memset(date, 0, sizeof(struct tm));
	date->tm_isdst = -1;
	localtime_r(&t, date);

	err = gtp_cdr_file_build_name(s, n);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant build filename...", __FUNCTION__);
		FREE(n);
		return NULL;
	}

	err = gtp_disk_open(n, (s->cdr_file_size) ? : GTP_CDR_DEFAULT_FSIZE);
	if (err) {
		FREE(n);
		return NULL;
	}

	s->create_time = t;
	t += (s->roll_period) ? : GTP_CDR_DEFAULT_ROLLPERIOD;
	s->roll_time = t;

	return n;
}

int
gtp_cdr_file_create(gtp_cdr_spool_t *s)
{
	map_file_t *map_file;
	int err;

	map_file = gtp_cdr_file_open(s);
	if (!map_file)
		return -1;

	s->cdr_file = map_file;
	err = gtp_cdr_file_header_init(s);
	if (err) {
		log_message(LOG_INFO, "%s(): error init header for cdr file:%s (%m)"
				    , __FUNCTION__
				    , map_file->path);
		gtp_disk_close(s->cdr_file);
		s->cdr_file = NULL;
		return -1;
	}

	return 0;
}

int
gtp_cdr_file_spool_destroy(gtp_cdr_spool_t *s)
{
	gtp_disk_close(s->cdr_file);
	FREE(s);
	return 0;
}
