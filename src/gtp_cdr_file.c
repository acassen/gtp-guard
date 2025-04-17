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

static int
gtp_cdr_file_mv(const char *src, const char *dst_dir)
{
	char filename[GTP_PATH_MAX_LEN+1];
	char *bname = basename(src);

	if (!bname)
		return -1;

	snprintf(filename, GTP_PATH_MAX_LEN, "%s/%s", dst_dir, bname);

	return gtp_disk_mv(src, filename);
}

static int
gtp_cdr_file_roll(gtp_cdr_spool_t *s)
{
	map_file_t *map_file = s->cdr_file;
	gtp_cdr_file_header_t *h;

	if (!map_file)
		return -1;

	h = (gtp_cdr_file_header_t *) map_file->map;
	gtp_disk_resize(map_file, ntohl(h->flen));
	gtp_cdr_file_close(s);
	s->cdr_file = NULL;

	return gtp_cdr_file_create(s);
}

int
gtp_cdr_file_write(gtp_cdr_spool_t *s, const void *buf, size_t bsize)
{
	map_file_t *map_file;
	gtp_cdr_file_header_t *h;
	gtp_cdr_header_t *cdrh;
	int err, sync, retry_cnt = 0;
	off_t offset;

retry:
	/* SHOULD only hit one time. Discard otherwise */
	if (retry_cnt > 1)
		return -1;

	/* Roll time reached ? */
	if (time(NULL) > s->roll_time) {
		log_message(LOG_INFO, "%s(): roll time reached Creating new file."
				    , __FUNCTION__);

		err = gtp_cdr_file_roll(s);
		if (err) {
			log_message(LOG_INFO, "%s(): Unable to create a new cdr file !!!"
					    , __FUNCTION__);
			return -1;
		}
	}

	/* Pointer */
	map_file = s->cdr_file;
	h = (gtp_cdr_file_header_t *) map_file->map;
	offset = ntohl(h->flen);

	/* Write CDR */
	err = gtp_disk_write(map_file, offset + sizeof(gtp_cdr_header_t), buf, bsize);
	if (err) {
		if (errno == ENOSPC) {
			log_message(LOG_INFO, "%s(): file:[%s] exceed max size."
					      " Creating new file."
					    , __FUNCTION__
					    , map_file->path);
			err = gtp_cdr_file_roll(s);
			if (err) {
				log_message(LOG_INFO, "%s(): Unable to create a new cdr file !!!"
						    , __FUNCTION__);
				return -1;
			}

			/* One more time, we're gonna celebrate
			 * Oh yeah, all right, don't stop dancing... */
			retry_cnt++;
			goto retry;
		}

		log_message(LOG_INFO, "%s(): Cant write cdr into file:[%s] (%m)"
				    , __FUNCTION__
				    , map_file->path);
		return -1;
	}

	/* Create cdr header */
	cdrh = (gtp_cdr_header_t *) ((uint8_t *)map_file->map + offset);
	cdrh->clen = htons(bsize);
	cdrh->magic = GTP_CDR_MAGIC;

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
	s->roll_time = t + (s->roll_period) ? : GTP_CDR_DEFAULT_ROLLPERIOD;

	return n;
}

int
gtp_cdr_file_close(gtp_cdr_spool_t *s)
{
	map_file_t *map_file = s->cdr_file;

	if (!map_file)
		return -1;

	gtp_disk_close(map_file);

	/* Move to archive if specified */
	if (s->archive_root[0])
		gtp_cdr_file_mv(map_file->path, s->archive_root);

	FREE(map_file);
	return 0;
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
