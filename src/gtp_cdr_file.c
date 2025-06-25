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

/* local includes */
#include "gtp_guard.h"


static int
gtp_cdr_file_header_sync(gtp_cdr_file_t *f)
{
	gtp_cdr_spool_t *s = f->spool;

	map_file_t *map_file = f->file;
	int hlen = sizeof(gtp_cdr_file_header_t);
	int sync = __test_bit(GTP_CDR_SPOOL_FL_ASYNC_BIT, &s->flags) ? GTP_DISK_ASYNC :
								       GTP_DISK_SYNC;
	return gtp_disk_msync_offset(map_file, 0, hlen, sync);
}

int
gtp_cdr_file_header_init(gtp_cdr_file_t *f)
{
	map_file_t *map_file = f->file;
	gtp_cdr_file_header_t *h;
	int hlen = sizeof(gtp_cdr_file_header_t);

	if (!map_file || !map_file->map)
		return -1;

	h = (gtp_cdr_file_header_t *) map_file->map;

	/* skip if previously initalized. In case where
	 * daemon restart with existing file. */
	if (h->magic == GTP_CDR_MAGIC)
		return 0;

	h->flen = htonl(hlen);
	h->hlen = h->flen;
	h->magic = GTP_CDR_MAGIC;
	h->file_creation_ts = htobe64(f->create_time);

	return gtp_cdr_file_header_sync(f);
}

int
gtp_cdr_file_write(gtp_cdr_file_t *f, const void *buf, size_t bsize)
{
	gtp_cdr_spool_t *s = f->spool;
	map_file_t *map_file;
	gtp_cdr_file_header_t *h;
	gtp_cdr_header_t *cdrh;
	int err, sync, retry_cnt = 0;
	off_t offset;

retry:
	/* SHOULD only hit one time. Discard otherwise */
	if (retry_cnt > 1)
		return -1;

	/* Already open ? */
	if (!f->file) {
		err = gtp_cdr_file_create(f);
		if (err) {
			log_message(LOG_INFO, "%s(): Unable to create a new cdr file !!!"
					    , __FUNCTION__);
			return -1;
		}
	}

	/* Pointer */
	map_file = f->file;
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

			/* One more time, we're gonna celebrate
			 * Oh yeah, all right, don't stop dancing... */
			gtp_cdr_file_close(f);
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

	sync = __test_bit(GTP_CDR_SPOOL_FL_ASYNC_BIT, &s->flags) ? GTP_DISK_ASYNC :
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

	return gtp_cdr_file_header_sync(f);
}

static map_file_t *
gtp_cdr_file_open(gtp_cdr_file_t *f)
{
	gtp_cdr_spool_t *s = f->spool;
	map_file_t *n;
	time_t t;
	int err;

	if (f->file) {
		errno = EEXIST;
		return NULL;
	}

	PMALLOC(n);
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	bsd_strlcpy(n->path, s->document_root, GTP_PATH_MAX_LEN);
	bsd_strlcat(n->path, "/current", GTP_PATH_MAX_LEN);
	err = gtp_disk_open(n, (s->cdr_file_size) ? : GTP_CDR_DEFAULT_FSIZE);
	if (err) {
		FREE(n);
		return NULL;
	}

	/* Current time init */
	t = time(NULL);
	f->create_time = t;
	f->roll_time = t + (s->roll_period) ? : GTP_CDR_DEFAULT_ROLLPERIOD;

	return n;
}

static int
gtp_cdr_file_build_dst_path(gtp_cdr_file_t *f, char *dst, size_t dsize, time_t t)
{
	gtp_cdr_spool_t *s = f->spool;
	struct tm *date = &f->date;
	char filename[256];
	char *document_root;
	int err;

	/* Get time from file creation */
	memset(date, 0, sizeof(struct tm));
	date->tm_isdst = -1;
	localtime_r(&t, date);

	/* Init dst document root */
	document_root = (s->archive_root[0]) ? s->archive_root : s->document_root;

	/* Seq is 8bits so we only support 256 full cdr files creation per seconds.
	 * which is enough to prevent against DDoS flooding impact on disk space.
	 * In such a scenario simply consider it as a circular buffer. */
	f->file_seq = (f->create_time == t) ? f->file_seq + 1 : 0;
	err = strftime(filename, sizeof(filename), "%Y%m%d%H%M%S", date);
	err = (!err) ? -1 : snprintf(dst, dsize, "%s/%s%s%.3d"
					       , document_root
					       , (s->prefix[0]) ? s->prefix : "cdr_"
					       , filename
					       , f->file_seq);
	return (err < 0);
}

int
gtp_cdr_file_close(gtp_cdr_file_t *f)
{
	map_file_t *map_file = f->file;
	gtp_cdr_spool_t *s = f->spool;
	gtp_cdr_file_header_t *h;
	time_t t;
	int err;

	if (!map_file)
		return -1;

	h = (gtp_cdr_file_header_t *) map_file->map;
	t = be64toh(h->file_creation_ts);

	err = gtp_cdr_file_build_dst_path(f, f->dst_path, GTP_PATH_MAX_LEN, t);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant build filename...", __FUNCTION__);
		goto end;
	}

	/* Resize, Close & Move to final dst */
	log_message(LOG_INFO, "%s(): Closing cdr-file:%s (%ldBytes)"
			    , __FUNCTION__
			    , f->dst_path, ntohl(h->flen));
	gtp_disk_resize(map_file, ntohl(h->flen));
	gtp_disk_close(map_file);
	gtp_disk_mv(map_file->path, f->dst_path);
	if (__test_bit(GTP_CDR_SPOOL_FL_OWNER_BIT, &s->flags))
		gtp_disk_chown(f->dst_path, s->user, s->group);
end:
	FREE(map_file);
	f->file = NULL;
	return 0;
}

int
gtp_cdr_file_create(gtp_cdr_file_t *f)
{
	map_file_t *map_file;
	int err;

	map_file = gtp_cdr_file_open(f);
	if (!map_file)
		return -1;

	f->file = map_file;
	err = gtp_cdr_file_header_init(f);
	if (err) {
		log_message(LOG_INFO, "%s(): error init header for cdr file:%s (%m)"
				    , __FUNCTION__
				    , map_file->path);
		gtp_disk_close(f->file);
		f->file = NULL;
		return -1;
	}

	return 0;
}

gtp_cdr_file_t *
gtp_cdr_file_alloc(void)
{
	gtp_cdr_file_t *n;

	PMALLOC(n);
	if (!n) {
		errno = ENOMEM;
		return NULL;
	}

	return n;
}

int
gtp_cdr_file_destroy(gtp_cdr_file_t *f)
{
	gtp_cdr_file_close(f);
	FREE(f);
	return 0;
}
