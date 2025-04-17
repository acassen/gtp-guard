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

/* Extern data */
extern data_t *daemon_data;


/*
 *      I/O related
 */
static int
gtp_disk_mkpath(char *path)
{
	struct stat sb;
	char *slash;
	int done = 0, err;

	for (slash = path;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		err = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		if (err) {
			if (!(errno == EEXIST || errno == EISDIR))
				return -1;

			if (stat(path, &sb) < 0)
				return -1;

			if (!S_ISDIR(sb.st_mode))
				return -1;
		}

		if (done)
			break;

		*slash = '/';
	}

	return 0;
}

static int
gtp_disk_mkdir(char *path)
{
	char *p = strrchr(path, '\0');
	int err;

	if (!p)
		return -1;

	while (--p > path && *p != '/') ;

	if (p > path) *p = '\0';
	err = gtp_disk_mkpath(path);
	if (p > path) *p = '/';

	return err;
}

static int
gtp_disk_fopen(char *path)
{
	int err, fd = -1;

	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd >= 0)
		goto end;

	/* Try to create path */
	err = gtp_disk_mkdir(path);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant mkpath for file %s !!! (%m)\n"
				    , __FUNCTION__, path);
		return -1;
	}

	/* Ok target dir is created */
	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd < 0)
		return -1;

end:
	return fd;
}

static int
gtp_disk_close_fd(int *fd)
{
	if (*fd) {
		close(*fd);
		*fd = -1;
	}

	return 0;
}

int
gtp_disk_rm(const char *path)
{
	return unlink(path);
}

int
gtp_disk_mv(const char *src, const char *dst)
{
	return rename(src, dst);
}

static void *
gtp_disk_mmap(int fd, size_t size)
{
	void *map = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		log_message(LOG_INFO, "%s(): Error mmap file with fd:%d size:%llu (%m)"
				    , __FUNCTION__, fd, (unsigned long long) size);
		return NULL;
	}

	return map;
}

static void *
gtp_disk_mremap(int fd, void *map, size_t old_size, size_t new_size, int flags)
{
	void *map_new = mremap(map, old_size, new_size, flags, fd, 0);
	if (map_new == MAP_FAILED) {
		log_message(LOG_INFO, "%s(): Error mremap file with fd:%d old_size:%llu new_size:%llu (%m)"
				    , __FUNCTION__, fd
				    , (unsigned long long) old_size, (unsigned long long) new_size);
		return NULL;
	}

	return map_new;
}

static int
gtp_disk_map(map_file_t *map_file)
{
	if (map_file->map) {
		log_message(LOG_INFO, "%s(): Error opening file [%s] (already mapped)"
				    , __FUNCTION__, map_file->path);
		return -1;
	}

	map_file->fd = open(map_file->path, O_RDWR);
	if (map_file->fd < 0) {
		log_message(LOG_INFO, "%s(): Error opening file [%s] (%m)"
				    , __FUNCTION__, map_file->path);
		return -1;
	}

	if (fstat(map_file->fd, &map_file->fstat) == -1) {
		gtp_disk_close_fd(&map_file->fd);
		log_message(LOG_INFO, "%s(): Error stat file [%s] (%m)"
				    , __FUNCTION__, map_file->path);
		return -1;
	}

	map_file->map = gtp_disk_mmap(map_file->fd, map_file->fstat.st_size);
	if (!map_file->map) {
		gtp_disk_close_fd(&map_file->fd);
		return -1;
	}

	gtp_disk_close_fd(&map_file->fd);
	return 0;
}

int
gtp_disk_open(map_file_t *map_file, size_t size)
{
	int err = 0;

	if (!size) {
		errno = EINVAL;
		return -1;
	}

	err = access(map_file->path, F_OK);
	if (!err)
		goto end;

	map_file->fd = gtp_disk_fopen(map_file->path);
	if (map_file->fd < 0)
		return -1;

	err = ftruncate(map_file->fd, size);
	if (err) {
		gtp_disk_close_fd(&map_file->fd);
		return -1;
	}

	gtp_disk_close_fd(&map_file->fd);
end:
	return gtp_disk_map(map_file);
}

int
gtp_disk_close(map_file_t *map_file)
{
	if (!map_file)
		return -1;

	if (map_file->map) {
		munmap(map_file->map, map_file->fstat.st_size);
		map_file->map = NULL;
	}

	gtp_disk_close_fd(&map_file->fd);
	return 0;
}

int
gtp_disk_msync_offset(map_file_t *map_file, off_t offset, size_t ssize, int flags)
{
	off_t sync_offset;
	int sync_flags = (flags) ? MS_SYNC : MS_ASYNC;
	size_t sync_size;

	if (!map_file->map)
		return -1;

	/* synced zone need to be aligned, assumption : bl_ksize = page_size */
	sync_offset = (offset / map_file->fstat.st_blksize) * map_file->fstat.st_blksize;
	sync_size = ssize + offset % map_file->fstat.st_blksize;

	return msync(map_file->map + sync_offset, sync_size, sync_flags);
}

int
gtp_disk_resize(map_file_t *map_file, size_t new_size)
{
	int err = 0;

	if (!map_file->map)
		return -1;

	/* sync and close current file */
	err = (err) ? : gtp_disk_msync_offset(map_file, 0
						      , map_file->fstat.st_size
						      , MS_ASYNC);
	err = (err) ? : gtp_disk_close(map_file);
	if (err) {
		log_message(LOG_INFO, "%s(): Error closing file [%s] (%m)"
					, __FUNCTION__, map_file->path);
		return -1;
	}

	/* Re-open file */
	map_file->fd = open(map_file->path, O_RDWR);
	if (map_file->fd < 0) {
		log_message(LOG_INFO, "%s(): Error opening file [%s] (%m)"
					, __FUNCTION__, map_file->path);
		return -1;
	}

	err = ftruncate(map_file->fd, new_size);
	if (err)
		goto end;

	map_file->map = gtp_disk_mremap(map_file->fd, map_file->map,
					map_file->fstat.st_size, new_size, MREMAP_MAYMOVE);
	if (!map_file->map) {
		err = -1;
		goto end;
	}

	map_file->fstat.st_size = new_size;
end:
	gtp_disk_close_fd(&map_file->fd);
	return err;
}

int
gtp_disk_write(map_file_t *map_file, off_t offset, const void *buf, size_t bsize)
{
	void *cp, *end = map_file->map + map_file->fstat.st_size;

	if (!map_file->map)
		return -1;

	if (offset >= map_file->fstat.st_size) {
		errno = ENOSPC;
		return -1;
	}

	cp = map_file->map + offset;
	if (cp + bsize > end) {
		errno = ENOSPC;
		return -1;
	}

	memcpy(cp, buf, bsize);
	return 0;
}

int
gtp_disk_write_async(map_file_t *map_file, off_t offset, const void *buf, size_t bsize)
{
	int err = gtp_disk_write(map_file, offset, buf, bsize);

	return (err) ? : gtp_disk_msync_offset(map_file, offset, bsize, GTP_DISK_ASYNC);
}

int
gtp_disk_write_sync(map_file_t *map_file, off_t offset, const void *buf, size_t bsize)
{
	int err = gtp_disk_write(map_file, offset, buf, bsize);

	return (err) ? : gtp_disk_msync_offset(map_file, offset, bsize, GTP_DISK_SYNC);
}

/*
 *      Restart counter file handling
 */
int
gtp_disk_write_restart_counter(void)
{
	FILE *fcounter;

	fcounter = fopen(daemon_data->restart_counter_filename, "w");
	if (!fcounter)
		return -1;

	fprintf(fcounter, "%hhx\n", daemon_data->restart_counter);
	fclose(fcounter);
	return 0;
}

int
gtp_disk_read_restart_counter(void)
{
	FILE *fcounter;
	int ret;

	fcounter = fopen(daemon_data->restart_counter_filename, "r");
	if (!fcounter)
		return -1;

	ret = fscanf(fcounter, "%hhx\n", &daemon_data->restart_counter);
	if (ret != 1) {
		fclose(fcounter);
		return -1;
	}

	fclose(fcounter);
	return daemon_data->restart_counter;
}

