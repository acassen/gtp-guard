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
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include "logger.h"
#include "disk.h"


/*
 *      I/O related
 */
static int
disk_mkpath(char *path)
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
disk_mkdir(char *path)
{
	char *p = strrchr(path, '\0');
	int err;

	if (!p)
		return -1;

	while (--p > path && *p != '/') ;

	if (p > path) *p = '\0';
	err = disk_mkpath(path);
	if (p > path) *p = '/';

	return err;
}

int
disk_create(char *path, bool append)
{
	int err, fd = -1;

	fd = open(path, O_CREAT | (append ? O_APPEND : O_TRUNC) | O_RDWR, 0644);
	if (fd >= 0)
		goto end;

	/* Try to create path */
	err = disk_mkdir(path);
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

void
disk_close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

int
disk_rm(const char *path)
{
	return unlink(path);
}

int
disk_mv(char *src, char *dst)
{
	char *p = strrchr(dst, '/');
	int err;

	if (!p)
		return -1;

	if (p > dst) *p = '\0';
	err = access(dst, F_OK);
	if (p > dst) *p = '/';

	err = (err) ? disk_mkdir(dst) : 0;
	if (err)
		return -1;

	return rename(src, dst);
}

int
disk_chown(const char *path, uid_t uid, gid_t gid)
{
	return chown(path, uid, gid);
}

static void *
disk_mmap(int fd, size_t size)
{
	void *map = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		log_message(LOG_INFO, "%s(): Error mmap file with fd:%d size:%llu (%m)"
				    , __FUNCTION__, fd, (unsigned long long) size);
		return NULL;
	}

	return map;
}

static int
disk_map(map_file_t *map_file)
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
		disk_close_fd(&map_file->fd);
		log_message(LOG_INFO, "%s(): Error stat file [%s] (%m)"
				    , __FUNCTION__, map_file->path);
		return -1;
	}

	map_file->map = disk_mmap(map_file->fd, map_file->fstat.st_size);
	if (!map_file->map) {
		disk_close_fd(&map_file->fd);
		return -1;
	}

	disk_close_fd(&map_file->fd);
	return 0;
}

int
disk_map_open(map_file_t *map_file, size_t size)
{
	int err = 0;

	if (!size) {
		errno = EINVAL;
		return -1;
	}

	err = access(map_file->path, F_OK);
	if (!err)
		goto end;

	map_file->fd = disk_create(map_file->path, false);
	if (map_file->fd < 0)
		return -1;

	err = ftruncate(map_file->fd, size);
	if (err) {
		disk_close_fd(&map_file->fd);
		return -1;
	}

	disk_close_fd(&map_file->fd);
end:
	/* FIXME: sanitize file before mapping & unlink if bogus... */
	return disk_map(map_file);
}

int
disk_map_close(map_file_t *map_file)
{
	if (!map_file)
		return -1;

	if (map_file->map) {
		munmap(map_file->map, map_file->fstat.st_size);
		map_file->map = NULL;
	}

	disk_close_fd(&map_file->fd);
	return 0;
}

int
disk_msync_offset(map_file_t *map_file, off_t offset, size_t ssize, int flags)
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
disk_map_resize(map_file_t *map_file, size_t new_size)
{
	int err = 0;

	if (!map_file->map)
		return -1;

	/* sync and close current file */
	err = (err) ? : disk_msync_offset(map_file, 0
						      , map_file->fstat.st_size
						      , MS_ASYNC);
	err = (err) ? : disk_map_close(map_file);
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

	return ftruncate(map_file->fd, new_size);
}

int
disk_map_write(map_file_t *map_file, off_t offset, const void *buf, size_t bsize)
{
	void *cp, *end = map_file->map + map_file->fstat.st_size;

	if (!map_file->map) {
		errno = EINVAL;
		return -1;
	}

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
disk_map_write_async(map_file_t *map_file, off_t offset, const void *buf, size_t bsize)
{
	int err = disk_map_write(map_file, offset, buf, bsize);

	return (err) ? : disk_msync_offset(map_file, offset, bsize, DISK_ASYNC);
}

int
disk_map_write_sync(map_file_t *map_file, off_t offset, const void *buf, size_t bsize)
{
	int err = disk_map_write(map_file, offset, buf, bsize);

	return (err) ? : disk_msync_offset(map_file, offset, bsize, DISK_SYNC);
}

int
disk_write(int fd, const void *buffer, int size)
{
	int offset = 0, ret;

	if (fd < 0)
		return -1;

	while (offset < size) {
		ret = write(fd, buffer + offset, size - offset);
		if (ret < 0)
			return -1;
		offset += ret;
	}

	return 0;
}

int
disk_read(int fd, void *buffer, int size)
{
	int offset = 0, ret = 0;

	if (fd < 0)
		return -1;

	while (offset < size) {
		ret = read(fd, buffer + offset, size - offset);
		if (ret < 0)
			return -1;
		if (!ret) {
			if (!offset)
				return 0;
			errno = ENOEXEC;
			return -1;
		}
		offset += ret;
	}

	return size;
}
