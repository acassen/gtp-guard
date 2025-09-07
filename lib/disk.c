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
disk_mkdir(char *pathname)
{
	char *p = strrchr(pathname, '\0');
	int err;

	if (!p)
		return -1;

	while (--p > pathname && *p != '/') ;

	if (p > pathname) *p = '\0';
	err = disk_mkpath(pathname);
	if (p > pathname) *p = '/';

	return err;
}

int
disk_create(char *pathname, bool append)
{
	int err, fd = -1;

	fd = open(pathname, O_CREAT | (append ? O_APPEND : O_TRUNC) | O_RDWR, 0644);
	if (fd >= 0)
		goto end;

	/* Try to create path */
	err = disk_mkdir(pathname);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant mkpath for file %s !!! (%m)\n"
				    , __FUNCTION__, pathname);
		return -1;
	}

	/* Ok target dir is created */
	fd = open(pathname, O_CREAT | O_TRUNC | O_RDWR, 0644);
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
disk_rm(const char *pathname)
{
	return unlink(pathname);
}

int
disk_mv(char *pathsrc, char *pathdst)
{
	char *p = strrchr(pathdst, '/');
	int err;

	if (!p)
		return -1;

	if (p > pathdst) *p = '\0';
	err = access(pathdst, F_OK);
	if (p > pathdst) *p = '/';

	err = (err) ? disk_mkdir(pathdst) : 0;
	if (err)
		return -1;

	return rename(pathsrc, pathdst);
}

int
disk_chown(const char *pathname, uid_t uid, gid_t gid)
{
	return chown(pathname, uid, gid);
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
disk_map(struct map_file *m)
{
	if (m->map) {
		log_message(LOG_INFO, "%s(): Error opening file [%s] (already mapped)"
				    , __FUNCTION__, m->path);
		return -1;
	}

	m->fd = open(m->path, O_RDWR);
	if (m->fd < 0) {
		log_message(LOG_INFO, "%s(): Error opening file [%s] (%m)"
				    , __FUNCTION__, m->path);
		return -1;
	}

	if (fstat(m->fd, &m->fstat) == -1) {
		disk_close_fd(&m->fd);
		log_message(LOG_INFO, "%s(): Error stat file [%s] (%m)"
				    , __FUNCTION__, m->path);
		return -1;
	}

	m->map = disk_mmap(m->fd, m->fstat.st_size);
	if (!m->map) {
		disk_close_fd(&m->fd);
		return -1;
	}

	disk_close_fd(&m->fd);
	return 0;
}

int
disk_map_open(struct map_file *m, size_t size)
{
	int err = 0;

	if (!size) {
		errno = EINVAL;
		return -1;
	}

	err = access(m->path, F_OK);
	if (!err)
		goto end;

	m->fd = disk_create(m->path, false);
	if (m->fd < 0)
		return -1;

	err = ftruncate(m->fd, size);
	if (err) {
		disk_close_fd(&m->fd);
		return -1;
	}

	disk_close_fd(&m->fd);
end:
	/* FIXME: sanitize file before mapping & unlink if bogus... */
	return disk_map(m);
}

int
disk_map_close(struct map_file *m)
{
	if (!m)
		return -1;

	if (m->map) {
		munmap(m->map, m->fstat.st_size);
		m->map = NULL;
	}

	disk_close_fd(&m->fd);
	return 0;
}

int
disk_msync_offset(struct map_file *map_file, off_t offset, size_t ssize, int flags)
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
disk_map_resize(struct map_file *m, size_t new_size)
{
	int err = 0;

	if (!m->map)
		return -1;

	/* sync and close current file */
	err = (err) ? : disk_msync_offset(m, 0, m->fstat.st_size, MS_ASYNC);
	err = (err) ? : disk_map_close(m);
	if (err) {
		log_message(LOG_INFO, "%s(): Error closing file [%s] (%m)"
					, __FUNCTION__, m->path);
		return -1;
	}

	/* Re-open file */
	m->fd = open(m->path, O_RDWR);
	if (m->fd < 0) {
		log_message(LOG_INFO, "%s(): Error opening file [%s] (%m)"
					, __FUNCTION__, m->path);
		return -1;
	}

	return ftruncate(m->fd, new_size);
}

int
disk_map_write(struct map_file *m, off_t offset, const void *buf, size_t bsize)
{
	void *cp, *end = m->map + m->fstat.st_size;

	if (!m->map) {
		errno = EINVAL;
		return -1;
	}

	if (offset >= m->fstat.st_size) {
		errno = ENOSPC;
		return -1;
	}

	cp = m->map + offset;
	if (cp + bsize > end) {
		errno = ENOSPC;
		return -1;
	}

	memcpy(cp, buf, bsize);
	return 0;
}

int
disk_map_write_async(struct map_file *m, off_t offset, const void *buf, size_t bsize)
{
	int err = disk_map_write(m, offset, buf, bsize);

	return (err) ? : disk_msync_offset(m, offset, bsize, DISK_ASYNC);
}

int
disk_map_write_sync(struct map_file *m, off_t offset, const void *buf, size_t bsize)
{
	int err = disk_map_write(m, offset, buf, bsize);

	return (err) ? : disk_msync_offset(m, offset, bsize, DISK_SYNC);
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
