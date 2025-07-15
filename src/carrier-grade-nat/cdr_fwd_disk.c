/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2010, 2011, 2024 Olivier Gournet, <gournet.olivier@gmail.com>
 */


#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include "tools.h"
#include "cdr_fwd-priv.h"


/*
 *	Disk I/O stuff
 */
static int
cdr_fwd_disk_mkpath(char *path)
{
	struct stat sb;
	int last;
	char *p;
	p = path;

	if (p[0] == '/') ++p;
	for (last = 0; !last ; ++p) {
		if (p[0] == '\0')
			last = 1;
		else
			if (p[0] != '/')
				continue;

		*p = '\0';
		if (!last && p[1] == '\0')
			last = 1;

		if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
			if (errno == EEXIST || errno == EISDIR) {
				if (stat(path, &sb) < 0)
					return -1;
				else
					if (!S_ISDIR(sb.st_mode))
						return -1;
			} else
				return -1;
		}
		if (!last) *p = '/';
	}
	return 0;
}

static int
cdr_fwd_disk_mkdir(char *path)
{
	char *p;

	p = path + strlen(path) - 1;
	while (p-- != path) {
		if (*p == '/')
			break;
	}

	if (p != path) *p = '\0';
	if (cdr_fwd_disk_mkpath(path) < 0)
		return -1;
	if (p != path) *p = '/';

	return 0;
}

int
cdr_fwd_disk_create(char *path, bool append)
{
	int ret, fd;

	fd = open(path, O_CREAT | (append ? O_APPEND : O_TRUNC) | O_RDWR, 0644);
	if (fd < 0) {
		/* Try to create path */
		ret = cdr_fwd_disk_mkdir(path);
		if (ret < 0)
			return -1;

		/* Ok target dir is created */
		fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
		if (fd < 0)
			return -1;
	}

	return fd;
}

int
cdr_fwd_disk_write(int fd, const void *buffer, int size)
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
cdr_fwd_disk_read(int fd, void *buffer, int size)
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

void
cdr_fwd_disk_close_file(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}


/*
 * read a ticket from spool file
 */
int
cdr_fwd_disk_read_ticket(struct cdr_fwd_context *ctx, int fd,
			 struct cdr_fwd_ticket_buffer *ticket,
			 const char *pathname)
{
	int ret;

	/* read ticket size and magic (mtype) */
	ret = cdr_fwd_disk_read(fd, ticket, 8);
	if (ret < 0) {
		err(ctx->log, "%s: %m", pathname);
		return -1;
	}

	/* end of file */
	if (ret == 0)
		return 0;

	/* check magic */
	if ((uint32_t)ticket->mtype != CDR_FWD_MTYPE_STOR_MAGIC) {
		err(ctx->log, "%s: bad magic: 0x%08x != 0x%08x",
		    pathname, ticket->mtype, CDR_FWD_MTYPE_STOR_MAGIC);
		return -1;
	}

	/* check file consistency */
	if (!ticket->size || ticket->size > CDR_FWD_TICKETS_MAX_BUFF) {
		err(ctx->log, "%s: bad ticket->size: %d",
			pathname, ticket->size);
		return -1;
	}

	/* read ticket payload */
	ret = cdr_fwd_disk_read(fd, ticket->mtext, ticket->size);
	if (ret != (int)ticket->size) {
		if (ret < 0)
			err(ctx->log, "%s: %m", pathname);
		else
			err(ctx->log, "%s: eof while reading", pathname);
		return -1;
	}

	return 8 + (int)ticket->size;
}


/*
 * write a ticket to window or spool file
 */
int
cdr_fwd_disk_write_ticket(struct cdr_fwd_context *ctx, int fd,
			  const struct cdr_fwd_ticket_buffer *t,
			  const char *pathname)
{
	struct {
		uint32_t size, magic;
	} v = { t->size, CDR_FWD_MTYPE_STOR_MAGIC };
	int ret = 0;

	/* Write ticket size and magic */
	ret = cdr_fwd_disk_write(fd, &v, 8);
	if (ret < 0) {
		err(ctx->log, "%s: %m", pathname);
		return -1;
	}

	/* Write ticket data */
	if (t->size > 0) {
		ret = cdr_fwd_disk_write(fd, t->mtext, t->size);
		if (ret < 0) {
			err(ctx->log, "%s: %m", pathname);
			return -1;
		}
	}

	return 8 + t->size;
}
