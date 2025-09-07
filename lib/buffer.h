/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Buffering of output and input.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* buffer definition */
struct buffer_data {
	struct buffer_data	*next;

	size_t			cp;	/* Location to add new data. */
	size_t			sp;	/* Pointer to data not yet flushed. */
	unsigned char		data[];	/* Actual data stream (variable length).
					 * real dimension is buffer->size.
					 */
};

struct buffer {
	struct buffer_data	*head;
	struct buffer_data	*tail;

	size_t			size;	/* Size of each buffer_data chunk. */
};

enum buffer_status {
	BUFFER_ERROR = -1,		/* An I/O error occurred.
					 * The buffer should be destroyed and the
					 * file descriptor should be closed.
					 */
	BUFFER_EMPTY = 0,		/* The data was written successfully,
					 * and the buffer is now empty (there is
					 * no pending data waiting to be flushed).
					 */
	BUFFER_PENDING = 1		/* There is pending data in the buffer
					 * waiting to be flushed. Please try
					 * flushing the buffer when select
					 * indicates that the file descriptor
					 * is writeable.
					 */
};

/* Some defines */
#define BUFFER_SIZE_DEFAULT	4096

/* Some usefull macros */
#define ERRNO_IO_RETRY(EN) \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

/* Prototypes */
struct buffer *buffer_new(size_t size);
void buffer_free(struct buffer *b);
char *buffer_getstr(struct buffer *b);
int buffer_empty(struct buffer *b);
void buffer_reset(struct buffer *b);
void buffer_put(struct buffer *b, const void *p, size_t size);
void buffer_putc(struct buffer *b, uint8_t c);
void buffer_putstr(struct buffer *b, const char *c);
enum buffer_status buffer_write(struct buffer *b, int fd,
				const void *p, size_t size);
enum buffer_status buffer_flush_all(struct buffer *b, int fd);
enum buffer_status buffer_flush_window(struct buffer *b, int fd, int width,
				       int height, int erase, int no_more);
enum buffer_status buffer_flush_available(struct buffer *b, int fd);
