/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Buffering of output and input.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* buffer definition */
typedef struct _buffer_data {
	struct _buffer_data	*next;

	size_t			cp;	/* Location to add new data. */
	size_t			sp;	/* Pointer to data not yet flushed. */
	unsigned char		data[];	/* Actual data stream (variable length).
					 * real dimension is buffer->size.
					 */
} buffer_data_t;

typedef struct _buffer {
	buffer_data_t		*head;
	buffer_data_t		*tail;

	size_t			size;	/* Size of each buffer_data chunk. */
} buffer_t;

typedef enum _buffer_status {
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
} buffer_status_t;

/* Some defines */
#define BUFFER_SIZE_DEFAULT	4096

/* Some usefull macros */
#define ERRNO_IO_RETRY(EN) \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

/* Prototypes */
buffer_t *buffer_new(size_t size);
void buffer_free(buffer_t *b);
char *buffer_getstr(buffer_t *b);
int buffer_empty(buffer_t *b);
void buffer_reset(buffer_t *b);
void buffer_put(buffer_t *b, const void *p, size_t size);
void buffer_putc(buffer_t *b, uint8_t c);
void buffer_putstr(buffer_t *b, const char *c);
buffer_status_t buffer_write(buffer_t *b, int fd,
                             const void *p, size_t size);
buffer_status_t buffer_flush_all(buffer_t *b, int fd);
buffer_status_t buffer_flush_window(buffer_t *b, int fd, int width,
                                    int height, int erase, int no_more);
buffer_status_t buffer_flush_available(buffer_t *b, int fd);
