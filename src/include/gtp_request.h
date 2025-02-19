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

#ifndef _GTP_REQUEST_H
#define _GTP_REQUEST_H

/* Default values */
#define GTP_REQUEST_THREAD_CNT_DEFAULT	5
#define GTP_REQUEST_BUFFER_SIZE		4096

/* Channel definition */
#define GTP_REQUEST_TCP_TIMEOUT        (3 * TIMER_HZ)
#define GTP_REQUEST_TCP_LISTENER_TIMER (3 * TIMER_HZ)
#define GTP_REQUEST_TCP_TIMER          (3 * TIMER_HZ)

/* Defines */
#define GTP_REQUEST_TIMER		(3 * TIMER_HZ)

/* session flags */
enum session_flags {
	GTP_SESSION_FL_CONNECTED,
	GTP_SESSION_FL_INUSE,
	GTP_SESSION_FL_INPROGRESS,
	GTP_SESSION_FL_RUNNING,
	GTP_SESSION_FL_STOP,
	GTP_SESSION_FL_WRITE,
	GTP_SESSION_FL_READ,
	GTP_SESSION_FL_DONTSEND,
	GTP_SESSION_FL_COMPLETE,
	GTP_SESSION_FL_ASYNCSEND,
};

/* Resquest channel */
typedef struct _gtp_req_worker {
	int			id;
	pthread_t		task;
	int			fd;
	struct _gtp_req_channel *channel;		/* backpointer */

	/* I/O MUX related */
	thread_master_t		*master;
	thread_ref_t		r_thread;

	list_head_t		next;

	unsigned long		flags;
} gtp_req_worker_t;

typedef struct _gtp_req_channel {
	struct sockaddr_storage	addr;
	int			thread_cnt;

	pthread_mutex_t		workers_mutex;
	list_head_t		workers;

	unsigned long		flags;
} gtp_req_channel_t;

typedef struct _gtp_req_session {
	pthread_t		task;
	pthread_attr_t		task_attr;
	struct sockaddr_storage	addr;
	int                     fd;
	FILE			*fp;
	uint32_t                id;

	gtp_req_worker_t	*worker;

	json_writer_t		*jwriter;

	off_t			offset_read;
	off_t			offset_sent;
	char			buffer_in[GTP_REQUEST_BUFFER_SIZE];
	char			buffer_out[GTP_REQUEST_BUFFER_SIZE];
	off_t			buffer_size;
	off_t			offset_header;

	unsigned long		flags;
} gtp_req_session_t;

/* Protocol defines */
#define GTP_IMSI_REQUEST	0x50

#define GTP_ACCESS_ACCEPT	0x01
#define GTP_UNKNOWN_IMSI	0x05
#define GTP_ACCESS_DENY		0x0f
typedef struct __attribute__ ((packed)) _gtp_request_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int    hl:4;
	unsigned int    version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int    version:4;
	unsigned int    hl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	union {
		uint8_t	command;
		uint8_t err_code;
	};
	uint16_t	size;
	uint32_t	request_id;
} gtp_request_header_t;

typedef struct __attribute__ ((packed)) _gtp_imsi_request {
	gtp_request_header_t	header;
	uint64_t		imsi;
	uint32_t		sgsn_ip;
} gtp_imsi_request_t;

/* Prototypes */
extern int gtp_request_worker_start(void);
extern int gtp_request_init(void);
extern int gtp_request_destroy(void);
extern int gtp_request_for_each_worker(gtp_req_channel_t *srv, int (*cb) (gtp_req_worker_t *, void *), void *arg);

#endif
