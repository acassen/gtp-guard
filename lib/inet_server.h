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

#ifndef _INET_SERVER_H
#define _INET_SERVER_H

#include <stdio.h>
#include <pthread.h>
#include "scheduler.h"


/* Default values */
#define INET_SRV_THREAD_CNT_DEFAULT	5
#define INET_BUFFER_SIZE		4096

/* Default TCP timer */
#define INET_TCP_TIMEOUT	(3 * TIMER_HZ)
#define INET_TCP_LISTENER_TIMER	(3 * TIMER_HZ)
#define INET_TCP_TIMER		(3 * TIMER_HZ)
#define INET_SRV_TIMER		(3 * TIMER_HZ)

/* session flags */
enum inet_server_flags {
	INET_FL_RUNNING_BIT,
	INET_FL_STOP_BIT,
};

/* Server */
typedef struct _inet_cnx {
	pthread_t		task;
	pthread_attr_t		task_attr;
	struct sockaddr_storage	addr;
	int                     fd;
	FILE			*fp;
	uint32_t                id;

	struct _inet_worker	*worker;
	void			*arg;

	char			buffer_in[INET_BUFFER_SIZE];
	ssize_t			buffer_in_size;
	char			buffer_out[INET_BUFFER_SIZE];
	ssize_t			buffer_out_size;

	unsigned long		flags;
} inet_cnx_t;

typedef struct _inet_worker {
	int			id;
	pthread_t		task;
	int			fd;
	struct _inet_server	*server;	/* backpointer */

	/* I/O MUX related */
	thread_master_t		*master;
	thread_ref_t		r_thread;

	list_head_t		next;

	unsigned long		flags;
} inet_worker_t;

typedef struct _inet_server {
	struct sockaddr_storage	addr;
	int			thread_cnt;

	pthread_mutex_t		workers_mutex;
	list_head_t		workers;

	/* Call-back */
	int (*cnx_init) (inet_cnx_t *);
	int (*cnx_destroy) (inet_cnx_t *);
	ssize_t (*cnx_rcv) (inet_cnx_t *);
	int (*cnx_process) (inet_cnx_t *);

	unsigned long		flags;
} inet_server_t;



/* Prototypes */
extern ssize_t inet_http_read(inet_cnx_t *);
extern int inet_server_worker_start(inet_server_t *);
extern int inet_server_init(inet_server_t *);
extern int inet_server_destroy(inet_server_t *);
extern int inet_server_for_each_worker(inet_server_t *, int (*cb) (inet_worker_t *, void *), void *);

#endif
