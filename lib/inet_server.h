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

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include "thread.h"
#include "pkt_buffer.h"


/* Default values */
#define INET_SRV_THREAD_CNT_DEFAULT	5
#define INET_SOCKBUF_SIZE		(64 * 1024)

/* Default TCP timer */
#define INET_SRV_TIMEOUT	(3 * TIMER_HZ)
#define INET_SRV_LISTENER_TIMER	(3 * TIMER_HZ)
#define INET_SRV_TIMER		(3 * TIMER_HZ)

/* session flags */
enum inet_server_flags {
	INET_FL_RUNNING_BIT,
	INET_FL_STOP_BIT,
	INET_FL_PIPE_BIT,
};

/* Server */
struct inet_cnx {
	pthread_t		task;
	pthread_attr_t		task_attr;
	struct sockaddr_storage	addr;
	int                     fd;
	FILE			*fp;
	uint32_t                id;

	struct inet_worker	*worker;
	void			*arg;

	char			buffer_in[DEFAULT_PKT_BUFFER_SIZE];
	ssize_t			buffer_in_size;
	char			buffer_out[DEFAULT_PKT_BUFFER_SIZE];
	ssize_t			buffer_out_size;

	unsigned long		flags;
};

struct inet_worker {
	int			id;
	pthread_t		task;
	int			fd;
	struct inet_server	*server;	/* backpointer */
	int			event_pipe[2];

	/* I/O MUX related */
	struct thread_master	*master;
	struct thread		*r_thread;

	struct list_head	next;

	unsigned long		flags;
};

struct inet_server {
	struct sockaddr_storage	addr;
	int			type;		/* SOCK_DGRAM or SOCK_STREAM */

	/* async I/O MUX related */
	int			fd;
	struct pkt_buffer	*pbuff;
	unsigned int		seed;
	void			*ctx;		/* context backpointer */
	struct thread		*r_thread;
	struct thread		*w_thread;

	/* pthread related */
	int			thread_cnt;
	pthread_mutex_t		workers_mutex;
	struct list_head	workers;

	/* Call-back */
	int (*init) (struct inet_server *);
	int (*snd) (struct inet_server *, ssize_t);
	int (*rcv) (struct inet_server *, ssize_t);
	int (*process) (struct inet_server *, struct sockaddr_storage *);
	int (*destroy) (struct inet_server *);
	int (*cnx_init) (struct inet_cnx *);
	int (*cnx_destroy) (struct inet_cnx *);
	ssize_t (*cnx_rcv) (struct inet_cnx *);
	int (*cnx_process) (struct inet_cnx *);

	/* metrics */
	uint64_t		rx_pkts;
	uint64_t		rx_errors;
	uint64_t		tx_pkts;
	uint64_t		tx_errors;

	unsigned long		flags;
};


/* Prototypes */
ssize_t inet_server_snd(struct inet_server *s, int fd, struct pkt_buffer *pbuff,
			struct sockaddr_in *addr);
ssize_t inet_http_read(struct inet_cnx *c);
int inet_server_start(struct inet_server *s, struct thread_master *m);
int inet_server_init(struct inet_server *s, int type);
int inet_server_destroy(struct inet_server *s);
int inet_server_for_each_worker(struct inet_server *s,
				int (*cb) (struct inet_worker *, void *),
				void *arg);
