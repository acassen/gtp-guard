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

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include "timer.h"
#include "list_head.h"
#include "rbtree_api.h"

/* Thread types. */
typedef enum {
	THREAD_READ,		/* thread_master.read rb tree */
	THREAD_WRITE,		/* thread_master.write rb tree */
	THREAD_TIMER,		/* thread_master.timer rb tree */
	THREAD_TIMER_SHUTDOWN,	/* thread_master.timer rb tree */
	THREAD_UNUSED,		/* thread_master.unuse list_head */

	/* The following are all on the thread_master.e_list list_head */
	THREAD_EVENT,
	THREAD_WRITE_TIMEOUT,
	THREAD_READ_TIMEOUT,
	THREAD_TERMINATE,
	THREAD_READY_TIMER,
	THREAD_READY_READ_FD,
	THREAD_READY_WRITE_FD,
	THREAD_READ_ERROR,
	THREAD_WRITE_ERROR,
} thread_type_t;

/* Thread Event flags */
enum thread_flags {
	THREAD_FL_READ_BIT,		/* Want read set */
	THREAD_FL_WRITE_BIT,		/* Want write set */
	THREAD_FL_EPOLL_BIT,		/* fd is registered with epoll */
	THREAD_FL_EPOLL_READ_BIT,	/* read is registered */
	THREAD_FL_EPOLL_WRITE_BIT,	/* write is registered */
};

/* epoll def */
#define THREAD_EPOLL_REALLOC_THRESH	64

/* Thread flags for thread destruction */
#define THREAD_DESTROY_CLOSE_FD	0x01
#define THREAD_DESTROY_FREE_ARG	0x02

typedef struct thread thread_t;
typedef void (*thread_func_t)(thread_t *);

typedef union {
	int val;
	unsigned uval;
	struct {
		int fd;		/* file descriptor in case of read/write. */
		unsigned flags;
	} f;
	struct {
		pid_t pid;	/* process id a child thread is wanting. */
		int status;	/* return status of the process */
	} c;
} thread_arg2;

/* Thread itself. */
struct thread {
	unsigned long id;
	thread_type_t type;		/* thread type */
	struct thread_master *master;	/* pointer to the struct thread_master. */
	thread_func_t func;		/* event function */
	void *arg;			/* event argument */
	timeval_t sands;		/* rest of time sands value. */
	thread_arg2 u;			/* second argument of the event. */
	struct thread_event *event;	/* Thread Event back-pointer */

	union {
		rb_node_t n;
		list_head_t e_list;
	};

	rb_node_t rb_data;		/* PID or fd/vrid */
};

/* Thread Event */
typedef struct thread_event {
	thread_t		*read;
	thread_t		*write;
	unsigned long		flags;
	int			fd;

	rb_node_t		n;
} thread_event_t;

/* Master of the threads. */
typedef struct thread_master {
	rb_root_cached_t	read;
	rb_root_cached_t	write;
	rb_root_cached_t	timer;
	list_head_t		event;
	list_head_t		ready;
	list_head_t		unuse;

	thread_t		*current_thread;

	/* epoll related */
	rb_root_t		io_events;
	struct epoll_event	*epoll_events;
	thread_event_t		*current_event;
	unsigned int		epoll_size;
	unsigned int		epoll_count;
	int			epoll_fd;

	/* timer related */
	int			timer_fd;
	thread_t		*timer_thread;

	/* signal related */
	int			signal_fd;

	/* Local data */
	unsigned long		alloc;
	unsigned long		id;
	bool			shutdown_timer_running;
} thread_master_t;

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X) ((X)->u.f.fd)
#define THREAD_VAL(X) ((X)->u.val)

/* Exit codes */
enum exit_code {
	PROG_EXIT_OK = EXIT_SUCCESS,
	PROG_EXIT_NO_MEMORY = EXIT_FAILURE,
	PROG_EXIT_PROGRAM_ERROR,
	PROG_EXIT_FATAL,
	PROG_EXIT_CONFIG,
	PROG_EXIT_CONFIG_TEST,
	PROG_EXIT_CONFIG_TEST_SECURITY,
	PROG_EXIT_NO_CONFIG,
	PROG_EXIT_MISSING_PERMISSION,
} ;

/* global vars exported */
extern thread_master_t *master;

/* Prototypes. */
thread_master_t *thread_make_master(bool nosignal);
thread_t * thread_add_terminate_event(thread_master_t *m);
void thread_destroy_master(thread_master_t *m);
thread_t * thread_add_read_sands(thread_master_t *m, thread_func_t func, void *arg, int fd,
				 const timeval_t *sands, unsigned flags);
thread_t * thread_add_read(thread_master_t *m, thread_func_t func, void *arg, int fd,
			   unsigned long timer, unsigned flags);
void thread_requeue_read(thread_master_t *m, int, const timeval_t *sands);
thread_t * thread_add_write(thread_master_t *m, thread_func_t func, void *arg, int fd,
			    unsigned long timer, unsigned flags);
void thread_close_fd(thread_t *t);
thread_t * thread_add_timer_uval(thread_master_t *m, thread_func_t func, void *arg,
				 unsigned val, uint64_t timer);
thread_t * thread_add_timer(thread_master_t *m, thread_func_t func, void *arg,
			    uint64_t timer);
void thread_mod_timer(thread_t *t, uint64_t timer);
thread_t * thread_add_event(thread_master_t *m, thread_func_t func, void *arg, int val);
void thread_del(thread_t *t);
void launch_thread_scheduler(thread_master_t *m);
