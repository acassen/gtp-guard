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
#include "rbtree_types.h"

/* Thread types. */
enum thread_type {
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
};

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

union thread_arg2 {
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
};

/* Thread itself. */
struct thread {
	unsigned long id;
	enum thread_type type;		/* thread type */
	struct thread_master *master;	/* pointer to the struct thread_master. */
	void (*func)(struct thread *);	/* event function */
	void *arg;			/* event argument */
	timeval_t sands;		/* rest of time sands value. */
	union thread_arg2 u;		/* second argument of the event. */
	struct thread_event *event;	/* Thread Event back-pointer */

	union {
		struct rb_node n;
		struct list_head e_list;
	};

	struct rb_node rb_data;		/* PID or fd/vrid */
};

/* Thread Event */
struct thread_event {
	struct thread		*read;
	struct thread		*write;
	unsigned long		flags;
	int			fd;

	struct rb_node		n;
};

/* Master of the threads. */
struct thread_master {
	struct rb_root_cached	read;
	struct rb_root_cached	write;
	struct rb_root_cached	timer;
	struct list_head	event;
	struct list_head	ready;
	struct list_head	unuse;

	struct thread		*current_thread;

	/* epoll related */
	struct rb_root		io_events;
	struct epoll_event	*epoll_events;
	struct thread_event		*current_event;
	unsigned int		epoll_size;
	unsigned int		epoll_count;
	int			epoll_fd;

	/* timer related */
	int			timer_fd;
	struct thread		*timer_thread;

	/* signal related */
	int			signal_fd;

	/* Local data */
	unsigned long		alloc;
	unsigned long		id;
	bool			shutdown_timer_running;
};

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
extern struct thread_master *master;

/* Prototypes. */
struct thread_master *thread_make_master(bool nosignal);
struct thread *thread_add_terminate_event(struct thread_master *m);
void thread_destroy_master(struct thread_master *m);
struct thread *thread_add_read_sands(struct thread_master *m, void (*func)(struct thread *),
				     void *arg, int fd, const timeval_t *sands, unsigned flags);
struct thread *thread_add_read(struct thread_master *m, void (*func)(struct thread *),
			       void *arg, int fd, unsigned long timer, unsigned flags);
void thread_requeue_read(struct thread_master *m, int, const timeval_t *sands);
struct thread *thread_add_write(struct thread_master *m, void (*func)(struct thread *), void *arg, int fd,
				unsigned long timer, unsigned flags);
void thread_close_fd(struct thread *t);
struct thread *thread_add_timer_uval(struct thread_master *m, void (*func)(struct thread *),
				     void *arg, unsigned val, uint64_t timer);
struct thread *thread_add_timer(struct thread_master *m, void (*func)(struct thread *),
				void *arg, uint64_t timer);
void thread_mod_timer(struct thread *t, uint64_t timer);
struct thread *thread_add_event(struct thread_master *m, void (*func)(struct thread *),
				void *arg, int val);
void thread_del(struct thread *t);
void launch_thread_scheduler(struct thread_master *m);
