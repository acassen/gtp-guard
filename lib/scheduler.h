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

/* system includes */
#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#ifdef THREAD_DUMP
#include <stdio.h>
#endif

#include "timer.h"
#include "list_head.h"
#include "rbtree_api.h"

/* Thread types. */
typedef enum {
	THREAD_READ,		/* thread_master.read rb tree */
	THREAD_WRITE,		/* thread_master.write rb tree */
	THREAD_TIMER,		/* thread_master.timer rb tree */
	THREAD_TIMER_SHUTDOWN,	/* thread_master.timer rb tree */
	THREAD_CHILD,		/* thread_master.child rb tree */
#define THREAD_MAX_WAITING THREAD_CHILD
	THREAD_UNUSED,		/* thread_master.unuse list_head */

	/* The following are all on the thread_master.e_list list_head */
	THREAD_READY,
	THREAD_EVENT,
	THREAD_WRITE_TIMEOUT,
	THREAD_READ_TIMEOUT,
	THREAD_CHILD_TIMEOUT,
	THREAD_CHILD_TERMINATED,
	THREAD_TERMINATE_START,
	THREAD_TERMINATE,
	THREAD_READY_TIMER,
	THREAD_READY_READ_FD,
	THREAD_READY_WRITE_FD,
	THREAD_READ_ERROR,
	THREAD_WRITE_ERROR,
#ifdef USE_SIGNAL_THREADS
	THREAD_SIGNAL,
#endif
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

typedef struct _thread thread_t;
typedef const thread_t * thread_ref_t;
typedef void (*thread_func_t)(thread_ref_t);

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
struct _thread {
	unsigned long id;
	thread_type_t type;		/* thread type */
	struct _thread_master *master;	/* pointer to the struct thread_master. */
	thread_func_t func;		/* event function */
	void *arg;			/* event argument */
	timeval_t sands;		/* rest of time sands value. */
	thread_arg2 u;			/* second argument of the event. */
	struct _thread_event *event;	/* Thread Event back-pointer */

	union {
		rb_node_t n;
		list_head_t e_list;
	};

	rb_node_t rb_data;		/* PID or fd/vrid */
};

/* Thread Event */
typedef struct _thread_event {
	thread_t		*read;
	thread_t		*write;
	unsigned long		flags;
	int			fd;

	rb_node_t		n;
} thread_event_t;

/* Master of the threads. */
typedef struct _thread_master {
	rb_root_cached_t	read;
	rb_root_cached_t	write;
	rb_root_cached_t	timer;
	rb_root_cached_t	child;
	list_head_t		event;
#ifdef USE_SIGNAL_THREADS
	list_head_t		signal;
#endif
	list_head_t		ready;
	list_head_t		unuse;

	thread_t		*current_thread;

	/* child process related */
	rb_root_t		child_pid;

	/* epoll related */
	rb_root_t		io_events;
	struct epoll_event	*epoll_events;
	thread_event_t		*current_event;
	unsigned int		epoll_size;
	unsigned int		epoll_count;
	int			epoll_fd;

	/* timer related */
	int			timer_fd;
	thread_ref_t		timer_thread;

	/* signal related */
	int			signal_fd;

	/* Local data */
	unsigned long		alloc;
	unsigned long		id;
	bool			shutdown_timer_running;
} thread_master_t;

#ifndef _ONE_PROCESS_DEBUG_
typedef enum {
	PROG_TYPE_PARENT,
} prog_type_t;
#endif

/* MICRO SEC def */
#define BOOTSTRAP_DELAY TIMER_HZ

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X) ((X)->u.f.fd)
#define THREAD_VAL(X) ((X)->u.val)
#define THREAD_CHILD_PID(X) ((X)->u.c.pid)
#define THREAD_CHILD_STATUS(X) ((X)->u.c.status)

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

#define DEFAULT_CHILD_FINDER ((void *)1)

/* global vars exported */
extern thread_master_t *master;
#ifndef _ONE_PROCESS_DEBUG_
extern prog_type_t prog_type;		/* Parent/VRRP/Checker process */
#endif
#ifdef _EPOLL_DEBUG_
extern bool do_epoll_debug;
#endif
#ifdef _EPOLL_THREAD_DUMP_
extern bool do_epoll_thread_dump;
#endif
#ifdef _SCRIPT_DEBUG_
extern bool do_script_debug;
#endif

/* Prototypes. */
extern void set_child_finder_name(char const * (*)(pid_t));
extern void save_cmd_line_options(int, char * const *);
extern char * const * get_cmd_line_options(int *);
extern void log_command_line(unsigned);
#ifndef _ONE_PROCESS_DEBUG_
extern unsigned calc_restart_delay(const timeval_t *, unsigned *, const char *);
extern void log_child_died(const char *, pid_t);
extern bool report_child_status(int, pid_t, const char *);
#endif
extern thread_master_t *thread_make_master(bool);
extern thread_ref_t thread_add_terminate_event(thread_master_t *);
extern thread_ref_t thread_add_start_terminate_event(thread_master_t *, thread_func_t);
#ifdef THREAD_DUMP
extern void dump_thread_data(const thread_master_t *, FILE *);
#endif
extern void thread_cleanup_master(thread_master_t *, bool);
extern void thread_destroy_master(thread_master_t *);
extern thread_ref_t thread_add_read_sands(thread_master_t *, thread_func_t, void *, int, const timeval_t *, unsigned);
extern thread_ref_t thread_add_read(thread_master_t *, thread_func_t, void *, int, unsigned long, unsigned);
extern void thread_del_read(thread_ref_t);
extern void thread_requeue_read(thread_master_t *, int, const timeval_t *);
extern thread_ref_t thread_add_write(thread_master_t *, thread_func_t, void *, int, unsigned long, unsigned);
extern void thread_del_write(thread_ref_t);
extern void thread_close_fd(thread_ref_t);
extern thread_ref_t thread_add_timer_uval(thread_master_t *, thread_func_t, void *, unsigned, unsigned long);
extern thread_ref_t thread_add_timer(thread_master_t *, thread_func_t, void *, unsigned long);
extern void thread_update_arg2(thread_ref_t, const thread_arg2 *);
extern void timer_thread_update_timeout(thread_ref_t, unsigned long);
extern thread_ref_t thread_add_timer_shutdown(thread_master_t *, thread_func_t, void *, unsigned long);
extern thread_ref_t thread_add_child(thread_master_t *, thread_func_t, void *, pid_t, unsigned long);
extern void thread_children_reschedule(thread_master_t *, thread_func_t, unsigned long);
extern thread_ref_t thread_add_event(thread_master_t *, thread_func_t, void *, int);
extern void thread_cancel(thread_ref_t);
extern void thread_cancel_read(thread_master_t *, int);
extern void process_threads(thread_master_t *);
extern void thread_child_handler(void *, int);
extern void thread_add_base_threads(thread_master_t *, bool);
extern void launch_thread_scheduler(thread_master_t *);
#ifndef _ONE_PROCESS_DEBUG_
extern void register_shutdown_function(void (*)(int));
#endif
#ifdef THREAD_DUMP
extern const char *get_signal_function_name(void (*)(void *, int));
extern void register_signal_handler_address(const char *, void (*)(void *, int));
extern void register_thread_address(const char *, thread_func_t);
extern void deregister_thread_addresses(void);
extern void register_scheduler_addresses(void);
#endif
#ifdef _VRRP_FD_DEBUG_
extern void set_extra_threads_debug(void (*)(void));
#endif
