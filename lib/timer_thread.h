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

enum {
	TIMER_THREAD_FL_STOP_BIT,
};

#define TIMER_THREAD_NAMESIZ	128
typedef struct _timer_thread {
	char			name[TIMER_THREAD_NAMESIZ];
	rb_root_cached_t	timer;
	pthread_mutex_t		timer_mutex;
	pthread_t		task;
	pthread_cond_t		cond;
	pthread_mutex_t		cond_mutex;
	int			(*fired) (void *);

	unsigned long		flags;
} timer_thread_t;

typedef struct _timer_node {
	int		(*to_func) (void *);
	void		*to_arg;
	timeval_t	sands;
	rb_node_t	n;
} timer_node_t;


/* prototypes */
extern void timer_node_expire_now(timer_thread_t *, timer_node_t *);
extern void timer_node_init(timer_node_t *, int (*fn) (void *), void *);
extern void timer_node_add(timer_thread_t *, timer_node_t *, int);
extern int timer_node_pending(timer_node_t *);
extern int timer_node_del(timer_thread_t *, timer_node_t *);
extern int timer_thread_init(timer_thread_t *, const char *, int (*fired) (void *));
extern timer_thread_t *timer_thread_alloc(const char *, int (*fired) (void *));
extern int timer_thread_signal(timer_thread_t *);
extern int timer_thread_destroy(timer_thread_t *);
extern int timer_thread_free(timer_thread_t *);
