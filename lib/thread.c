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

#include "config.h"

#include <errno.h>
#include <sys/wait.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <assert.h>
#include <sys/signalfd.h>
#include <linux/version.h>
#include <sched.h>

#include "thread.h"
#include "memory.h"
#include "rbtree_api.h"
#include "utils.h"
#include "signals.h"
#include "logger.h"
#include "bitops.h"
#include "timer.h"
#include "warnings.h"
#include "process.h"

/* local variables */
static bool shutting_down;


/* Move ready thread into ready queue */
static void
thread_move_ready(thread_master_t *m, rb_root_cached_t *root, thread_t *thread, int type)
{
	rb_erase_cached(&thread->n, root);
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->ready);
	if (thread->type != THREAD_TIMER_SHUTDOWN)
		thread->type = type;
}

/* Move ready thread into ready queue */
static void
thread_rb_move_ready(thread_master_t *m, rb_root_cached_t *root, int type)
{
	thread_t *thread;
	rb_node_t *thread_node;

	while ((thread_node = rb_first_cached(root))) {
		thread = rb_entry(thread_node, thread_t, n);

		if (thread->sands.tv_sec == TIMER_DISABLED || timercmp(&time_now, &thread->sands, <))
			break;

		if (type == THREAD_READ_TIMEOUT)
			thread->event->read = NULL;
		else if (type == THREAD_WRITE_TIMEOUT)
			thread->event->write = NULL;

		thread_move_ready(m, root, thread, type);
	}
}

/* Update timer value */
static void
thread_update_timer(rb_root_cached_t *root, timeval_t *timer_min)
{
	const thread_t *first;
	rb_node_t *first_node;

	if (!(first_node = rb_first_cached(root)))
		return;

	first = rb_entry(first_node, thread_t, n);

	if (first->sands.tv_sec == TIMER_DISABLED)
		return;

	if (!timerisset(timer_min) ||
	    timercmp(&first->sands, timer_min, <=))
		*timer_min = first->sands;
}

/* Compute the wait timer. Take care of timeouted fd */
static timeval_t
thread_set_timer(thread_master_t *m)
{
	timeval_t timer_wait, timer_wait_time;
	struct itimerspec its;

	/* Prepare timer */
	timerclear(&timer_wait_time);
	thread_update_timer(&m->timer, &timer_wait_time);
	thread_update_timer(&m->write, &timer_wait_time);
	thread_update_timer(&m->read, &timer_wait_time);

	if (timerisset(&timer_wait_time)) {
		/* Re-read the current time to get the maximum accuracy */
		set_time_now();

		/* Take care about monotonic clock */
		timersub(&timer_wait_time, &time_now, &timer_wait);

		if (timer_wait.tv_sec < 0) {
			/* This will disable the timerfd */
			timerclear(&timer_wait);
		}
	} else {
		/* set timer to a VERY long time */
		timer_wait.tv_sec = LONG_MAX;
		timer_wait.tv_usec = 0;
	}

	its.it_value.tv_sec = timer_wait.tv_sec;
	if (!timerisset(&timer_wait)) {
		/* We could try to avoid doing the epoll_wait since
		 * testing shows it takes about 4 microseconds
		 * for the timer to expire. */
		its.it_value.tv_nsec = 1;
	}
	else
		its.it_value.tv_nsec = timer_wait.tv_usec * 1000;

	/* We don't want periodic timer expiry */
	its.it_interval.tv_sec = its.it_interval.tv_nsec = 0;

	if (timerfd_settime(m->timer_fd, 0, &its, NULL))
		log_message(LOG_INFO, "Setting timer_fd returned errno %d - %m", errno);

	return timer_wait_time;
}

static void
thread_timerfd_handler(thread_t *thread)
{
	thread_master_t *m = thread->master;
	uint64_t expired;
	ssize_t len;

	len = read(m->timer_fd, &expired, sizeof(expired));
	if (len < 0)
		log_message(LOG_ERR, "scheduler: Error reading on timerfd fd:%d (%m)", m->timer_fd);

	/* Read, Write, Timer, Child thread. */
	thread_rb_move_ready(m, &m->read, THREAD_READ_TIMEOUT);
	thread_rb_move_ready(m, &m->write, THREAD_WRITE_TIMEOUT);
	thread_rb_move_ready(m, &m->timer, THREAD_READY_TIMER);

	/* Register next timerfd thread */
	m->timer_thread = thread_add_read(m, thread_timerfd_handler, NULL, m->timer_fd, TIMER_NEVER, 0);
}

/* epoll related */
static int
thread_events_resize(thread_master_t *m, int delta)
{
	unsigned int new_size;

	m->epoll_count += delta;
	if (m->epoll_count < m->epoll_size)
		return 0;

	new_size = ((m->epoll_count / THREAD_EPOLL_REALLOC_THRESH) + 1);
	new_size *= THREAD_EPOLL_REALLOC_THRESH;

	if (m->epoll_events)
		FREE(m->epoll_events);
	m->epoll_events = MALLOC(new_size * sizeof(struct epoll_event));
	if (!m->epoll_events) {
		m->epoll_size = 0;
		return -1;
	}

	m->epoll_size = new_size;
	return 0;
}

static inline int
thread_event_cmp(const void *key, const rb_node_t *a)
{
	int fd = *((int *) key);

	return fd - rb_entry_const(a, thread_event_t, n)->fd;
}

static inline bool
thread_event_less(rb_node_t *a, const rb_node_t *b)
{
	return rb_entry(a, thread_event_t, n)->fd < rb_entry_const(b, thread_event_t, n)->fd;
}

static thread_event_t *
thread_event_new(thread_master_t *m, int fd)
{
	thread_event_t *event;

	PMALLOC(event);
	if (!event)
		return NULL;

	if (thread_events_resize(m, 1) < 0) {
		FREE(event);
		return NULL;
	}

	event->fd = fd;

	rb_add(&event->n, &m->io_events, thread_event_less);

	return event;
}

static thread_event_t * __attribute__ ((pure))
thread_event_get(thread_master_t *m, int fd)
{
	rb_node_t *node;

	node = rb_find(&fd, &m->io_events, thread_event_cmp);

	if (!node)
		return NULL;
	return rb_entry(node, thread_event_t, n);
}

static int
thread_event_set(const thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;
	struct epoll_event ev = { .events = 0, .data.ptr = event };
	int op;

	if (__test_bit(THREAD_FL_READ_BIT, &event->flags))
		ev.events |= EPOLLIN;

	if (__test_bit(THREAD_FL_WRITE_BIT, &event->flags))
		ev.events |= EPOLLOUT;

	if (__test_bit(THREAD_FL_EPOLL_BIT, &event->flags))
		op = EPOLL_CTL_MOD;
	else
		op = EPOLL_CTL_ADD;

	if (epoll_ctl(m->epoll_fd, op, event->fd, &ev) < 0) {
		log_message(LOG_INFO, "scheduler: Error %d performing control on EPOLL instance for fd %d (%m)", errno, event->fd);
		return -1;
	}

	__set_bit(THREAD_FL_EPOLL_BIT, &event->flags);
	return 0;
}

static int
thread_event_cancel(const thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;

	if (!event) {
		log_message(LOG_INFO, "scheduler: Error performing epoll_ctl DEL op no event linked?!");
		return -1;
	}

	/* Ignore error if we don't know if they have been closed */
	if (m->epoll_fd != -1 &&
	    epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, event->fd, NULL) < 0)
		log_message(LOG_INFO, "scheduler: Error performing epoll_ctl DEL op for fd:%d (%m)", event->fd);

	rb_erase(&event->n, &m->io_events);
	if (event == m->current_event)
		m->current_event = NULL;

	thread_events_resize(m, -1);
	FREE(event);
	return 0;
}

static int
thread_event_del(const thread_t *thread, unsigned flag)
{
	thread_event_t *event = thread->event;

	if (!__test_bit(flag, &event->flags))
		return 0;

	if (flag == THREAD_FL_EPOLL_READ_BIT) {
		__clear_bit(THREAD_FL_READ_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags))
			return thread_event_cancel(thread);

		event->read = NULL;
	}
	else if (flag == THREAD_FL_EPOLL_WRITE_BIT) {
		__clear_bit(THREAD_FL_WRITE_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags))
			return thread_event_cancel(thread);

		event->write = NULL;
	}

	if (thread_event_set(thread) < 0)
		return -1;

	__clear_bit(flag, &event->flags);
	return 0;
}

/* Make thread master. */
thread_master_t *
thread_make_master(bool nosignal)
{
	thread_master_t *new;

	PMALLOC(new);

	new->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (new->epoll_fd < 0) {
		log_message(LOG_INFO, "scheduler: Error creating EPOLL instance (%m)");
		FREE(new);
		return NULL;
	}

	new->read = RB_ROOT_CACHED;
	new->write = RB_ROOT_CACHED;
	new->timer = RB_ROOT_CACHED;
	new->io_events = RB_ROOT;
	INIT_LIST_HEAD(&new->event);
	INIT_LIST_HEAD(&new->ready);
	INIT_LIST_HEAD(&new->unuse);

	/* Register timerfd thread */
	new->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (new->timer_fd < 0) {
		log_message(LOG_ERR, "scheduler: Cant create timerfd (%m)");
		FREE(new);
		return NULL;
	}

	if (!nosignal)
		new->signal_fd = signal_handler_init();

	new->timer_thread = thread_add_read(new, thread_timerfd_handler, NULL, new->timer_fd, TIMER_NEVER, 0);

	if (!nosignal)
		add_signal_read_thread(new);

	return new;
}


/* declare thread_timer_less() for rbtree compares */
RB_TIMER_LESS(thread, n);

/* Free all unused thread. */
static void
thread_clean_unuse(thread_master_t *m)
{
	thread_t *thread, *thread_tmp;
	list_head_t *l = &m->unuse;

	list_for_each_entry_safe(thread, thread_tmp, l, e_list) {
		list_del_init(&thread->e_list);

		/* free the thread */
		FREE(thread);
		m->alloc--;
	}

	INIT_LIST_HEAD(l);
}

/* Move thread to unuse list. */
static void
thread_add_unuse(thread_master_t *m, thread_t *thread)
{
	assert(m != NULL);

	thread->type = THREAD_UNUSED;
	thread->event = NULL;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->unuse);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(thread_master_t *m, list_head_t *l)
{
	thread_t *thread, *thread_tmp;

	list_for_each_entry_safe(thread, thread_tmp, l, e_list) {
		/* The following thread types are relevant for the ready list */
		if (thread->type == THREAD_READY_READ_FD ||
		    thread->type == THREAD_READY_WRITE_FD ||
		    thread->type == THREAD_READ_TIMEOUT ||
		    thread->type == THREAD_WRITE_TIMEOUT ||
		    thread->type == THREAD_READ_ERROR ||
		    thread->type == THREAD_WRITE_ERROR) {
			/* Do we have a thread_event, and does it need deleting? */
			if (thread->event) {
				thread_del_read(thread);
				thread_del_write(thread);
			}

			/* Do we have a file descriptor that needs closing ? */
			if (thread->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(thread);

			/* Do we need to free arg? */
			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		list_del_init(&thread->e_list);
		thread_add_unuse(m, thread);
	}
}

static void
thread_destroy_rb(thread_master_t *m, rb_root_cached_t *root)
{
	thread_t *thread;
	thread_t *thread_sav;

	rbtree_postorder_for_each_entry_safe(thread, thread_sav, &root->rb_root, n) {
		/* The following are relevant for the read and write rb lists */
		if (thread->type == THREAD_READ ||
		    thread->type == THREAD_WRITE) {
			/* Do we have a thread_event, and does it need deleting? */
			if (thread->type == THREAD_READ)
				thread_del_read(thread);
			else if (thread->type == THREAD_WRITE)
				thread_del_write(thread);

			/* Do we have a file descriptor that needs closing ? */
			if (thread->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(thread);

			/* Do we need to free arg? */
			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		thread_add_unuse(m, thread);
	}

	*root = RB_ROOT_CACHED;
}

/* Cleanup master */
void
thread_cleanup_master(thread_master_t *m)
{
	/* Unuse current thread lists */
	m->current_event = NULL;
	thread_destroy_rb(m, &m->read);
	thread_destroy_rb(m, &m->write);
	thread_destroy_rb(m, &m->timer);
	thread_destroy_list(m, &m->event);
	thread_destroy_list(m, &m->ready);

	if (m->current_thread) {
		thread_add_unuse(m, m->current_thread);
		m->current_thread = NULL;
	}

	/* Clean garbage */
	thread_clean_unuse(m);

	FREE(m->epoll_events);
	m->epoll_size = 0;
	m->epoll_count = 0;

	m->timer_thread = NULL;
}

/* Stop thread scheduler. */
void
thread_destroy_master(thread_master_t *m)
{
	if (m->epoll_fd != -1) {
		close(m->epoll_fd);
		m->epoll_fd = -1;
	}

	if (m->timer_fd != -1)
		close(m->timer_fd);

	if (m->signal_fd != -1)
		signal_handler_destroy();

	thread_cleanup_master(m);

	FREE(m);
}

/* Delete top of the list and return it. */
static thread_t *
thread_trim_head(list_head_t *l)
{
	thread_t *thread;

	if (list_empty(l))
		return NULL;

	thread = list_first_entry(l, thread_t, e_list);
	list_del_init(&thread->e_list);
	return thread;
}

/* Make unique thread id for non pthread version of thread manager. */
static inline unsigned long
thread_get_id(thread_master_t *m)
{
	return m->id++;
}

/* Make new thread. */
static thread_t *
thread_new(thread_master_t *m)
{
	thread_t *new;

	/* If one thread is already allocated return it */
	new = thread_trim_head(&m->unuse);
	if (!new) {
		PMALLOC(new);
		m->alloc++;
	}

	INIT_LIST_HEAD(&new->e_list);
	new->id = thread_get_id(m);
	return new;
}

/* Add new read thread. */
thread_t *
thread_add_read_sands(thread_master_t *m, thread_func_t func, void *arg, int fd, const timeval_t *sands, unsigned flags)
{
	thread_event_t *event;
	thread_t *thread;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd)
		event = m->current_event;
	else
		event = thread_event_get(m, fd);

	if (!event) {
		if (!(event = thread_event_new(m, fd))) {
			log_message(LOG_INFO, "scheduler: Cant allocate read event for fd [%d](%m)", fd);
			return NULL;
		}
	}
	else if (__test_bit(THREAD_FL_READ_BIT, &event->flags) && event->read) {
		log_message(LOG_INFO, "scheduler: There is already read event %p (read %p) registered on fd [%d]", event, event->read, fd);
		return NULL;
	}

	thread = thread_new(m);
	thread->type = THREAD_READ;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.f.fd = fd;
	thread->u.f.flags = flags;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_READ_BIT, &event->flags);
	event->read = thread;
	if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
		if (thread_event_set(thread) < 0) {
			log_message(LOG_INFO, "scheduler: Cant register read event for fd [%d](%m)", fd);
			thread_add_unuse(m, thread);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
	}

	thread->sands = *sands;

	/* Sort the thread. */
	rb_add_cached(&thread->n, &m->read, thread_timer_less);

	return thread;
}

thread_t *
thread_add_read(thread_master_t *m, thread_func_t func, void *arg, int fd, unsigned long timer, unsigned flags)
{
	timeval_t sands;

	/* Compute read timeout value */
	if (timer == TIMER_NEVER) {
		sands.tv_sec = TIMER_DISABLED;
		sands.tv_usec = 0;
	} else {
		set_time_now();
		sands = timer_add_long(time_now, timer);
	}

	return thread_add_read_sands(m, func, arg, fd, &sands, flags);
}

static void
thread_read_requeue(thread_master_t *m, int fd, const timeval_t *new_sands)
{
	thread_t *thread;
	thread_event_t *event;

	event = thread_event_get(m, fd);
	if (!event || !event->read)
		return;

	thread = event->read;

	if (thread->type != THREAD_READ) {
		/* If the thread is not on the read list, don't touch it */
		return;
	}

	thread->sands = *new_sands;

	rb_move_cached(&thread->n, &thread->master->read, thread_timer_less);
}

/* Adjust the timeout of a read thread */
void
thread_requeue_read(thread_master_t *m, int fd, const timeval_t *sands)
{
	thread_read_requeue(m, fd, sands);
}

/* Add new write thread. */
thread_t *
thread_add_write(thread_master_t *m, thread_func_t func, void *arg, int fd, unsigned long timer, unsigned flags)
{
	thread_event_t *event;
	thread_t *thread;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd)
		event = m->current_event;
	else
		event = thread_event_get(m, fd);

	if (!event) {
		if (!(event = thread_event_new(m, fd))) {
			log_message(LOG_INFO, "scheduler: Cant allocate write event for fd [%d](%m)", fd);
			return NULL;
		}
	}
	else if (__test_bit(THREAD_FL_WRITE_BIT, &event->flags) && event->write) {
		log_message(LOG_INFO, "scheduler: There is already write event registered on fd [%d]", fd);
		return NULL;
	}

	thread = thread_new(m);
	thread->type = THREAD_WRITE;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.f.fd = fd;
	thread->u.f.flags = flags;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_WRITE_BIT, &event->flags);
	event->write = thread;
	if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags)) {
		if (thread_event_set(thread) < 0) {
			log_message(LOG_INFO, "scheduler: Cant register write event for fd [%d](%m)" , fd);
			thread_add_unuse(m, thread);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags);
	}

	/* Compute write timeout value */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort the thread. */
	rb_add_cached(&thread->n, &m->write, thread_timer_less);

	return thread;
}

void
thread_close_fd(thread_t *thread)
{
	if (thread->u.f.fd == -1)
		return;

	if (thread->event)
		thread_event_cancel(thread);

	close(thread->u.f.fd);
	thread->u.f.fd = -1;
}

/* Add timer event thread. */
thread_t *
thread_add_timer_uval(thread_master_t *m, thread_func_t func, void *arg, unsigned val, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TIMER;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.uval = val;

	/* Do we need jitter here? */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort by timeval. */
	rb_add_cached(&thread->n, &m->timer, thread_timer_less);

	return thread;
}

thread_t *
thread_add_timer(thread_master_t *m, thread_func_t func, void *arg, unsigned long timer)
{
	return thread_add_timer_uval(m, func, arg, 0, timer);
}

void
thread_update_arg2(thread_t * thread_cp, const thread_arg2 *u)
{
	thread_t *thread = no_const(thread_t, thread_cp);

	thread->u = *u;
}

void
thread_mod_timer(thread_t *thread, unsigned long timer)
{
	timeval_t sands;

	set_time_now();
	sands = timer_add_long(time_now, timer);

	if (timercmp(&thread->sands, &sands, ==))
		return;

	thread->sands = sands;

	rb_move_cached(&thread->n, &thread->master->timer, thread_timer_less);
}

thread_t *
thread_add_timer_shutdown(thread_master_t *m, thread_func_t func, void *arg, unsigned long timer)
{
	union {
		thread_t *p;
		thread_t *cp;
	} thread;

	thread.cp = thread_add_timer(m, func, arg, timer);

	thread.p->type = THREAD_TIMER_SHUTDOWN;

	return thread.cp;
}

/* Add simple event thread. */
thread_t *
thread_add_event(thread_master_t *m, thread_func_t func, void *arg, int val)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_EVENT;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->event);

	return thread;
}

/* Add terminate event thread. */
static thread_t *
thread_add_generic_terminate_event(thread_master_t *m, thread_type_t type, thread_func_t func)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = type;
	thread->master = m;
	thread->func = func;
	thread->arg = NULL;
	thread->u.val = 0;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->event);

	return thread;
}

thread_t *
thread_add_terminate_event(thread_master_t *m)
{
	return thread_add_generic_terminate_event(m, THREAD_TERMINATE, NULL);
}

thread_t *
thread_add_start_terminate_event(thread_master_t *m, thread_func_t func)
{
	return thread_add_generic_terminate_event(m, THREAD_TERMINATE_START, func);
}

/* Remove thread from scheduler. */
void
thread_del(thread_t *thread)
{
	thread_master_t *m;

	if (!thread)
		return;

	m = thread->master;

	switch (thread->type) {
	case THREAD_READ:
		thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		rb_erase_cached(&thread->n, &m->read);
		break;
	case THREAD_WRITE:
		thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
		rb_erase_cached(&thread->n, &m->write);
		break;
	case THREAD_TIMER:
		rb_erase_cached(&thread->n, &m->timer);
		break;
	case THREAD_READY_READ_FD:
	case THREAD_READ_TIMEOUT:
	case THREAD_READ_ERROR:
		if (thread->event)
			thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		if (m->current_thread == thread)
			return;
		list_del_init(&thread->e_list);
		break;
	case THREAD_READY_WRITE_FD:
	case THREAD_WRITE_TIMEOUT:
	case THREAD_WRITE_ERROR:
		if (thread->event)
			thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
		if (m->current_thread == thread)
			return;
		list_del_init(&thread->e_list);
		break;
	case THREAD_READY_TIMER:
		if (m->current_thread == thread)
			return;
		list_del_init(&thread->e_list);
		break;
	case THREAD_UNUSED:
		return;
	default:
		log_message(LOG_WARNING, "ERROR - thread_cancel called for"
			    "unknown thread type %u", thread->type);
		return;
	}

	thread_add_unuse(m, thread);
}


void
thread_cancel_read(thread_master_t *m, int fd)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe_cached(thread, thread_tmp, &m->read, n) {
		if (thread->u.f.fd == fd) {
			if (thread->event->write) {
				thread_cancel(thread->event->write);
				thread->event->write = NULL;
			}
			thread_cancel(thread);
			break;
		}
	}
}

/* Fetch next ready thread. */
static list_head_t *
thread_fetch_next_queue(thread_master_t *m)
{
	int last_epoll_errno = 0, ret, i;
	timeval_t earliest_timer;

	assert(m != NULL);

	/* If there is event process it first. */
	if (!list_empty(&m->event))
		return &m->event;

	/* If there are ready threads process them */
	if (!list_empty(&m->ready))
		return &m->ready;

	do {
		/* Calculate and set wait timer. Take care of timeouted fd.  */
		earliest_timer = thread_set_timer(m);


		/* Call epoll function. */
		ret = epoll_wait(m->epoll_fd, m->epoll_events, m->epoll_count, -1);

		if (ret < 0) {
			/* epoll_wait() will return EINTR if the process is sent SIGSTOP
			 * (see signal(7) man page for details.
			 * Although we don't except to receive SIGSTOP, it can happen if,
			 * for example, the system is hibernated. */
			if (errno == EINTR)
				continue;

			/* Real error. */
			if (errno != last_epoll_errno) {
				last_epoll_errno = errno;

				/* Log the error first time only */
				log_message(LOG_INFO, "scheduler: epoll_wait error: %d (%m)", errno);

			}

			/* Make sure we don't sit it a tight loop */
			if (last_epoll_errno == EBADF || last_epoll_errno == EFAULT || last_epoll_errno == EINVAL)
				sleep(1);

			continue;
		} else
			last_epoll_errno = 0;

		/* Check to see if we are long overdue. This can happen on a very heavily loaded system */
		if (min_auto_priority_delay && timerisset(&earliest_timer)) {
			/* Re-read the current time to get the maximum accuracy */
			set_time_now();

			/* Take care about monotonic clock */
			timersub(&earliest_timer, &time_now, &earliest_timer);

			/* If it is over min_auto_increment_delay usecs after the timer should have expired,
			 * we are not running soon enough. */
			if (earliest_timer.tv_sec < 0) {
				if (earliest_timer.tv_sec * -1000000 - earliest_timer.tv_usec > min_auto_priority_delay) {
					if (earliest_timer.tv_usec) {
						earliest_timer.tv_sec++;
						earliest_timer.tv_usec = 1000000 - earliest_timer.tv_usec;
					}
					log_message(LOG_INFO, "A thread timer expired %ld.%6.6ld seconds ago", -earliest_timer.tv_sec, earliest_timer.tv_usec);

					/* Set realtime scheduling if not already using it, or if already in use,
					 * increase the priority. */
					increment_process_priority();
				}
			}
		}

		/* Handle epoll events */
		for (i = 0; i < ret; i++) {
			struct epoll_event *ep_ev;
			thread_event_t *ev;

			ep_ev = &m->epoll_events[i];
			ev = ep_ev->data.ptr;

			/* Error */
			if (ep_ev->events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
				if (ev->read) {
					thread_move_ready(m, &m->read, ev->read, THREAD_READ_ERROR);
					ev->read = NULL;
				} else if (ev->write) {
					thread_move_ready(m, &m->write, ev->write, THREAD_WRITE_ERROR);
					ev->write = NULL;
				}

				if (__test_bit(LOG_DETAIL_BIT, &debug) &&
				    ep_ev->events & EPOLLRDHUP)
					log_message(LOG_INFO, "Received EPOLLRDHUP for fd %d", ev->fd);

				continue;
			}

			/* READ */
			if (ep_ev->events & EPOLLIN) {
				if (!ev->read) {
					log_message(LOG_INFO, "scheduler: No read thread bound on fd:%d (fl:0x%.4X)"
						      , ev->fd, ep_ev->events);
					continue;
				}
				thread_move_ready(m, &m->read, ev->read, THREAD_READY_READ_FD);
				ev->read = NULL;
			}

			/* WRITE */
			if (ep_ev->events & EPOLLOUT) {
				if (!ev->write) {
					log_message(LOG_INFO, "scheduler: No write thread bound on fd:%d (fl:0x%.4X)"
						      , ev->fd, ep_ev->events);
					continue;
				}
				thread_move_ready(m, &m->write, ev->write, THREAD_READY_WRITE_FD);
				ev->write = NULL;
			}
		}

		/* Update current time */
		set_time_now();

		/* If there is a ready thread, return it. */
		if (!list_empty(&m->ready))
			return &m->ready;
	} while (true);
}

/* Our infinite scheduling loop */
void
launch_thread_scheduler(thread_master_t *m)
{
	thread_t* thread;
	list_head_t *thread_list;
	int thread_type;

	/*
	 * Processing the master thread queues,
	 * return and execute one ready thread.
	 */
	while ((thread_list = thread_fetch_next_queue(m))) {
		/* Run until error, used for debuging only */

		/* If we are shutting down, only process relevant thread types.
		 * We only want timer and signal fd, and don't want inotify, vrrp socket,
		 * snmp_read, bfd_receiver, bfd pipe in vrrp/check, dbus pipe or netlink fds. */
		if (!(thread = thread_trim_head(thread_list)))
			continue;

		m->current_thread = thread;
		m->current_event = thread->event;
		thread_type = thread->type;

		if (!shutting_down ||
		    ((thread->type == THREAD_READY_READ_FD ||
		      thread->type == THREAD_READY_WRITE_FD ||
		      thread->type == THREAD_READ_ERROR ||
		      thread->type == THREAD_WRITE_ERROR) &&
		     (thread->u.f.fd == m->timer_fd ||
		      thread->u.f.fd == m->signal_fd)) ||
		    thread->type == THREAD_TIMER_SHUTDOWN ||
		    thread->type == THREAD_TERMINATE) {
			if (thread->func)
				(*thread->func) (thread);

			/* If m->current_thread has been cleared, the thread
			 * has been freed. This happens during a reload. */
			thread = m->current_thread;

			if (thread_type == THREAD_TERMINATE_START)
				shutting_down = true;
		} else if (thread->type == THREAD_READY_READ_FD ||
			   thread->type == THREAD_READY_WRITE_FD ||
			   thread->type == THREAD_READ_TIMEOUT ||
			   thread->type == THREAD_WRITE_TIMEOUT ||
			   thread->type == THREAD_READ_ERROR ||
			   thread->type == THREAD_WRITE_ERROR) {
			thread_close_fd(thread);

			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		if (thread) {
#if 0
			m->current_event = (thread_type == THREAD_READY_READ_FD || thread_type == THREAD_READY_WRITE_FD) ? thread->event : NULL;
#endif
			thread_add_unuse(m, thread);
			m->current_thread = NULL;
		} else
			m->current_event = NULL;

		/* If we are shutting down, and the shutdown timer is not running 
		 * then we can terminate */
		if (shutting_down && !m->shutdown_timer_running)
			break;

		/* If daemon hanging event is received stop processing */
		if (thread_type == THREAD_TERMINATE)
			break;
	}
}
