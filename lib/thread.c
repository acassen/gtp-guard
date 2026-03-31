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

#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <assert.h>

#include "thread.h"
#include "memory.h"
#include "rbtree_api.h"
#include "utils.h"
#include "signals.h"
#include "logger.h"
#include "bitops.h"
#include "timer.h"
#include "process.h"


/* Move ready thread into ready queue */
static void
thread_move_ready(struct thread_master *m, struct rb_root_cached *root,
		  struct thread *t, int type)
{
	rb_erase_cached(&t->n, root);
	INIT_LIST_HEAD(&t->e_list);
	list_add_tail(&t->e_list, &m->ready);
	if (t->type != THREAD_TIMER_SHUTDOWN)
		t->type = type;
}

/* Move ready thread into ready queue */
static void
thread_rb_move_ready(struct thread_master *m, struct rb_root_cached *root, int type)
{
	struct thread *t;
	struct rb_node *t_node;

	while ((t_node = rb_first_cached(root))) {
		t = rb_entry(t_node, struct thread, n);

		if (t->sands.tv_sec == TIMER_DISABLED || timercmp(&time_now, &t->sands, <))
			break;

		if (type == THREAD_READ_TIMEOUT)
			t->event->read = NULL;
		else if (type == THREAD_WRITE_TIMEOUT)
			t->event->write = NULL;

		thread_move_ready(m, root, t, type);
	}
}

/* Update timer value */
static void
thread_update_timer(struct rb_root_cached *root, timeval_t *timer_min)
{
	const struct thread *first;
	struct rb_node *first_node;

	if (!(first_node = rb_first_cached(root)))
		return;

	first = rb_entry(first_node, struct thread, n);

	if (first->sands.tv_sec == TIMER_DISABLED)
		return;

	if (!timerisset(timer_min) ||
	    timercmp(&first->sands, timer_min, <=))
		*timer_min = first->sands;
}

/* Compute the wait timer. Take care of timeouted fd */
static timeval_t
thread_set_timer(struct thread_master *m)
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
thread_timerfd_handler(struct thread *t)
{
	struct thread_master *m = t->master;
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
thread_events_resize(struct thread_master *m, int delta)
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
thread_event_cmp(const void *key, const struct rb_node *a)
{
	int fd = *((int *) key);

	return fd - rb_entry_const(a, struct thread_event, n)->fd;
}

static inline bool
thread_event_less(struct rb_node *a, const struct rb_node *b)
{
	return rb_entry(a, struct thread_event, n)->fd < rb_entry_const(b, struct thread_event, n)->fd;
}

static struct thread_event *
thread_event_new(struct thread_master *m, int fd)
{
	struct thread_event *event;

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

static struct thread_event * __attribute__ ((pure))
thread_event_get(struct thread_master *m, int fd)
{
	struct rb_node *node;

	node = rb_find(&fd, &m->io_events, thread_event_cmp);

	if (!node)
		return NULL;
	return rb_entry(node, struct thread_event, n);
}

static void
thread_event_clean(struct thread_master *m)
{
	struct thread_event *tev, *tev_tmp;

	rbtree_postorder_for_each_entry_safe(tev, tev_tmp, &m->io_events, n) {
		free(tev);
	}
}

static int
thread_event_set(const struct thread *t)
{
	struct thread_event *event = t->event;
	struct thread_master *m = t->master;
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
thread_event_cancel(const struct thread *t)
{
	struct thread_event *event = t->event;
	struct thread_master *m = t->master;

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
thread_event_del(const struct thread *t, unsigned flag)
{
	struct thread_event *event = t->event;

	if (!__test_bit(flag, &event->flags))
		return 0;

	if (flag == THREAD_FL_EPOLL_READ_BIT) {
		__clear_bit(THREAD_FL_READ_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags))
			return thread_event_cancel(t);

		event->read = NULL;
	}
	else if (flag == THREAD_FL_EPOLL_WRITE_BIT) {
		__clear_bit(THREAD_FL_WRITE_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags))
			return thread_event_cancel(t);

		event->write = NULL;
	}

	if (thread_event_set(t) < 0)
		return -1;

	__clear_bit(flag, &event->flags);
	return 0;
}

/* Make thread master. */
struct thread_master *
thread_make_master(bool nosignal)
{
	struct thread_master *new;

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
	new->signal_fd = -1;

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
thread_clean_unuse(struct thread_master *m)
{
	struct thread *t, *_t;
	struct list_head *l = &m->unuse;

	list_for_each_entry_safe(t, _t, l, e_list) {
		list_del_init(&t->e_list);

		/* free the thread */
		FREE(t);
		m->alloc--;
	}

	INIT_LIST_HEAD(l);
}

/* Move thread to unuse list. */
static void
thread_add_unuse(struct thread_master *m, struct thread *t)
{
	assert(m != NULL);

	t->type = THREAD_UNUSED;
	t->event = NULL;
	list_add_tail(&t->e_list, &m->unuse);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(struct thread_master *m, struct list_head *l)
{
	struct thread *t, *_t;

	list_for_each_entry_safe(t, _t, l, e_list) {
		/* The following thread types are relevant for the ready list */
		if (t->type == THREAD_READY_READ_FD ||
		    t->type == THREAD_READY_WRITE_FD ||
		    t->type == THREAD_READ_TIMEOUT ||
		    t->type == THREAD_WRITE_TIMEOUT ||
		    t->type == THREAD_READ_ERROR ||
		    t->type == THREAD_WRITE_ERROR) {
			/* Do we have a file descriptor that needs closing ? */
			if (t->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(t);

			/* Do we need to free arg? */
			if (t->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(t->arg);
		}

		list_del_init(&t->e_list);
		thread_add_unuse(m, t);
	}
}

static void
thread_destroy_rb(struct thread_master *m, struct rb_root_cached *root)
{
	struct thread *t, *_t;

	rbtree_postorder_for_each_entry_safe(t, _t, &root->rb_root, n) {
		/* The following are relevant for the read and write rb lists */
		if (t->type == THREAD_READ ||
		    t->type == THREAD_WRITE) {
			/* Do we have a file descriptor that needs closing ? */
			if (t->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(t);

			/* Do we need to free arg? */
			if (t->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(t->arg);
		}

		thread_add_unuse(m, t);
	}

	*root = RB_ROOT_CACHED;
}

/* Stop thread scheduler. */
void
thread_destroy_master(struct thread_master *m)
{
	if (m->epoll_fd != -1) {
		close(m->epoll_fd);
		m->epoll_fd = -1;
	}

	if (m->timer_fd != -1)
		close(m->timer_fd);

	if (m->signal_fd != -1)
		signal_handler_destroy();

	/* Unuse current thread lists */
	thread_destroy_rb(m, &m->read);
	thread_destroy_rb(m, &m->write);
	thread_destroy_rb(m, &m->timer);
	thread_destroy_list(m, &m->event);
	thread_destroy_list(m, &m->ready);

	/* Clean garbage */
	thread_event_clean(m);
	thread_clean_unuse(m);

	FREE(m->epoll_events);
	FREE(m);
}

/* Delete top of the list and return it. */
static struct thread *
thread_trim_head(struct list_head *l)
{
	struct thread *t;

	if (list_empty(l))
		return NULL;

	t = list_first_entry(l, struct thread, e_list);
	list_del_init(&t->e_list);
	return t;
}

/* Make unique thread id for non pthread version of thread manager. */
static inline unsigned long
thread_get_id(struct thread_master *m)
{
	return m->id++;
}

/* Make new thread. */
static struct thread *
thread_new(struct thread_master *m)
{
	struct thread *new;

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
struct thread *
thread_add_read_sands(struct thread_master *m, void (*func)(struct thread *),
		      void *arg, int fd, const timeval_t *sands, unsigned flags)
{
	struct thread_event *event;
	struct thread *t;

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

	t = thread_new(m);
	t->type = THREAD_READ;
	t->master = m;
	t->func = func;
	t->arg = arg;
	t->u.f.fd = fd;
	t->u.f.flags = flags;
	t->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_READ_BIT, &event->flags);
	event->read = t;
	if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
		if (thread_event_set(t) < 0) {
			log_message(LOG_INFO, "scheduler: Cant register read event for fd [%d](%m)", fd);
			thread_add_unuse(m, t);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
	}

	t->sands = *sands;

	/* Sort the thread. */
	rb_add_cached(&t->n, &m->read, thread_timer_less);

	return t;
}

struct thread *
thread_add_read(struct thread_master *m, void (*func)(struct thread *),
		void *arg, int fd, unsigned long timer, unsigned flags)
{
	timeval_t sands;

	/* Compute read timeout value */
	if (timer == TIMER_NEVER) {
		sands.tv_sec = TIMER_DISABLED;
		sands.tv_usec = 0;
	} else {
		set_time_now();
		sands = timer_add_ll(time_now, timer);
	}

	return thread_add_read_sands(m, func, arg, fd, &sands, flags);
}

/* Adjust the timeout of a read thread */
void
thread_requeue_read(struct thread_master *m, int fd, const timeval_t *sands)
{
	struct thread *t;
	struct thread_event *event;

	event = thread_event_get(m, fd);
	if (!event || !event->read)
		return;

	t = event->read;

	if (t->type != THREAD_READ) {
		/* If the thread is not on the read list, don't touch it */
		return;
	}

	t->sands = *sands;

	rb_move_cached(&t->n, &t->master->read, thread_timer_less);
}

/* Add new write thread. */
struct thread *
thread_add_write(struct thread_master *m, void (*func)(struct thread *),
		 void *arg, int fd, unsigned long timer, unsigned flags)
{
	struct thread_event *event;
	struct thread *t;

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

	t = thread_new(m);
	t->type = THREAD_WRITE;
	t->master = m;
	t->func = func;
	t->arg = arg;
	t->u.f.fd = fd;
	t->u.f.flags = flags;
	t->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_WRITE_BIT, &event->flags);
	event->write = t;
	if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags)) {
		if (thread_event_set(t) < 0) {
			log_message(LOG_INFO, "scheduler: Cant register write event for fd [%d](%m)" , fd);
			thread_add_unuse(m, t);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags);
	}

	/* Compute write timeout value */
	if (timer == TIMER_NEVER)
		t->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		t->sands = timer_add_ll(time_now, timer);
	}

	/* Sort the thread. */
	rb_add_cached(&t->n, &m->write, thread_timer_less);

	return t;
}

void
thread_close_fd(struct thread *t)
{
	if (t->u.f.fd == -1)
		return;

	if (t->event)
		thread_event_cancel(t);

	close(t->u.f.fd);
	t->u.f.fd = -1;
}

/* Add timer event thread. */
struct thread *
thread_add_timer_uval(struct thread_master *m, void (*func)(struct thread *),
		      void *arg, unsigned val, uint64_t timer)
{
	struct thread *t;

	assert(m != NULL);

	t = thread_new(m);
	t->type = THREAD_TIMER;
	t->master = m;
	t->func = func;
	t->arg = arg;
	t->u.uval = val;

	/* Do we need jitter here? */
	if (timer == TIMER_NEVER)
		t->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		t->sands = timer_add_ll(time_now, timer);
	}

	/* Sort by timeval. */
	rb_add_cached(&t->n, &m->timer, thread_timer_less);

	return t;
}

struct thread *
thread_add_timer(struct thread_master *m, void (*func)(struct thread *),
		 void *arg, uint64_t timer)
{
	return thread_add_timer_uval(m, func, arg, 0, timer);
}

void
thread_mod_timer(struct thread *t, uint64_t timer)
{
	timeval_t sands;

	set_time_now();
	sands = timer_add_ll(time_now, timer);

	if (timercmp(&t->sands, &sands, ==))
		return;

	t->sands = sands;

	rb_move_cached(&t->n, &t->master->timer, thread_timer_less);
}

/* Add simple event thread. */
struct thread *
thread_add_event(struct thread_master *m, void (*func)(struct thread *),
		 void *arg, int val)
{
	struct thread *t;

	assert(m != NULL);

	t = thread_new(m);
	t->type = THREAD_EVENT;
	t->master = m;
	t->func = func;
	t->arg = arg;
	t->u.val = val;
	INIT_LIST_HEAD(&t->e_list);
	list_add_tail(&t->e_list, &m->event);

	return t;
}

/* Add terminate event thread. */
struct thread *
thread_add_terminate_event(struct thread_master *m)
{
	struct thread *t;

	assert(m != NULL);

	t = thread_new(m);
	t->type = THREAD_TERMINATE;
	t->master = m;
	t->func = NULL;
	t->arg = NULL;
	t->u.val = 0;
	INIT_LIST_HEAD(&t->e_list);
	list_add_tail(&t->e_list, &m->event);

	return t;
}


/* Remove thread from scheduler. */
void
thread_del(struct thread *t)
{
	struct thread_master *m;

	if (!t)
		return;

	m = t->master;

	switch (t->type) {
	case THREAD_READ:
		thread_event_del(t, THREAD_FL_EPOLL_READ_BIT);
		rb_erase_cached(&t->n, &m->read);
		break;
	case THREAD_WRITE:
		thread_event_del(t, THREAD_FL_EPOLL_WRITE_BIT);
		rb_erase_cached(&t->n, &m->write);
		break;
	case THREAD_TIMER:
		rb_erase_cached(&t->n, &m->timer);
		break;
	case THREAD_READY_READ_FD:
	case THREAD_READ_TIMEOUT:
	case THREAD_READ_ERROR:
		if (t->event)
			thread_event_del(t, THREAD_FL_EPOLL_READ_BIT);
		if (m->current_thread == t)
			return;
		list_del_init(&t->e_list);
		break;
	case THREAD_READY_WRITE_FD:
	case THREAD_WRITE_TIMEOUT:
	case THREAD_WRITE_ERROR:
		if (t->event)
			thread_event_del(t, THREAD_FL_EPOLL_WRITE_BIT);
		if (m->current_thread == t)
			return;
		list_del_init(&t->e_list);
		break;
	case THREAD_READY_TIMER:
		if (m->current_thread == t)
			return;
		list_del_init(&t->e_list);
		break;
	case THREAD_UNUSED:
		return;
	default:
		log_message(LOG_WARNING, "ERROR - thread_cancel called for"
			    "unknown thread type %u", t->type);
		return;
	}

	thread_add_unuse(m, t);
}


/* Fetch next ready thread. */
static struct list_head *
thread_fetch_next_queue(struct thread_master *m)
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
			struct thread_event *ev;

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
launch_thread_scheduler(struct thread_master *m)
{
	struct thread *t;
	struct list_head *thread_list;
	int thread_type;

	/*
	 * Processing the master thread queues,
	 * return and execute all ready threads.
	 */
	while ((thread_list = thread_fetch_next_queue(m))) {
		if (!(t = thread_trim_head(thread_list)))
			continue;

		m->current_thread = t;
		m->current_event = t->event;
		thread_type = t->type;

		if (t->func)
			(*t->func) (t);

		thread_add_unuse(m, t);
		m->current_thread = NULL;

		/* If daemon hanging event is received stop processing */
		if (thread_type == THREAD_TERMINATE)
			break;
	}
}
