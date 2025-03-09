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

#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#include "utils.h"
#include "bitops.h"
#include "container.h"
#include "rbtree_api.h"
#include "timer.h"
#include "timer_thread.h"
#ifdef _TIMER_CHECK_
#include "logger.h"
#endif

/* time_now holds current time */
timeval_t time_now;
#ifdef _TIMER_CHECK_
static timeval_t last_time;
bool do_timer_check;
#endif


/*
 *	Timer related
 */
timeval_t
timer_add_long(timeval_t a, unsigned long b)
{
	if (b == TIMER_NEVER)
	{
		a.tv_usec = TIMER_HZ - 1;
		a.tv_sec = TIMER_DISABLED;

		return a;
	}

	a.tv_usec += b % TIMER_HZ;
	a.tv_sec += b / TIMER_HZ;

	if (a.tv_usec >= TIMER_HZ) {
		a.tv_sec++;
		a.tv_usec -= TIMER_HZ;
	}

	return a;
}

timeval_t
timer_sub_long(timeval_t a, unsigned long b)
{
	if (a.tv_usec < (suseconds_t)(b % TIMER_HZ)) {
		a.tv_usec += TIMER_HZ;
		a.tv_sec--;
	}
	a.tv_usec -= b % TIMER_HZ;
	a.tv_sec -= b / TIMER_HZ;

	return a;
}

static void
set_mono_offset(struct timespec *ts)
{
	struct timespec realtime, realtime_1, mono_offset;

	/* Calculate the offset of the realtime clock from the monotonic
	 * clock. We read the realtime clock twice and take the mean,
	 * which should then make it very close to the time the monotonic
	 * clock was read. */
	clock_gettime(CLOCK_REALTIME, &realtime);
	clock_gettime(CLOCK_MONOTONIC, &mono_offset);
	clock_gettime(CLOCK_REALTIME, &realtime_1);

	/* Calculate the mean realtime. If tv_sec is 4 bytes, then
	 * adding two times after Sat 10 Jan 13:37:04 GMT 2004 results
	 * in overflow. If tv_sec is only 6 bytes (unlikely) then
	 * overflow doesn't occur until the two dates average
	 * Tue 25 Sep 15:41:04 BST 2231866, */
	realtime.tv_nsec = (realtime.tv_nsec + realtime_1.tv_nsec) / 2;
#ifndef TIME_T_ADD_OVERFLOWS
	realtime.tv_sec = (realtime.tv_sec + realtime_1.tv_sec) / 2;
#else
	realtime.tv_sec = realtime.tv_sec / 2 + realtime_1.tv_sec / 2;
	if ((realtime.tv_sec & 1) && (realtime_1.tv_sec & 1))
		realtime.tv_sec++;
#endif

	/* If the sum would be odd, we need to add * 1/2 second. */
	if ((realtime.tv_sec ^ realtime_1.tv_sec) & 1)
		realtime.tv_nsec += NSEC_PER_SEC / 2;

	if (realtime.tv_nsec < mono_offset.tv_nsec) {
		realtime.tv_nsec += NSEC_PER_SEC;
		realtime.tv_sec--;
	}
	realtime.tv_sec -= mono_offset.tv_sec;
	realtime.tv_nsec -= mono_offset.tv_nsec;

	*ts = realtime;
}

/* This function is a wrapper for gettimeofday(). It uses the monotonic clock to
 * guarantee that the returned time will always be monotonicly increasing.
 * When called for the first time it calculates the difference between the
 * monotonic clock and the realtime clock, and this difference is then subsequently
 * added to the monotonic clock to return a monotonic approximation to realtime.
 *
 * It is designed to be used as a drop-in replacement of gettimeofday(&now, NULL).
 * It will normally return 0, unless <now> is NULL, in which case it will
 * return -1 and set errno to EFAULT.
 */
static int
monotonic_gettimeofday(timeval_t *now)
{
	static struct timespec mono_offset;
	static bool initialised = false;
	struct timespec cur_time;

	if (!now) {
		errno = EFAULT;
		return -1;
	}

	if (!initialised) {
		set_mono_offset(&mono_offset);
		initialised = true;
	}

	/* Read the monotonic clock and add the offset we initially
	 * calculated of the realtime clock */
	clock_gettime(CLOCK_MONOTONIC, &cur_time);
	cur_time.tv_sec += mono_offset.tv_sec;
	cur_time.tv_nsec += mono_offset.tv_nsec;
	if (cur_time.tv_nsec > NSEC_PER_SEC) {
		cur_time.tv_nsec -= NSEC_PER_SEC;
		cur_time.tv_sec++;
	}

	TIMESPEC_TO_TIMEVAL(now, &cur_time);

	return 0;
}

/* current time */
timeval_t
#ifdef _TIMER_CHECK_
timer_now_r(const char *file, const char *function, int line_no)
#else
timer_now(void)
#endif
{
	timeval_t curr_time;

	/* init timer */
	monotonic_gettimeofday(&curr_time);

#ifdef _TIMER_CHECK_
	if (do_timer_check) {
		unsigned long timediff = (curr_time.tv_sec - last_time.tv_sec) * 1000000 + curr_time.tv_usec - last_time.tv_usec;
		log_message(LOG_INFO, "timer_now called from %s %s:%d - difference %lu usec", file, function, line_no, timediff);
		last_time = curr_time;
	}
#endif

	return curr_time;
}

/* sets and returns current time from system time */
timeval_t
#ifdef _TIMER_CHECK_
set_time_now_r(const char *file, const char *function, int line_no)
#else
set_time_now(void)
#endif
{
	/* init timer */
	monotonic_gettimeofday(&time_now);

#ifdef _TIMER_CHECK_
	if (do_timer_check) {
		unsigned long timediff = (time_now.tv_sec - last_time.tv_sec) * 1000000 + time_now.tv_usec - last_time.tv_usec;
		log_message(LOG_INFO, "set_time_now called from %s %s:%d, time %ld.%6.6ld difference %lu usec", file, function, line_no, time_now.tv_sec, time_now.tv_usec, timediff);
		last_time = time_now;
	}
#endif

	return time_now;
}

struct tm *
time_now_to_calendar(struct tm *t)
{
	return localtime_r(&time_now.tv_sec, t);
}


/*
 *	Timer thread related
 */
RB_TIMER_LESS(timer_node, n);

void
timer_node_clear(timer_node_t *n)
{
	n->sands.tv_sec = 0;
	n->sands.tv_usec = 0;
}

void
timer_node_expire_now(timer_thread_t *t, timer_node_t *t_node)
{
	pthread_mutex_lock(&t->timer_mutex);
	rb_erase_cached(&t_node->n, &t->timer);
	gettimeofday(&t_node->sands, NULL);
	rb_add_cached(&t_node->n, &t->timer, timer_node_timer_less);
	pthread_mutex_unlock(&t->timer_mutex);

	timer_thread_signal(t);
}

void
timer_node_init(timer_node_t *t_node, int (*fn) (void *), void *arg)
{
	t_node->to_func = fn;
	t_node->to_arg = arg;
	timer_node_clear(t_node);
}

int
timer_node_pending(timer_node_t *t_node)
{
	return timerisset(&t_node->sands);
}

static void
__timer_node_del(timer_thread_t *t, timer_node_t *t_node)
{
	rb_erase_cached(&t_node->n, &t->timer);
	timer_node_clear(t_node);
}

int
timer_node_del(timer_thread_t *t, timer_node_t *t_node)
{
	if (!timer_node_pending(t_node))
		return -1;

	pthread_mutex_lock(&t->timer_mutex);
	__timer_node_del(t, t_node);
	pthread_mutex_unlock(&t->timer_mutex);
	return 0;
}

void
timer_node_add(timer_thread_t *t, timer_node_t *t_node, int sec)
{
	pthread_mutex_lock(&t->timer_mutex);
	if (timer_node_pending(t_node))
		__timer_node_del(t, t_node);
	t_node->sands = timer_add_now_sec(t_node->sands, sec);
	rb_add_cached(&t_node->n, &t->timer, timer_node_timer_less);
	pthread_mutex_unlock(&t->timer_mutex);
}

static void
timer_thread_fired(timer_thread_t *t, timeval_t *now)
{
	timer_node_t *node, *_node;

	pthread_mutex_lock(&t->timer_mutex);
	rb_for_each_entry_safe_cached(node, _node, &t->timer, n) {
		if (timercmp(now, &node->sands, <))
			break;

		rb_erase_cached(&node->n, &t->timer);
		timer_node_clear(node);

		pthread_mutex_unlock(&t->timer_mutex);
		/* Cascade handlers */
		if (node->to_func)
			(*node->to_func) (node->to_arg);
		if (t->fired)
			(*t->fired) (node->to_arg);
		pthread_mutex_lock(&t->timer_mutex);
	}
	pthread_mutex_unlock(&t->timer_mutex);
}

static void
timespec_add_now_ms(struct timespec *t, timeval_t *now, unsigned long ms)
{
	t->tv_sec = now->tv_sec;
	t->tv_nsec = now->tv_usec * 1000 + ms;
	if (t->tv_nsec >= NSEC_PER_SEC) {
		t->tv_sec++;
		t->tv_nsec -= NSEC_PER_SEC;
	}
}

static void *
timer_thread_task(void *arg)
{
	timer_thread_t *t = arg;
	struct timespec timeout;
	timeval_t now;

	/* Our identity */
	prctl(PR_SET_NAME, t->name, 0, 0, 0, 0);

  timer_process:
	/* Schedule interruptible timeout */
	pthread_mutex_lock(&t->cond_mutex);
	monotonic_gettimeofday(&now);
	timespec_add_now_ms(&timeout, &now, 500 * TIMER_HZ); /* 500ms granularity */
	pthread_cond_timedwait(&t->cond, &t->cond_mutex, &timeout);
	pthread_mutex_unlock(&t->cond_mutex);

	if (__test_bit(TIMER_THREAD_FL_STOP_BIT, &t->flags))
		goto timer_finish;

	/* Expiration handling */
	timer_thread_fired(t, &now);

	goto timer_process;

  timer_finish:
	return NULL;
}

int
timer_thread_init(timer_thread_t *t, const char *name, int (*fired) (void *))
{
	t->timer = RB_ROOT_CACHED;
	t->fired = fired;
	bsd_strlcpy(t->name, name, TIMER_THREAD_NAMESIZ);
	pthread_mutex_init(&t->timer_mutex, NULL);
	pthread_mutex_init(&t->cond_mutex, NULL);
	pthread_cond_init(&t->cond, NULL);

	pthread_create(&t->task, NULL, timer_thread_task, t);
	return 0;
}

int
timer_thread_signal(timer_thread_t *t)
{
	pthread_mutex_lock(&t->cond_mutex);
	pthread_cond_signal(&t->cond);
	pthread_mutex_unlock(&t->cond_mutex);
	return 0;
}

int
timer_thread_destroy(timer_thread_t *t)
{
	__set_bit(TIMER_THREAD_FL_STOP_BIT, &t->flags);
	timer_thread_signal(t);
	pthread_join(t->task, NULL);
	pthread_mutex_destroy(&t->timer_mutex);
	pthread_mutex_destroy(&t->cond_mutex);
	pthread_cond_destroy(&t->cond);
	return 0;
}
