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

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/time.h>

#include "rbtree.h"

typedef struct timeval timeval_t;

/* Global vars */
extern timeval_t time_now;

/* Some defines */
#define TIMER_HZ		1000000
#define	TIMER_HZ_DIGITS		6
#define TIMER_HZ_FLOAT		1000000.0F
#define TIMER_HZ_DOUBLE		((double)1000000.0F)
#define TIMER_CENTI_HZ		10000
#define TIMER_MAX_SEC		1000U
#define TIMER_NEVER		ULONG_MAX	/* Used with time intervals in TIMER_HZ units */
#define TIMER_DISABLED		LONG_MIN	/* Value in timeval_t tv_sec */

#define	NSEC_PER_SEC		1000000000	/* nanoseconds per second. Avoids typos by having a definition */

#ifdef _TIMER_CHECK_
#define timer_now()	timer_now_r((__FILE__), (__func__), (__LINE__))
#define set_time_now()	set_time_now_r((__FILE__), (__func__), (__LINE__))
#endif

#define RB_TIMER_CMP(obj, nnn)						\
static inline int							\
obj##_timer_cmp(const timeval_t *sands, const struct rb_node *a)	\
{									\
	const struct obj *r1 = rb_entry_const(a, struct obj, nnn);	\
									\
	if (sands->tv_sec == TIMER_DISABLED) {				\
		if (r1->sands.tv_sec == TIMER_DISABLED)			\
			return 0;					\
		return 1;						\
	}								\
									\
	if (r1->sands.tv_sec == TIMER_DISABLED)				\
		return -1;						\
									\
	if (sands->tv_sec != r1->sands.tv_sec)				\
		return sands->tv_sec - r1->sands.tv_sec;		\
									\
	return sands->tv_usec - r1->sands.tv_usec;			\
}

#define RB_TIMER_LESS(obj, nnn)						\
static inline bool							\
obj##_timer_less(struct rb_node *a, const struct rb_node *b)		\
{									\
	const struct obj *r1 = rb_entry_const(a, struct obj, nnn);	\
	const struct obj *r2 = rb_entry_const(b, struct obj, nnn);	\
									\
	if (r1->sands.tv_sec == TIMER_DISABLED)				\
		return false;						\
									\
	if (r2->sands.tv_sec == TIMER_DISABLED)				\
		return true;						\
									\
	if (r1->sands.tv_sec != r2->sands.tv_sec)			\
		return r1->sands.tv_sec < r2->sands.tv_sec;		\
									\
	return r1->sands.tv_usec < r2->sands.tv_usec;			\
}

/* timer sub from current time */
static inline timeval_t
timer_sub_now(timeval_t a)
{
	timersub(&a, &time_now, &a);

	return a;
}

/* timer add to current time */
static inline timeval_t
timer_add_now(timeval_t a)
{
	timeradd(&time_now, &a, &a);

	return a;
}

/* timer add secs to current time */
static inline timeval_t
timer_add_now_sec(timeval_t a, time_t sec)
{
	a.tv_sec = time_now.tv_sec + sec;
	a.tv_usec = time_now.tv_usec;

	return a;
}

/* Returns true if time a + diff_hz < time_now */
static inline bool
timer_cmp_now_diff(timeval_t a, unsigned long diff_hz)
{
	timeval_t b = { .tv_sec = diff_hz / TIMER_HZ, .tv_usec = diff_hz % TIMER_HZ };

	timeradd(&b, &a, &b);

	return !!timercmp(&b, &time_now, <);
}

/* Return time as unsigned long */
static inline unsigned long
timer_long(timeval_t a)
{
	return (unsigned long)a.tv_sec * TIMER_HZ + (unsigned long)a.tv_usec;
}

/* prototypes */
int monotonic_gettimeofday(timeval_t *now);
void timespec_add_now_ms(struct timespec *t, timeval_t *now, unsigned long ms);
timeval_t timer_now(void);
timeval_t set_time_now(void);
struct tm *time_now_to_calendar(struct tm *t);
uint32_t time_now_to_ntp(void);
timeval_t timer_add_ll(timeval_t a, uint64_t b) __attribute__((const));
timeval_t timer_sub_ll(timeval_t a, uint64_t b) __attribute__((const));
