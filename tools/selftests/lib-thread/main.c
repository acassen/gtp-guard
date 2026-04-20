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
 * Authors:     Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>

#include "gtp_data.h"
#include "thread.h"
#include "signals.h"
#include "mempool.h"

/* Local data */
struct data *daemon_data;
struct thread_master *master = NULL;

/*
 *      Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -h, --help                   Display this help message\n");
}


/*
 *	Command line parser
 */
static int
parse_cmdline(int argc, char **argv)
{
	int c, longindex;

	struct option long_options[] = {
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	while (longindex = -1, (c = getopt_long(argc, argv, ":ha:p:s:S:"
						, long_options, &longindex)) != -1) {
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument &&
		    optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
			exit(1);
			break;
		}
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		return -1;
	}

	return 0;
}

static int
list_size(struct list_head *l)
{
	struct list_head *pos;
	int c = 0;

	list_for_each(pos, l) {
		c++;
	}
	return c;
}

static void
test_mpool(void)
{
	struct mpool mp = MPOOL_INIT(mp);
	uint8_t *d, *a[100];
	int i;

	d = mpool_malloc(&mp, 60);
	d[0] = 'a';
	d[59] = 'b';
	mpool_free(d);

	for (int i = 0; i < 100; i++) {
		a[i] = mpool_malloc(&mp, 10 + i * 2);
	}
	mpool_free(a[50]);
	mpool_free(a[0]);
	mpool_release(&mp);

	struct obj {
		struct mpool mp;
		char s[130];
	} *obj;

	obj = mpool_new(sizeof (*obj), 1000);
	mpool_delete(obj);

	obj = mpool_new(sizeof (*obj), 0);
	mpool_malloc(&obj->mp, 50);
	mpool_delete(obj);

	obj = mpool_new(sizeof (*obj), 1000);
	mpool_malloc(&obj->mp, 50);
	mpool_delete(obj);

	memset(a, 0x00, sizeof (a));
	obj = mpool_new(sizeof (*obj), 1000);
	for (i = 10; i < 100; i++)
		a[i] = mpool_malloc(&obj->mp, 50);
	for (i = 0; i < 90; i++)
		a[i] = mpool_realloc(&obj->mp, a[i], 70);
	for (i = 50; i < 60; i++)
		mpool_free(a[i]);
	mpool_delete(obj);

	/* reset, without prealloc */
	memset(a, 0x00, sizeof (a));
	obj = mpool_new(sizeof (*obj), 0);
	mpool_reset(&obj->mp);
	assert(list_size(&obj->mp.head) == 1);
	for (i = 0; i < 60; i++)
		a[i] = mpool_malloc(&obj->mp, 160);
	mpool_free(a[8]);
	mpool_free(a[59]);
	mpool_reset(&obj->mp);
	assert(list_size(&obj->mp.head) == 1);
	for (i = 0; i < 20; i++)
		a[i] = mpool_malloc(&obj->mp, 160);
	mpool_free(a[0]);
	mpool_delete(obj);

	/* reset, with (a small) prealloc area */
	memset(a, 0x00, sizeof (a));
	obj = mpool_new(sizeof (*obj), 1000);
	mpool_reset(&obj->mp);
	assert(list_size(&obj->mp.head) == 1);
	for (i = 0; i < 18; i++)
		a[i] = mpool_malloc(&obj->mp, 80);
	mpool_free(a[8]);
	mpool_free(a[0]);
	mpool_reset(&obj->mp);
	assert(list_size(&obj->mp.head) == 2);
	for (i = 0; i < 20; i++)
		a[i] = mpool_malloc(&obj->mp, 160);
	mpool_free(a[0]);
	mpool_delete(obj);
}


/*
 * Scheduler selftests
 *
 * Each test creates its own thread_master, runs a short scenario, and
 * reports pass/fail. A backstop terminate-timer guards against hangs so
 * no test runs longer than a few hundred milliseconds.
 */

#define MS_TO_TIMER(ms)	((unsigned long)(ms) * (TIMER_HZ / 1000))

struct io_ctx {
	int		fd;
	int		fire_count;
	int		last_type;
};

static void
terminate_cb(struct thread *t)
{
	thread_add_terminate_event(t->master);
}

static void
io_record_cb(struct thread *t)
{
	struct io_ctx *c = THREAD_ARG(t);

	c->fd = THREAD_FD(t);
	c->fire_count++;
	c->last_type = t->type;
}

static void
io_silent_cb(struct thread *t)
{
	struct io_ctx *c = THREAD_ARG(t);

	c->fire_count++;
}

/* --- Tier 1 -------------------------------------------------------------- */

static bool
test_read_fires(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx ctx = { 0 };
	int sv[2];
	bool ok;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	assert(write(sv[0], "x", 1) == 1);

	thread_add_read(m, io_record_cb, &ctx, sv[1], TIMER_NEVER, 0);
	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(100));

	launch_thread_scheduler(m);

	ok = ctx.fire_count == 1 &&
	     ctx.fd == sv[1] &&
	     ctx.last_type == THREAD_READY_READ_FD;

	thread_destroy_master(m);
	close(sv[0]);
	close(sv[1]);
	return ok;
}

static bool
test_write_fires(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx ctx = { 0 };
	int sv[2];
	bool ok;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	thread_add_write(m, io_record_cb, &ctx, sv[0], TIMER_NEVER, 0);
	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(100));

	launch_thread_scheduler(m);

	ok = ctx.fire_count == 1 &&
	     ctx.fd == sv[0] &&
	     ctx.last_type == THREAD_READY_WRITE_FD;

	thread_destroy_master(m);
	close(sv[0]);
	close(sv[1]);
	return ok;
}

static bool
test_read_timeout(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx ctx = { 0 };
	int sv[2];
	bool ok;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* no data; expect timeout */
	thread_add_read(m, io_record_cb, &ctx, sv[1], MS_TO_TIMER(50), 0);
	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(200));

	launch_thread_scheduler(m);

	ok = ctx.fire_count == 1 &&
	     ctx.last_type == THREAD_READ_TIMEOUT;

	thread_destroy_master(m);
	close(sv[0]);
	close(sv[1]);
	return ok;
}

static bool
test_thread_del_pending(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx ctx = { 0 };
	struct thread *t;
	int sv[2];
	bool ok;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* add then immediately delete; callback must not fire */
	t = thread_add_read(m, io_silent_cb, &ctx, sv[1], TIMER_NEVER, 0);
	thread_del(t);

	/* make the fd readable; if del left the fd registered we'd see it */
	assert(write(sv[0], "x", 1) == 1);

	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(100));
	launch_thread_scheduler(m);

	ok = ctx.fire_count == 0;

	thread_destroy_master(m);
	close(sv[0]);
	close(sv[1]);
	return ok;
}

static bool
test_dup_registration(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx ctx = { 0 };
	struct thread *t1, *t2;
	int sv[2];
	bool ok;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	t1 = thread_add_read(m, io_silent_cb, &ctx, sv[1], TIMER_NEVER, 0);
	t2 = thread_add_read(m, io_silent_cb, &ctx, sv[1], TIMER_NEVER, 0);

	ok = t1 != NULL && t2 == NULL;

	thread_destroy_master(m);
	close(sv[0]);
	close(sv[1]);
	return ok;
}

/* --- Tier 2 -------------------------------------------------------------- */

static bool
test_read_error_hup(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx ctx = { 0 };
	int sv[2];
	bool ok;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	thread_add_read(m, io_record_cb, &ctx, sv[1], TIMER_NEVER, 0);

	/* peer close: EPOLLHUP/RDHUP on sv[1] -> THREAD_READ_ERROR */
	close(sv[0]);

	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(200));
	launch_thread_scheduler(m);

	ok = ctx.fire_count == 1 && ctx.last_type == THREAD_READ_ERROR;

	thread_destroy_master(m);
	close(sv[1]);
	return ok;
}

static bool
test_read_write_same_fd(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx read_ctx = { 0 }, write_ctx = { 0 };
	int sv[2];
	bool ok;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* make sv[1] read-ready; it is also write-ready (empty send buffer) */
	assert(write(sv[0], "x", 1) == 1);

	thread_add_read(m, io_record_cb, &read_ctx, sv[1], TIMER_NEVER, 0);
	thread_add_write(m, io_record_cb, &write_ctx, sv[1], TIMER_NEVER, 0);

	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(200));
	launch_thread_scheduler(m);

	ok = read_ctx.fire_count == 1 &&
	     read_ctx.last_type == THREAD_READY_READ_FD &&
	     write_ctx.fire_count == 1 &&
	     write_ctx.last_type == THREAD_READY_WRITE_FD;

	thread_destroy_master(m);
	close(sv[0]);
	close(sv[1]);
	return ok;
}

#define GROW_N (THREAD_EPOLL_REALLOC_THRESH + 5)

static bool
test_event_buffer_grow(void)
{
	struct thread_master *m = thread_make_master(false);
	struct io_ctx ctx = { 0 };
	int fds[GROW_N];
	struct thread *ts[GROW_N] = { NULL };
	int pipe_fd[2];
	int i, n = 0;
	bool ok = true;

	while (n + 2 <= GROW_N) {
		if (pipe(pipe_fd) < 0) {
			ok = false;
			goto cleanup;
		}
		fds[n++] = pipe_fd[0];
		fds[n++] = pipe_fd[1];
	}

	for (i = 0; i < n; i++) {
		ts[i] = thread_add_read(m, io_silent_cb, &ctx, fds[i],
					TIMER_NEVER, 0);
		if (!ts[i]) {
			ok = false;
			break;
		}
	}

cleanup:
	for (i = 0; i < GROW_N; i++) {
		if (ts[i])
			thread_del(ts[i]);
	}
	for (i = 0; i < n; i++)
		close(fds[i]);
	thread_destroy_master(m);
	return ok;
}

/*
 * Regression: with no I/O registered the scheduler must still drive
 * timers. Prior to the maxevents=1 fallback, epoll_pwait2() returned
 * EINVAL on maxevents == 0 and the error path looped forever without
 * ever calling thread_timer_expired().
 */
static bool
test_timer_only_no_io(void)
{
	struct thread_master *m = thread_make_master(true);
	struct io_ctx ctx = { 0 };
	bool ok;

	thread_add_timer(m, io_record_cb, &ctx, MS_TO_TIMER(20));
	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(200));

	launch_thread_scheduler(m);

	ok = ctx.fire_count == 1 && ctx.last_type == THREAD_READY_TIMER;

	thread_destroy_master(m);
	return ok;
}

/* --- existing timer cancellation test ------------------------------------ */

static struct thread *tc_t1, *tc_t2, *tc_t3;
static bool tc_ok;

static void
tc_timer_func(struct thread *t)
{
	struct thread *ot = t == tc_t1 ? tc_t2 : tc_t1;

	/* cancel thread that did not yet fire */
	if (tc_t3->type != THREAD_TIMER) {
		tc_ok = false;
		goto done;
	}
	thread_del(tc_t3);

	/* cancel thread that fired, in ready list, but not this callback */
	if (ot->type != THREAD_READY_TIMER) {
		tc_ok = false;
		goto done;
	}
	thread_del(ot);

	/* cancel thread that fired and is this callback (no-op) */
	if (t->type != THREAD_READY_TIMER) {
		tc_ok = false;
		goto done;
	}
	thread_del(t);

	tc_ok = true;
done:
	thread_add_terminate_event(t->master);
}

static bool
test_timer_cancellation(void)
{
	struct thread_master *m = thread_make_master(false);

	tc_ok = false;
	tc_t1 = thread_add_timer(m, tc_timer_func, (void *)1, MS_TO_TIMER(20));
	tc_t2 = thread_add_timer(m, tc_timer_func, (void *)2, MS_TO_TIMER(20));
	tc_t3 = thread_add_timer(m, tc_timer_func, (void *)3, MS_TO_TIMER(500));

	thread_add_timer(m, terminate_cb, NULL, MS_TO_TIMER(300));
	launch_thread_scheduler(m);

	thread_destroy_master(m);
	return tc_ok;
}

/* --- test runner --------------------------------------------------------- */

typedef bool (*test_fn)(void);

struct test_case {
	const char	*name;
	test_fn		fn;
};

static const struct test_case sched_tests[] = {
	/* Tier 1 */
	{ "read_fires",          test_read_fires },
	{ "write_fires",         test_write_fires },
	{ "read_timeout",        test_read_timeout },
	{ "thread_del_pending",  test_thread_del_pending },
	{ "dup_registration",    test_dup_registration },
	/* Tier 2 */
	{ "read_error_hup",      test_read_error_hup },
	{ "read_write_same_fd",  test_read_write_same_fd },
	{ "event_buffer_grow",   test_event_buffer_grow },
	{ "timer_only_no_io",    test_timer_only_no_io },
	/* existing timer test */
	{ "timer_cancellation",  test_timer_cancellation },
};

static int
run_sched_tests(void)
{
	const int n = sizeof(sched_tests) / sizeof(sched_tests[0]);
	int pass = 0, fail = 0;
	int i;

	for (i = 0; i < n; i++) {
		printf("[ RUN      ] %s\n", sched_tests[i].name);
		fflush(stdout);
		if (sched_tests[i].fn()) {
			printf("[       OK ] %s\n", sched_tests[i].name);
			pass++;
		} else {
			printf("[  FAILED  ] %s\n", sched_tests[i].name);
			fail++;
		}
		fflush(stdout);
	}

	printf("\n%d passed, %d failed\n", pass, fail);
	return fail;
}

int main(int argc, char **argv)
{
	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);

	err = parse_cmdline(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	test_mpool();

	return run_sched_tests() ? 1 : 0;
}
