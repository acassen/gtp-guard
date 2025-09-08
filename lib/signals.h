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

#include <signal.h>
#include <stdbool.h>
#include "thread.h"

#define SIGJSON 		(SIGRTMIN + 2)
#ifdef THREAD_DUMP
#define	SIGTDUMP		(SIGRTMAX)
#endif
#define	SIGSTATS_CLEAR		(SIGRTMAX - 1)
#ifndef _ONE_PROCESS_DEBUG_
#endif

static inline int
sigmask_func(int how, const sigset_t *set, sigset_t *oldset)
{
#ifdef _WITH_PTHREADS_
    return pthread_sigmask(how, set, oldset);
#else
    return sigprocmask(how, set, oldset);
#endif
}

/* Prototypes */
int get_signum(const char *sigfunc);
void signal_set(int signo, void (*func) (void *, int), void *v);
void signal_ignore(int signo);
int signal_handler_init(void);
void signal_handler_destroy(void);
void signal_handler_script(void);
void add_signal_read_thread(struct thread_master *m);
void cancel_signal_read_thread(void);
void set_sigxcpu_handler(void);
void signal_noignore_sigchld(void);
void signal_noignore_sig(int sig);
