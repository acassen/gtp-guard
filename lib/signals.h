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

#ifndef _SIGNALS_H
#define _SIGNALS_H

#include "config.h"

#include <signal.h>
#include <stdbool.h>

#include "scheduler.h"

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
extern int get_signum(const char *);
extern void signal_set(int, void (*) (void *, int), void *);
extern void signal_ignore(int);
extern int signal_handler_init(void);
extern void signal_handler_destroy(void);
extern void signal_handler_script(void);
extern void add_signal_read_thread(thread_master_t *);
extern void cancel_signal_read_thread(void);
extern void set_sigxcpu_handler(void);
extern void signal_noignore_sigchld(void);
extern void signal_noignore_sig(int);

#ifdef THREAD_DUMP
extern void register_signal_thread_addresses(void);
#endif

#endif
