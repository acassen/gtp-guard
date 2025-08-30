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

#include <sched.h>
#include <sys/resource.h>

#define	RT_RLIMIT_DEFAULT	10000

/* The maximum pid is 2^22 - see definition of PID_MAX_LIMIT in kernel source include/linux/threads.h */
#define PID_MAX_DIGITS		7

extern long min_auto_priority_delay;

extern void set_process_priorities(int, int, long, int, int, int);
extern void reset_process_priorities(void);
extern void increment_process_priority(void);
extern unsigned get_cur_priority(void) __attribute__((pure));
extern unsigned get_cur_rlimit_rttime(void) __attribute__((pure));
extern int set_process_cpu_affinity(cpu_set_t *, const char *);
extern int get_process_cpu_affinity_string(cpu_set_t *, char *, size_t);
extern void set_child_rlimit(int, const struct rlimit *);

extern void set_max_file_limit(unsigned);
