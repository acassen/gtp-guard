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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <stdlib.h>
#include <libbpf.h> /* libbpf_num_possible_cpus */

enum {
	RULE_ADD = 0,
	RULE_UPDATE,
	RULE_DEL,
	RULE_LIST
};

#define GTP_XDP_STRERR_BUFSIZE	128

static inline unsigned int bpf_num_possible_cpus(void)
{
	int possible_cpus = libbpf_num_possible_cpus();

	if (possible_cpus < 0) {
		printf("Failed to get # of possible cpus: '%s'!\n",
			strerror(-possible_cpus));
		exit(EXIT_FAILURE);
	}
	return possible_cpus;
}

#define __bpf_percpu_val_align  __attribute__((__aligned__(8)))

#define BPF_DECLARE_PERCPU(type, name)                          \
	struct { type v; /* padding */ } __bpf_percpu_val_align \
		 name[bpf_num_possible_cpus()]
#define bpf_percpu(name, cpu) name[(cpu)].v

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))
#endif
