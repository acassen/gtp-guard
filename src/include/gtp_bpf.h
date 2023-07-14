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
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _GTP_BPF_H
#define _GTP_BPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>

/* Flags to direct loading requirements */
#define MAPS_RELAX_COMPAT       0x01

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC   0xcafe4a11
#endif

/* Recommend log buffer size */
#define BPF_LOG_BUF_SIZE (256 * 1024)

#define MAX_MAPS 32
#define MAX_PROGS 32

struct bpf_create_map_attr {
	const char *name;
	enum bpf_map_type map_type;
	__u32 map_flags;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 numa_node;
	__u32 btf_fd;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 map_ifindex;
	union {
		__u32 inner_map_fd;
		__u32 btf_vmlinux_value_type_id;
	};
};

struct bpf_load_program_attr {
	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	const char *name;
	const struct bpf_insn *insns;
	size_t insns_cnt;
	const char *license;
	union {
		__u32 kern_version;
		__u32 attach_prog_fd;
	};
	union {
		__u32 prog_ifindex;
		__u32 attach_btf_id;
	};
	__u32 prog_btf_fd;
	__u32 func_info_rec_size;
	const void *func_info;
	__u32 func_info_cnt;
	__u32 line_info_rec_size;
	const void *line_info;
	__u32 line_info_cnt;
	__u32 log_level;
	__u32 prog_flags;
};

struct bpf_load_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

struct bpf_map_data {
	int fd;
	char *name;
	size_t elf_offset;
	struct bpf_load_map_def def;
};

extern int prog_fd[MAX_PROGS];
extern int event_fd[MAX_PROGS];
extern char bpf_log_buf[BPF_LOG_BUF_SIZE];
extern int prog_cnt;

/* There is a one-to-one mapping between map_fd[] and map_data[].
 * The map_data[] just contains more rich info on the given map.
 */
extern int map_fd[MAX_MAPS];
extern struct bpf_map_data map_data[MAX_MAPS];
extern int map_data_count;

/* Prototypes */
extern unsigned int bpf_num_possible_cpus(void);
extern int bpf_map_update_elem(int, const void *, const void *, __u64);
extern int bpf_map_lookup_elem(int, const void *, void *);
extern int bpf_map_delete_elem(int, const void *);
extern int bpf_map_get_next_key(int, const void *, void *);
extern int bpf_obj_pin(int, const char *);
extern int bpf_obj_get(const char *);
extern int bpf_set_link_xdp_fd(int, int, __u32);
extern int bpf_load_from_file(const char *,
			      int (*)(struct bpf_map_data *, int));
extern void bpf_map_load_ack(int);

#endif
