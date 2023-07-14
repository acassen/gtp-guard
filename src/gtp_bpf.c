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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <unistd.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>
#include <asm/unistd.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <time.h>
#include <assert.h>
#include "logger.h"
#include "gtp_bpf.h"

/*
 * When building perf, unistd.h is overridden. __NR_bpf is
 * required to be defined explicitly.
 */
#ifndef __NR_bpf
#if defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__sparc__)
#define __NR_bpf 349
#elif defined(__s390__)
#define __NR_bpf 351
#else
#error __NR_bpf not defined. libbpf does not support your arch.
#endif
#endif

/*
 * Netlink type surcharge
 */
#ifndef IFLA_XDP
#define IFLA_XDP 43
#endif

#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD 1
#endif

#ifndef IFLA_XDP_FLAGS
#define IFLA_XDP_FLAGS 3
#endif

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

/*
 *	global vars
 */
static char license[128];
static int kern_version;
static bool processed_sec[128];
char bpf_log_buf[BPF_LOG_BUF_SIZE];
int map_fd[MAX_MAPS];
int prog_fd[MAX_PROGS];
int event_fd[MAX_PROGS];
int prog_cnt = 0;
int prog_array_fd = -1;

struct bpf_map_data map_data[MAX_MAPS];
int map_data_count = 0;

static inline __u64
ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int
sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

/*
 *	Utilities
 */
unsigned int
bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;
	int n;

	fp = fopen(fcpu, "r");
	if (!fp) {
		log_message(LOG_INFO, "%s(): Failed to open %s: '%s'!\n"
			      , __FUNCTION__
			      , fcpu, strerror(errno));
		exit(1);
	}

	while (fgets(buff, sizeof (buff), fp)) {
		n = sscanf(buff, "%u-%u", &start, &end);
		if (n == 0) {
			log_message(LOG_INFO, "%s(): Failed to retrieve # possible CPUs!\n"
				      , __FUNCTION__);
			exit(1);
		} else if (n == 1) {
			end = start;
		}
		possible_cpus = start == 0 ? end + 1 : 0;
		break;
	}
	fclose(fp);

	return possible_cpus;
}

/*
 *	Native BPF Loader
 */
int
bpf_create_map_xattr(const struct bpf_create_map_attr *create_attr)
{
	__u32 name_len = create_attr->name ? strlen(create_attr->name) : 0;
	union bpf_attr attr;

	memset(&attr, '\0', sizeof (attr));

	attr.map_type = create_attr->map_type;
	attr.key_size = create_attr->key_size;
	attr.value_size = create_attr->value_size;
	attr.max_entries = create_attr->max_entries;
	attr.map_flags = create_attr->map_flags;
	memcpy(attr.map_name, create_attr->name,
	       min(name_len, BPF_OBJ_NAME_LEN - 1));
	attr.inner_map_fd = create_attr->inner_map_fd;
	attr.numa_node = create_attr->numa_node;
        attr.btf_fd = create_attr->btf_fd;
        attr.btf_key_type_id = create_attr->btf_key_type_id;
        attr.btf_value_type_id = create_attr->btf_value_type_id;
        attr.map_ifindex = create_attr->map_ifindex;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof (attr));
}

int
bpf_create_map_node(enum bpf_map_type map_type, const char *name,
		    int key_size, int value_size, int max_entries,
		    __u32 map_flags, int node)
{
	struct bpf_create_map_attr map_attr = { };

	map_attr.name = name;
	map_attr.map_type = map_type;
	map_attr.map_flags = map_flags;
	map_attr.key_size = key_size;
	map_attr.value_size = value_size;
	map_attr.max_entries = max_entries;
	if (node >= 0) {
		map_attr.numa_node = node;
		map_attr.map_flags |= BPF_F_NUMA_NODE;
	}

	return bpf_create_map_xattr(&map_attr);
}

int
bpf_create_map(enum bpf_map_type map_type, int key_size,
	       int value_size, int max_entries, __u32 map_flags)
{
	struct bpf_create_map_attr map_attr = { };

	map_attr.map_type = map_type;
	map_attr.map_flags = map_flags;
	map_attr.key_size = key_size;
	map_attr.value_size = value_size;
	map_attr.max_entries = max_entries;

	return bpf_create_map_xattr(&map_attr);
}

int
bpf_create_map_name(enum bpf_map_type map_type, const char *name,
		    int key_size, int value_size, int max_entries,
		    __u32 map_flags)
{
	struct bpf_create_map_attr map_attr = { };

	map_attr.name = name;
	map_attr.map_type = map_type;
	map_attr.map_flags = map_flags;
	map_attr.key_size = key_size;
	map_attr.value_size = value_size;
	map_attr.max_entries = max_entries;

	return bpf_create_map_xattr(&map_attr);
}

int
bpf_create_map_in_map_node(enum bpf_map_type map_type, const char *name,
			   int key_size, int inner_map_fd, int max_entries,
			   __u32 map_flags, int node)
{
	__u32 name_len = name ? strlen(name) : 0;
	union bpf_attr attr;

	memset(&attr, '\0', sizeof (attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = 4;
	attr.inner_map_fd = inner_map_fd;
	attr.max_entries = max_entries;
	attr.map_flags = map_flags;
	memcpy(attr.map_name, name, min(name_len, BPF_OBJ_NAME_LEN - 1));

	if (node >= 0) {
		attr.map_flags |= BPF_F_NUMA_NODE;
		attr.numa_node = node;
	}

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof (attr));
}

int
bpf_create_map_in_map(enum bpf_map_type map_type, const char *name,
		      int key_size, int inner_map_fd, int max_entries,
		      __u32 map_flags)
{
	return bpf_create_map_in_map_node(map_type, name, key_size,
					  inner_map_fd, max_entries, map_flags,
					  -1);
}

int
bpf_load_program_xattr(const struct bpf_load_program_attr *load_attr,
		       char *log_buf, size_t log_buf_sz)
{
	union bpf_attr attr;
	__u32 name_len;
	int fd;

	if (!load_attr)
		return -EINVAL;

	name_len = load_attr->name ? strlen(load_attr->name) : 0;

	bzero(&attr, sizeof (attr));
	attr.prog_type = load_attr->prog_type;
	attr.expected_attach_type = load_attr->expected_attach_type;
	attr.insn_cnt = (__u32) load_attr->insns_cnt;
	attr.insns = ptr_to_u64(load_attr->insns);
	attr.license = ptr_to_u64(load_attr->license);
	attr.log_buf = ptr_to_u64(NULL);
	attr.log_size = 0;
	attr.log_level = 0;
	attr.kern_version = load_attr->kern_version;
	attr.prog_ifindex = load_attr->prog_ifindex;
	memcpy(attr.prog_name, load_attr->name,
	       min(name_len, BPF_OBJ_NAME_LEN - 1));

	fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof (attr));
	if (fd >= 0 || !log_buf || !log_buf_sz)
		return fd;

	/* Try again with log */
	attr.log_buf = ptr_to_u64(log_buf);
	attr.log_size = log_buf_sz;
	attr.log_level = 1;
	log_buf[0] = 0;
	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof (attr));
}

int
bpf_load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
		 size_t insns_cnt, const char *license,
		 __u32 kern_version, char *log_buf, size_t log_buf_sz)
{
	struct bpf_load_program_attr load_attr;

	memset(&load_attr, 0, sizeof (struct bpf_load_program_attr));
	load_attr.prog_type = type;
	load_attr.expected_attach_type = 0;
	load_attr.name = NULL;
	load_attr.insns = insns;
	load_attr.insns_cnt = insns_cnt;
	load_attr.license = license;
	load_attr.kern_version = kern_version;

	return bpf_load_program_xattr(&load_attr, log_buf, log_buf_sz);
}

int
bpf_verify_program(enum bpf_prog_type type, const struct bpf_insn *insns,
		   size_t insns_cnt, int strict_alignment,
		   const char *license, __u32 kern_version,
		   char *log_buf, size_t log_buf_sz, int log_level)
{
	union bpf_attr attr;

	bzero(&attr, sizeof (attr));
	attr.prog_type = type;
	attr.insn_cnt = (__u32) insns_cnt;
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64(license);
	attr.log_buf = ptr_to_u64(log_buf);
	attr.log_size = log_buf_sz;
	attr.log_level = log_level;
	log_buf[0] = 0;
	attr.kern_version = kern_version;
	attr.prog_flags = strict_alignment ? BPF_F_STRICT_ALIGNMENT : 0;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof (attr));
}

/*
 *	BPF helpers
 */
int
bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof (attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof (attr));
}

int
bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	bzero(&attr, sizeof (attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof (attr));
}

int
bpf_map_delete_elem(int fd, const void *key)
{
	union bpf_attr attr;

	bzero(&attr, sizeof (attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof (attr));
}

int
bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	union bpf_attr attr;

	bzero(&attr, sizeof (attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof (attr));
}

int
bpf_obj_pin(int fd, const char *pathname)
{
	union bpf_attr attr;

	bzero(&attr, sizeof (attr));
	attr.pathname = ptr_to_u64((void *) pathname);
	attr.bpf_fd = fd;

	return sys_bpf(BPF_OBJ_PIN, &attr, sizeof (attr));
}

int
bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;

	bzero(&attr, sizeof (attr));
	attr.pathname = ptr_to_u64((void *) pathname);

	return sys_bpf(BPF_OBJ_GET, &attr, sizeof (attr));
}

/*
 *	Netlink helpers
 */
static int
bpf_netlink_open(__u32 * nl_pid)
{
	struct sockaddr_nl sa;
	socklen_t addrlen;
	int ret, sock;

	memset(&sa, 0, sizeof (sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sock < 0)
		return -errno;

	if (bind(sock, (struct sockaddr *) &sa, sizeof (sa)) < 0) {
		ret = -errno;
		goto cleanup;
	}

	addrlen = sizeof (sa);
	if (getsockname(sock, (struct sockaddr *) &sa, &addrlen) < 0) {
		ret = -errno;
		goto cleanup;
	}

	if (addrlen != sizeof (sa)) {
		ret = -1;
		goto cleanup;
	}

	*nl_pid = sa.nl_pid;
	return sock;

      cleanup:
	close(sock);
	return ret;
}

static int
bpf_netlink_recv(int sock, __u32 nl_pid, int seq)
{
	bool multipart = true;
	struct nlmsgerr *err;
	struct nlmsghdr *nh;
	char buf[4096];
	int len, ret;

	while (multipart) {
		multipart = false;
		len = recv(sock, buf, sizeof (buf), 0);
		if (len < 0) {
			ret = -errno;
			goto done;
		}

		if (len == 0)
			break;

		for (nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_pid != nl_pid) {
				log_message(LOG_INFO, "%s(): Wrong nlmsg_pid(%d)!=nl_pid(%d)\n"
					      , __FUNCTION__, nh->nlmsg_pid, nl_pid);
				ret = -1;
				goto done;
			}
			if (nh->nlmsg_seq != seq) {
				log_message(LOG_INFO, "%s(): Wrong nlmsg_seq(%d)!=seq(%d)\n"
					      , __FUNCTION__, nh->nlmsg_seq, seq);
				ret = -1;
				goto done;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI)
				multipart = true;
			switch (nh->nlmsg_type) {
			case NLMSG_ERROR:
				err = (struct nlmsgerr *) NLMSG_DATA(nh);
				if (!err->error)
					continue;
				ret = err->error;
				log_message(LOG_INFO, "%s(): nlmsg error(%s)\n"
					      , __FUNCTION__, strerror(-ret));
				goto done;
			case NLMSG_DONE:
				return 0;
			default:
				break;
			}
		}
	}

	ret = 0;
      done:
	return ret;
}

int
bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
	int sock, seq = 0, ret;
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifinfo;
		char attrbuf[64];
	} req;
	__u32 nl_pid = 0;

	if (ifindex < 0)
		return -1;

	sock = bpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	memset(&req, 0, sizeof (req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;

	/* started nested attribute for XDP */
	nla = (struct nlattr *) (((char *) &req)
				 + NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | IFLA_XDP;
	nla->nla_len = NLA_HDRLEN;

	/* add XDP fd */
	nla_xdp = (struct nlattr *) ((char *) nla + nla->nla_len);
	nla_xdp->nla_type = IFLA_XDP_FD;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof (int);
	memcpy((char *) nla_xdp + NLA_HDRLEN, &fd, sizeof (fd));
	nla->nla_len += nla_xdp->nla_len;

	/* if user passed in any flags, add those too */
	if (flags) {
		nla_xdp = (struct nlattr *) ((char *) nla + nla->nla_len);
		nla_xdp->nla_type = IFLA_XDP_FLAGS;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof (flags);
		memcpy((char *) nla_xdp + NLA_HDRLEN, &flags, sizeof (flags));
		nla->nla_len += nla_xdp->nla_len;
	}

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		ret = -errno;
		goto cleanup;
	}
	ret = bpf_netlink_recv(sock, nl_pid, seq);

      cleanup:
	close(sock);
	return ret;
}

/*
 *	ELF helpers
 */
static int
load_and_attach(const char *event, struct bpf_insn *prog, int size)
{
	size_t insns_cnt = size / sizeof (struct bpf_insn);
	int fd;

	if (prog_cnt == MAX_PROGS) {
		log_message(LOG_INFO, "%s(): Too many program loaded (prog_cnt:%d)\n"
			      , __FUNCTION__, prog_cnt);
		return -1;
	}

	if (strncmp(event, "xdp", 3) != 0) {
		log_message(LOG_INFO, "%s(): Unknown event '%s'\n"
			      , __FUNCTION__, event);
		return -1;
	}

	fd = bpf_load_program(BPF_PROG_TYPE_XDP, prog, insns_cnt, license,
			      kern_version, bpf_log_buf, BPF_LOG_BUF_SIZE);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): Error loading BPF program errno=%d (%m)\n%s\n"
			      , __FUNCTION__, errno, bpf_log_buf);
		return -1;
	}

	prog_fd[prog_cnt++] = fd;
	return 0;
}

static int
load_maps(struct bpf_map_data *maps, int nr_maps,
	  int (*fixup_map) (struct bpf_map_data *, int))
{
	int i, j, numa_node;

	for (i = 0, j = map_data_count; i < nr_maps; i++, j++) {
		if (fixup_map) {
			(*fixup_map) (&maps[j], i);
			/* Allow userspace to assign map FD prior to creation */
			if (maps[j].fd != -1) {
				map_fd[j] = maps[j].fd;
				continue;
			}
		}

		numa_node = maps[j].def.map_flags & BPF_F_NUMA_NODE ?
		    		maps[j].def.numa_node : -1;

		if (maps[j].def.type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
		    maps[j].def.type == BPF_MAP_TYPE_HASH_OF_MAPS) {
			int inner_map_fd = map_fd[maps[j].def.inner_map_idx + map_data_count];

			map_fd[j] = bpf_create_map_in_map_node(maps[j].def.type,
							       maps[j].name,
							       maps[j].def.
							       key_size,
							       inner_map_fd,
							       maps[j].def.
							       max_entries,
							       maps[j].def.
							       map_flags,
							       numa_node);
		} else {
			map_fd[j] = bpf_create_map_node(maps[j].def.type,
							maps[j].name,
							maps[j].def.key_size,
							maps[j].def.value_size,
							maps[j].def.max_entries,
							maps[j].def.map_flags,
							numa_node);
		}
		if (map_fd[j] < 0) {
			log_message(LOG_INFO, "%s(): failed to create a map: %d (%m)\n"
				      , __FUNCTION__, errno);
			return -1;
		}
		maps[j].fd = map_fd[j];

		if (maps[j].def.type == BPF_MAP_TYPE_PROG_ARRAY)
			prog_array_fd = map_fd[j];
	}

	return 0;
}

static int
get_sec(Elf * elf, int i, GElf_Ehdr * ehdr, char **shname,
	GElf_Shdr * shdr, Elf_Data ** data)
{
	Elf_Scn *scn;

	scn = elf_getscn(elf, i);
	if (!scn)
		return -1;

	if (gelf_getshdr(scn, shdr) != shdr)
		return -1;

	*shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
	if (!*shname || !shdr->sh_size)
		return -1;

	*data = elf_getdata(scn, 0);
	if (!*data || elf_getdata(scn, *data) != NULL)
		return -1;

	return 0;
}

static int
parse_relo_and_apply(Elf_Data * data, Elf_Data * symbols,
		     GElf_Shdr * shdr, struct bpf_insn *insn,
		     struct bpf_map_data *maps, int nr_maps)
{
	int i, nrels;

	nrels = shdr->sh_size / shdr->sh_entsize;

	for (i = 0; i < nrels; i++) {
		GElf_Sym sym;
		GElf_Rel rel;
		unsigned int insn_idx;
		bool match = false;
		int map_idx;

		gelf_getrel(data, i, &rel);

		insn_idx = rel.r_offset / sizeof (struct bpf_insn);

		gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

		if (insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
			log_message(LOG_INFO, "%s(): invalid relo for insn[%d].code 0x%x\n",
				__FUNCTION__, insn_idx, insn[insn_idx].code);
			return -1;
		}
		insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;

		/* Match FD relocation against recorded map_data[] offset */
		for (map_idx = 0; map_idx < nr_maps; map_idx++) {
			if (maps[map_data_count + map_idx].elf_offset == sym.st_value) {
				match = true;
				break;
			}
		}
		if (match) {
			insn[insn_idx].imm = maps[map_data_count + map_idx].fd;
		} else {
			log_message(LOG_INFO, "%s(): invalid relo for insn[%d] no map_data match\n"
				      , __FUNCTION__, insn_idx);
			return -1;
		}
	}

	return 0;
}

static int
cmp_symbols(const void *l, const void *r)
{
	const GElf_Sym *lsym = (const GElf_Sym *) l;
	const GElf_Sym *rsym = (const GElf_Sym *) r;

	if (lsym->st_value < rsym->st_value)
		return -1;
	else if (lsym->st_value > rsym->st_value)
		return 1;
	else
		return 0;
}

static int
load_elf_maps_section(struct bpf_map_data *maps, int maps_shndx,
		      Elf * elf, Elf_Data * symbols, int strtabidx)
{
	int map_sz_elf, map_sz_copy;
	bool validate_zero = false;
	Elf_Data *data_maps;
	int i, nr_maps;
	GElf_Sym *sym;
	Elf_Scn *scn;

	if (maps_shndx < 0)
		return -EINVAL;
	if (!symbols)
		return -EINVAL;

	/* Get data for maps section via elf index */
	scn = elf_getscn(elf, maps_shndx);
	if (scn)
		data_maps = elf_getdata(scn, NULL);
	if (!scn || !data_maps) {
		log_message(LOG_INFO, "%s(): Failed to get Elf_Data from maps section %d\n"
			      , __FUNCTION__, maps_shndx);
		return -EINVAL;
	}

	/* For each map get corrosponding symbol table entry */
	sym = calloc(MAX_MAPS + 1, sizeof (GElf_Sym));
	for (i = 0, nr_maps = 0; i < symbols->d_size / sizeof (GElf_Sym); i++) {
		assert(nr_maps < MAX_MAPS + 1);
		if (!gelf_getsym(symbols, i, &sym[nr_maps]))
			continue;
		if (sym[nr_maps].st_shndx != maps_shndx)
			continue;
		/* Only increment iif maps section */
		nr_maps++;
	}

	/* Align to map_fd[] order, via sort on offset in sym.st_value */
	qsort(sym, nr_maps, sizeof (GElf_Sym), cmp_symbols);

	/* Keeping compatible with ELF maps section changes
	 * ------------------------------------------------
	 * The program size of struct bpf_load_map_def is known by loader
	 * code, but struct stored in ELF file can be different.
	 *
	 * Unfortunately sym[i].st_size is zero.  To calculate the
	 * struct size stored in the ELF file, assume all struct have
	 * the same size, and simply divide with number of map
	 * symbols.
	 */
	map_sz_elf = data_maps->d_size / nr_maps;
	map_sz_copy = sizeof (struct bpf_load_map_def);
	if (map_sz_elf < map_sz_copy) {
		/*
		 * Backward compat, loading older ELF file with
		 * smaller struct, keeping remaining bytes zero.
		 */
		map_sz_copy = map_sz_elf;
	} else if (map_sz_elf > map_sz_copy) {
		/*
		 * Forward compat, loading newer ELF file with larger
		 * struct with unknown features. Assume zero means
		 * feature not used.  Thus, validate rest of struct
		 * data is zero.
		 */
		validate_zero = true;
	}

	/* Memcpy relevant part of ELF maps data to loader maps */
	for (i = 0; i < nr_maps; i++) {
		struct bpf_load_map_def *def;
		unsigned char *addr, *end;
		const char *map_name;
		size_t offset;

		map_name = elf_strptr(elf, strtabidx, sym[i].st_name);
		maps[map_data_count + i].name = strdup(map_name);
		if (!maps[map_data_count + i].name) {
			log_message(LOG_INFO, "%s(): strdup(%s): %d (%m)\n"
				      , __FUNCTION__, map_name, errno);
			free(sym);
			return -errno;
		}

		/* Symbol value is offset into ELF maps section data area */
		offset = sym[i].st_value;
		def = (struct bpf_load_map_def *) ((uint8_t *) data_maps->d_buf + offset);
		maps[map_data_count + i].elf_offset = offset;
		memset(&maps[map_data_count + i].def, 0, sizeof (struct bpf_load_map_def));
		memcpy(&maps[map_data_count + i].def, def, map_sz_copy);

		/* Verify no newer features were requested */
		if (validate_zero) {
			addr = (unsigned char *) def + map_sz_copy;
			end = (unsigned char *) def + map_sz_elf;
			for (; addr < end; addr++) {
				if (*addr != 0) {
					free(sym);
					return -EFBIG;
				}
			}
		}
	}

	free(sym);
	return nr_maps;
}

int
bpf_load_from_file(const char *path, int (*fixup_map) (struct bpf_map_data *, int))
{
	int fd, i, ret = -1, maps_shndx = -1, strtabidx = -1;
	Elf *elf;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr, shdr_prog;
	Elf_Data *data, *data_prog, *data_maps = NULL, *symbols = NULL;
	char *shname, *shname_prog;
	int nr_maps = 0;

	/* reset global variables */
	kern_version = 0;
	memset(license, 0, sizeof (license));
	memset(processed_sec, 0, sizeof (processed_sec));

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf)
		return -1;

	if (gelf_getehdr(elf, &ehdr) != &ehdr)
		return -1;

	/* scan over all elf sections to get license and map info */
	for (i = 1; i < ehdr.e_shnum; i++) {
		if (get_sec(elf, i, &ehdr, &shname, &shdr, &data) < 0)
			continue;

#if 0		/* helpful for llvm debugging */
		printf("section %d:%s data %p size %zd link %d flags %d\n",
		       i, shname, data->d_buf, data->d_size,
		       shdr.sh_link, (int) shdr.sh_flags);
#endif

		if (strcmp(shname, "license") == 0) {
			processed_sec[i] = true;
			memcpy(license, data->d_buf, data->d_size);
		} else if (strcmp(shname, "version") == 0) {
			processed_sec[i] = true;
			if (data->d_size != sizeof (int)) {
				log_message(LOG_INFO, "%s(): invalid size of version section %zd\n"
					      , __FUNCTION__, data->d_size);
				return -1;
			}
			memcpy(&kern_version, data->d_buf, sizeof (int));
		} else if (strcmp(shname, "maps") == 0) {
			int j;

			maps_shndx = i;
			data_maps = data;
			for (j = map_data_count; j < MAX_MAPS; j++)
				map_data[j].fd = -1;
		} else if (shdr.sh_type == SHT_SYMTAB) {
			strtabidx = shdr.sh_link;
			symbols = data;
		}
	}

	if (!symbols) {
		log_message(LOG_INFO, "%s(): missing SHT_SYMTAB section\n"
			      , __FUNCTION__);
		goto done;
	}

	if (data_maps) {
		nr_maps = load_elf_maps_section(map_data, maps_shndx,
						elf, symbols, strtabidx);
		if (nr_maps < 0) {
			log_message(LOG_INFO, "%s(): Error: Failed loading ELF maps (errno:%d):%s\n"
				      , __FUNCTION__, nr_maps, strerror(-nr_maps));
			goto done;
		}

		if (load_maps(map_data, nr_maps, fixup_map) < 0)
			goto done;

		processed_sec[maps_shndx] = true;
	}

	/* process all relo sections, and rewrite bpf insns for maps */
	for (i = 1; i < ehdr.e_shnum; i++) {
		if (processed_sec[i])
			continue;

		if (get_sec(elf, i, &ehdr, &shname, &shdr, &data) < 0)
			continue;

		if (shdr.sh_type == SHT_REL) {
			struct bpf_insn *insns;

			/* locate prog sec that need map fixup (relocations) */
			if (get_sec(elf, shdr.sh_info, &ehdr, &shname_prog,
				    &shdr_prog, &data_prog) < 0)
				continue;

			if (shdr_prog.sh_type != SHT_PROGBITS ||
			    !(shdr_prog.sh_flags & SHF_EXECINSTR))
				continue;

			insns = (struct bpf_insn *) data_prog->d_buf;
			processed_sec[i] = true;	/* relo section */

			if (parse_relo_and_apply(data, symbols, &shdr, insns,
						 map_data, nr_maps) < 0)
				continue;
		}
	}

	/* load programs */
	for (i = 1; i < ehdr.e_shnum; i++) {
		if (processed_sec[i])
			continue;

		if (get_sec(elf, i, &ehdr, &shname, &shdr, &data) < 0)
			continue;

		/* Only XDP loading supported */
		if (memcmp(shname, "xdp", 3) != 0)
			continue;

		ret = load_and_attach(shname, data->d_buf, data->d_size);
		if (ret < 0)
			break;
	}

      done:
	close(fd);
	return ret;
}

void
bpf_map_load_ack(int nr_maps)
{
	map_data_count += nr_maps;
}
