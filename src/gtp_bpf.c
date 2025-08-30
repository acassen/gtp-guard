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

#include <stdlib.h>
#include <errno.h>
#include <btf.h>

#include "gtp_interface.h"
#include "gtp_bpf_utils.h"
#include "gtp_bpf.h"
#include "libbpf.h"
#include "logger.h"
#include "utils.h"


/*
 *	BPF Interface topology reflection
 * During daemon bootstrap a netlink interface probe is performed
 * to reflect these topology informations to BPF progs that may
 * use it.
 */
static struct ll_attr *
gtp_bpf_ll_attr_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ll_attr *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct ll_attr);
	return new;
}

static void
gtp_bpf_ll_attr_prepare(struct ll_attr *attr, uint16_t vlan_id, uint16_t flags)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int i;

	for (i = 0; i < nr_cpus; i++) {
		attr[i].vlan_id = vlan_id;
		attr[i].flags = flags;
	}
}

int
gtp_bpf_ll_attr_update(struct bpf_map *map, uint32_t ifindex, uint16_t vlan_id,
		       uint16_t flags)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	struct ll_attr *new;
	size_t sz;
	int err;

	new = gtp_bpf_ll_attr_alloc(&sz);
	if (!new) {
		log_message(LOG_INFO, "%s(): Cant allocate if_attr !!!"
				    , __FUNCTION__);
		return -1;
	}

	gtp_bpf_ll_attr_prepare(new, vlan_id, flags);
	err = bpf_map__update_elem(map, &ifindex, sizeof(uint32_t), new, sz, BPF_NOEXIST);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant add attr for ifindex:%d (%s)"
				    , __FUNCTION__
				    , ifindex
				    , errmsg);
		err = -1;
	}

	free(new);
	return err;
}

struct bpf_map *
gtp_bpf_load_map(struct bpf_object *obj, const char *map_name)
{
	struct bpf_map *map = NULL;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): XDP: error mapping tab:%s err:%d (%s)"
				    , __FUNCTION__
				    , map_name
				    , errno, errmsg);
		return NULL;
	}

	return map;
}

static int
gtp_bpf_log_message(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(debug & 16))
		return 0;

	log_message(LOG_INFO, format, args);
	return 0;
}


/*
 *	BPF init
 */
int
gtp_bpf_init(void)
{
	libbpf_set_print(gtp_bpf_log_message);
	return 0;
}

int
gtp_bpf_destroy(void)
{
	return 0;
}
