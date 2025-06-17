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

/* system includes */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libbpf.h>
#include <btf.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;

/* Local data */
static const char *pin_basedir = "/sys/fs/bpf";


/*
 *	BPF Object variable update.
 *
 *  This only apply to global variables as present in .rodata section,
 *  without using generated skeleton from libbpf.
 *  They can be modified *only* before program is loaded into kernel.
 *  it should be the same for variables in .data or .bss sections.
 */
static const char *
gtp_bpf_obj_get_rodata_name(struct bpf_object *obj)
{
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		if (strstr(bpf_map__name(map), ".rodata"))
			return bpf_map__name(map);
	}

	return NULL;
}

static int
gtp_bpf_obj_update_var(struct bpf_object *obj, const char *varname, uint32_t value)
{
	struct bpf_map *map;
	const char *name;
	void *rodata;
	bool found = false;

	name = gtp_bpf_obj_get_rodata_name(obj);
	if (!name) {
		log_message(LOG_INFO, "%s(): cant find rodata !!!", __FUNCTION__);
		errno = ENOENT;
		return -1;
	}

	/* this open() subskeleton is only here to retrieve map's mmap address
	 * libbpf doesn't provide other way to get this address */
	struct bpf_map_skeleton ms[1] = { {
		.name = name,
		.map = &map,
		.mmaped = &rodata,
	} };
	struct bpf_object_subskeleton ss = {
		.sz = sizeof (struct bpf_object_subskeleton),
		.obj = obj,
		.map_cnt = 1,
		.map_skel_sz = sizeof (struct bpf_map_skeleton),
		.maps = ms,
	};
	if (bpf_object__open_subskeleton(&ss) < 0) {
		log_message(LOG_INFO, "%s(): cant open subskeleton !!!", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	/* now use btf info to find this variable */
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	int sec_id, i;

	btf = bpf_object__btf(obj);
	if (btf == NULL) {
		log_message(LOG_INFO, "%s(): cant get BTF handler !!!", __FUNCTION__);
		errno = ENOENT;
		return -1;
	}

	/* get secdata id */
	sec_id = btf__find_by_name(btf, ".rodata");
	if (sec_id < 0) {
		log_message(LOG_INFO, "%s(): cant get .rodata section !!!", __FUNCTION__);
		errno = ENOENT;
		return -1;
	}

	/* get the actual BTF type from the ID */
	sec = btf__type_by_id(btf, sec_id);
	if (sec == NULL) {
		log_message(LOG_INFO, "%s(): cant get BTF type from section ID !!!"
				    , __FUNCTION__);
		errno = ENOENT;
		return -1;
	}

	/* Get all secinfos, each of which will be a global variable */
	secinfo = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++) {
		const struct btf_type *t = btf__type_by_id(btf, secinfo[i].type);
		const char *name = btf__name_by_offset(btf, t->name_off);

		if (!strncmp(name, varname, strlen(name))) {
			*((uint32_t *)(rodata + secinfo[i].offset)) = value;
			found = true;
		}
	}

	if (!found) {
		log_message(LOG_INFO, "%s(): unknown varname:%s !!!"
				, __FUNCTION__, varname);
		errno = ESRCH;
		return -1;
	}

	return 0;
}

int
gtp_bpf_obj_update_global_vars(struct bpf_object *obj)
{
	/* Update global variables */
	return gtp_bpf_obj_update_var(obj, "nr_cpus", bpf_num_possible_cpus());
}


/*
 *	BPF Global OPTS related
 */
static int
gtp_bpf_log_message(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(debug & 16))
		return 0;

	log_message(LOG_INFO, format, args);
	return 0;
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

static void
gtp_bpf_cleanup_maps(struct bpf_object *obj, gtp_bpf_opts_t *opts)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	struct bpf_map *map;
	vty_t *vty = opts->vty;

	bpf_object__for_each_map(map, obj) {
		char buf[GTP_STR_MAX_LEN];
		int len, err;

		len = snprintf(buf, GTP_STR_MAX_LEN, "%s/%d/%s"
						   , pin_basedir
						   , opts->ifindex
						   , bpf_map__name(map));
		if (len < 0) {
			vty_out(vty, "%% eBPF: error preparing path for map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (len > GTP_STR_MAX_LEN) {
			vty_out(vty, "%% eBPF error, pathname too long to store map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (access(buf, F_OK) != -1) {
			vty_out(vty, "eBPF: unpinning previous map in %s%s"
				   , buf, VTY_NEWLINE);
			err = bpf_map__unpin(map, buf);
			if (err) {
				libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
				vty_out(vty, "%% eBPF error:%d (%s)%s"
					   , err, errmsg, VTY_NEWLINE);
				continue;
			}
		}
	}
}

static struct bpf_object *
gtp_bpf_load_file(gtp_bpf_opts_t *opts)
{
	struct bpf_object *bpf_obj;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	vty_t *vty = opts->vty;
	int err;

	/* open eBPF file */
	bpf_obj = bpf_object__open(opts->filename);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		vty_out(vty, "%% eBPF: error opening bpf file err:%d (%s)%s"
			   , errno, errmsg, VTY_NEWLINE);
		return NULL;
	}

	/* Global vars update */
	gtp_bpf_obj_update_global_vars(bpf_obj);

	/* Release previously stalled maps. Our lazzy strategy here is to
	 * simply erase previous maps during startup. Maybe if we want to
	 * implement some kind of graceful-restart we need to reuse-maps
	 * and rebuild local daemon tracking. Auto-pinning is done during
	 * bpf_object__load.
	 * FIXME: Implement graceful-restart */
	gtp_bpf_cleanup_maps(bpf_obj, opts);

	/* Finally load it */
	err = bpf_object__load(bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		vty_out(vty, "%% eBPF: error loading bpf_object err:%d (%s)%s"
			   , err, errmsg, VTY_NEWLINE);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	return bpf_obj;
}

struct bpf_program *
gtp_bpf_load_prog(gtp_bpf_opts_t *opts)
{
	struct bpf_program *bpf_prog = NULL;
	struct bpf_object *bpf_obj;
	int len;

	/* Preprare pin_dir. We decided ifindex to be part of
	 * path to be able to load same bpf program on different
	 * ifindex */
	len = snprintf(opts->pin_root_path, GTP_STR_MAX_LEN, "%s/%d"
					  , pin_basedir, opts->ifindex);
	if (len < 0) {
		log_message(LOG_INFO, "%s(): Error preparing eBPF pin_dir for ifindex:%d"
				    , __FUNCTION__
				    , opts->ifindex);
		return NULL;
	}

	if (len > GTP_STR_MAX_LEN) {
		log_message(LOG_INFO, "%s(): Error preparing eBPF pin_dir for ifindex:%d (path_too_long)"
				    , __FUNCTION__
				    , opts->ifindex);
		return NULL;
	}

	/* Load object */
	bpf_obj = gtp_bpf_load_file(opts);
	if (!bpf_obj)
		return NULL;

	/* Attach prog to interface */
	if (opts->progname[0]) {
		bpf_prog = bpf_object__find_program_by_name(bpf_obj, opts->progname);
		if (!bpf_prog) {
			log_message(LOG_INFO, "%s(): eBPF: unknown program:%s (fallback to first one)"
					    , __FUNCTION__
					    , opts->progname);
		}
	}

	if (!bpf_prog) {
		bpf_prog = bpf_object__next_program(bpf_obj, NULL);
		if (!bpf_prog) {
			log_message(LOG_INFO, "%s(): eBPF: no program found in file:%s"
					    , __FUNCTION__
					    , opts->filename);
			goto err;
		}
	}

	opts->bpf_obj = bpf_obj;
	return bpf_prog;

  err:
	bpf_object__close(bpf_obj);
	return NULL;
}


int
gtp_bpf_load(gtp_bpf_opts_t *opts)
{
	struct bpf_program *bpf_prog = NULL;
	struct bpf_link *bpf_lnk;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	/* Load eBPF prog */
	bpf_prog = gtp_bpf_load_prog(opts);
	if (!bpf_prog)
		return -1;

	/* Detach previously stalled XDP programm */
	err = bpf_xdp_detach(opts->ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant detach previous XDP programm (%s)"
				    , __FUNCTION__
				    , errmsg);
	}

	/* Attach XDP */
	bpf_lnk = bpf_program__attach_xdp(bpf_prog, opts->ifindex);
	if (!bpf_lnk) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): XDP: error attaching program:%s to ifindex:%d err:%d (%s)"
				    , __FUNCTION__
				    , bpf_program__name(bpf_prog)
				    , opts->ifindex
				    , errno, errmsg);
		goto err;
	}

	opts->bpf_lnk = bpf_lnk;
	return 0;

  err:
	return -1;
}

void
gtp_bpf_unload(gtp_bpf_opts_t *opts)
{
	if (opts->bpf_maps)
		FREE(opts->bpf_maps);
	bpf_link__destroy(opts->bpf_lnk);
	bpf_object__close(opts->bpf_obj);
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
