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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <errno.h>
#include <btf.h>
#include <linux/if_link.h>

#include "gtp_data.h"
#include "gtp_bpf.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "bitops.h"
#include "libbpf.h"
#include "logger.h"
#include "utils.h"
#include "memory.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	BPF Object variable update.
 *
 *  This only apply to global variables as present in .rodata section,
 *  without using generated skeleton from libbpf.
 *  They can be modified *only* before program is loaded into kernel.
 *  it should be the same for variables in .data or .bss sections.
 */


/*
 * split given buffer into array using delimiters, consecutive
 * delimiters occurence are merged
 * does *NOT* remove leading occurence of delimiter
 */
static void
split_line(char *buf, int *argc, char **argv, const char *delim,
	   int max_args)
{
	int scan;

	*argc = 1;
	argv[0] = buf;

	scan = 0;
	while (*buf) {
		if (!scan) {
			if (strchr(delim, *buf)) {
				*buf = 0;
				scan = 1;
			}
		} else {
			if (!strchr(delim, *buf)) {
				(*argc)++;
				argv[*argc - 1] = buf;
				scan = 0;

				if (*argc == max_args)
					return;
			}
		}
		buf++;
	}
}


static const struct btf_type *
_get_datasec_type(struct bpf_object *obj, const char *datasec_name, void **out_data)
{
	struct bpf_map *map;
	const char *name;

	name = datasec_name;
#if 0
	/* sometimes '.rodata' is called 'prgnam.rodata' ? */
	/* XXX: if it's the case, re-enable this code */
	bpf_object__for_each_map(map, obj) {
		if (strstr(bpf_map__name(map), datasec_name)) {
			name = bpf_map__name(map);
			break;
		}
	}
	if (!name) {
		log_message(LOG_INFO, "%s(): cant find DATASEC=%s !!!",
			    __FUNCTION__, datasec_name);
		errno = ENOENT;
		return NULL;
	}
#endif

	/* this open() subskeleton is only here to retrieve map's mmap address
	 * libbpf doesn't provide other way to get this address */
	struct bpf_map_skeleton ms[1] = { {
		.name = name,
		.map = &map,
		.mmaped = out_data,
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
		return NULL;
	}

	/* now use btf info to find this variable */
	struct btf *btf;
	const struct btf_type *sec;
	int sec_id;

	btf = bpf_object__btf(obj);
	if (btf == NULL) {
		log_message(LOG_INFO, "%s(): cant get BTF handler !!!", __FUNCTION__);
		errno = ENOENT;
		return NULL;
	}

	/* get secdata id */
	sec_id = btf__find_by_name(btf, datasec_name);
	if (sec_id < 0) {
		log_message(LOG_INFO, "%s(): cant get %s section !!!",
			    __FUNCTION__, datasec_name);
		errno = ENOENT;
		return NULL;
	}

	/* get the actual BTF type from the ID */
	sec = btf__type_by_id(btf, sec_id);
	if (sec == NULL) {
		log_message(LOG_INFO, "%s(): cant get BTF type from section ID !!!"
				    , __FUNCTION__);
		errno = ENOENT;
		return NULL;
	}

	return sec;
}


int
gtp_bpf_prog_obj_update_var(struct bpf_object *obj, const struct gtp_bpf_prog_var *consts)
{
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	void *rodata;
	int set = 0, to_be_set = 0;
	int i, j;

	sec = _get_datasec_type(obj, ".rodata", &rodata);
	if (sec == NULL)
		return -1;

	/* Get all secinfos, each of which will be a global variable */
	btf = bpf_object__btf(obj);
	secinfo = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++) {
		const struct btf_type *t = btf__type_by_id(btf, secinfo[i].type);
		const char *name = btf__name_by_offset(btf, t->name_off);
		for (j = 0; consts[j].name != NULL; j++) {
			if (!strcmp(name, consts[j].name)) {
				if (secinfo[i].size != consts[j].size) {
					log_message(LOG_INFO, "%s(): '%s' var size mismatch"
						    " (btf:%d, userapp:%d)"
						    , __FUNCTION__, name,
						    secinfo[i].size, consts[j].size);
					errno = EINVAL;
					return -1;
				}
				memcpy(rodata + secinfo[i].offset,
				       consts[j].value, consts[j].size);
				++set;
				break;
			}
		}
		if (consts[j].name == NULL)
			to_be_set = j;
	}

	if (set < to_be_set - 1) {
		log_message(LOG_INFO, "%s(): not all .rodata var set (%d/%d) !!!"
				, __FUNCTION__, set, to_be_set);
	}

	return 0;
}

static int
gtp_bpf_prog_obj_get_mode_list(struct bpf_object *obj, char **tpl_names)
{
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	char buf[GTP_STR_MAX_LEN];
	void *data;
	int i, argc;

	sec = _get_datasec_type(obj, ".rodata", &data);
	if (sec == NULL)
		return -1;

	btf = bpf_object__btf(obj);
	secinfo = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++) {
		const struct btf_type *t = btf__type_by_id(btf, secinfo[i].type);
		const char *name = btf__name_by_offset(btf, t->name_off);
		if (!strcmp(name, "_mode")) {
			memcpy(buf, data + secinfo[i].offset, secinfo[i].size);
			buf[secinfo[i].size - 1] = 0;
			split_line(buf, &argc, tpl_names, ",; ", BPF_PROG_TPL_MAX);
			return argc ?: -1;
		}
	}

	log_message(LOG_INFO, "%s(): cannot find var '_mode' in DATASEC(mode) !!!",
		    __FUNCTION__);

	return -1;
}



/*
 *	BPF helpers
 */

int
gtp_bpf_prog_open(struct gtp_bpf_prog *p)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	const struct gtp_bpf_prog_tpl *tpl;
	char *argv[BPF_PROG_TPL_MAX];
	int i, n;

	/* Already opened */
	if (p->bpf_obj)
		return 0;

	/* Open eBPF file */
	p->bpf_obj = bpf_object__open(p->path);
	if (!p->bpf_obj) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error opening bpf file err:%d (%s)"
				    , errno, errmsg);
		return -1;
	}

	/* Get template mode(s), from const char *_mode */
	n = gtp_bpf_prog_obj_get_mode_list(p->bpf_obj, argv);
	if (n < 0) {
		gtp_bpf_prog_unload(p);
		return -1;
	}
	for (i = 0; i < n; i++) {
		tpl = gtp_bpf_prog_tpl_get(argv[i]);
		if (tpl == NULL) {
			log_message(LOG_INFO, "%s(): bpf program refers to "
				    "mode '%s', which is unknown",
				    __FUNCTION__, argv[i]);
			gtp_bpf_prog_unload(p);
			return -1;
		}
		if (tpl->udata_alloc_size)
			p->tpl_data[i] = MALLOC(tpl->udata_alloc_size);
		p->tpl[i] = tpl;
		p->tpl_n = i;
	}
	p->tpl_n = n;

	return 0;
}

static inline int
gtp_bpf_assign_program(struct gtp_bpf_prog *p, struct bpf_program *prg,
		       const char *force_type, const char *path)
{
	enum bpf_attach_type atype;

	if (prg == NULL) {
		log_message(LOG_INFO, "eBPF'%s': %s program '%s' not found",
			    p->path, force_type, path);
		return -1;
	}

	atype = bpf_program__expected_attach_type(prg);
	switch (atype) {
	case BPF_CGROUP_INET_INGRESS:
		if (*force_type && strcmp(force_type, "tc")) {
			log_message(LOG_INFO, "eBPF'%s': wrong program '%s' type', "
				    "has:%s expect:tc", p->path, p->tc.progname,
				    libbpf_bpf_attach_type_str(atype));
			return -1;
		}
		if (p->tc.bpf_prg == NULL) {
			p->tc.bpf_prg = prg;
			log_message(LOG_DEBUG, "%s: tc program %s loaded, %d instructions",
				    p->path, bpf_program__name(prg),
				    bpf_program__insn_cnt(prg));
		}
		return 0;

	case BPF_XDP:
		if (*force_type && strcmp(force_type, "xdp")) {
			log_message(LOG_INFO, "eBPF'%s': wrong program '%s' type, "
				    "has:%s expect:xdp", p->path, p->xdp.progname,
				    libbpf_bpf_attach_type_str(atype));
			return -1;
		}
		if (p->xdp.bpf_prg == NULL) {
			p->xdp.bpf_prg = prg;
			log_message(LOG_DEBUG, "%s: xdp program %s loaded, %d instructions",
				    p->path, bpf_program__name(prg),
				    bpf_program__insn_cnt(prg));
		}
		return 0;

	default:
		if (*force_type) {
			log_message(LOG_INFO, "eBPF'%s': program type '%s' not supported",
				    p->path, libbpf_bpf_attach_type_str(atype));
			return -1;
		}
		return 0;
	}
}

int
gtp_bpf_prog_load(struct gtp_bpf_prog *p)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	struct bpf_program *bpf_prg;
	int i, err;

	/* Already loaded */
	if (p->tc.bpf_prg || p->xdp.bpf_prg)
		return 0;

	/* Already attempted */
	if (__test_bit(GTP_BPF_PROG_FL_ERR_BIT, &p->flags))
		return -1;

	/* Open bpf file (if not done yet) */
	if (gtp_bpf_prog_open(p) < 0)
		return -1;

	for (i = 0; i < p->tpl_n; i++) {
		if (p->tpl[i]->opened != NULL && p->tpl[i]->opened(p, p->tpl_data[i]))
			goto err;
	}

	/* Finally load it (kernel runs verifier) */
	err = bpf_object__load(p->bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error loading bpf_object err:%d (%s)"
				    , err, errmsg);
		goto err;
	}

	for (i = 0; i < p->tpl_n; i++) {
		if (p->tpl[i]->loaded != NULL && p->tpl[i]->loaded(p, p->tpl_data[i]))
			goto err;
	}

	/* Explicit program lookup */
	if (p->xdp.progname[0]) {
		bpf_prg = bpf_object__find_program_by_name(p->bpf_obj, p->xdp.progname);
		if (gtp_bpf_assign_program(p, bpf_prg, "xdp", p->xdp.progname) < 0)
			goto err;
	}
	if (p->tc.progname[0]) {
		bpf_prg = bpf_object__find_program_by_name(p->bpf_obj, p->tc.progname);
		if (gtp_bpf_assign_program(p, bpf_prg, "tc", p->tc.progname) < 0)
			goto err;
	}

	/* If progname is not specified, use first program the object contains */
	bpf_object__for_each_program(bpf_prg, p->bpf_obj) {
		gtp_bpf_assign_program(p, bpf_prg, "", NULL);
	}

	/* Must have at least one program */
	if (!p->tc.bpf_prg && !p->xdp.bpf_prg)
		goto err;

	return 0;

 err:
	gtp_bpf_prog_unload(p);
	__set_bit(GTP_BPF_PROG_FL_ERR_BIT, &p->flags);
	return -1;
}

int
gtp_bpf_prog_attach(struct gtp_bpf_prog *p, struct gtp_interface *iface)
{
	int ifindex = iface->ifindex;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int i;

	/* Before attaching program to interface (program may not yet be loaded) */
	for (i = 0; i < p->tpl_n; i++)
		if (p->tpl[i]->iface_bind != NULL &&
		    p->tpl[i]->iface_bind(p, p->tpl_data[i], iface))
			return -1;

	/* Load program, if not already */
	if (gtp_bpf_prog_load(p) < 0)
		return -1;

	/* Attach XDP */
	if (p->xdp.bpf_prg != NULL) {
		iface->bpf_xdp_lnk = bpf_program__attach_xdp(p->xdp.bpf_prg, ifindex);
		if (!iface->bpf_xdp_lnk) {
			libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
			log_message(LOG_INFO,
				    "%s(): XDP: error attaching program:%s "
				    "to ifindex:%d err:%d (%s)"
				    , __FUNCTION__
				    , bpf_program__name(p->xdp.bpf_prg)
				    , ifindex
				    , errno, errmsg);
			return -1;
		}
	}

	/* Attach TCX */
	if (p->tc.bpf_prg != NULL) {
		DECLARE_LIBBPF_OPTS(bpf_tcx_opts, opts);
		iface->bpf_tc_lnk = bpf_program__attach_tcx(p->tc.bpf_prg, ifindex, &opts);
		if (!iface->bpf_tc_lnk) {
			libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
			log_message(LOG_INFO,
				    "%s(): TCX: error attaching program:%s "
				    "to ifindex:%d err:%d (%s)"
				    , __FUNCTION__
				    , bpf_program__name(p->tc.bpf_prg)
				    , ifindex
				    , errno, errmsg);
			if (iface->bpf_xdp_lnk != NULL) {
				bpf_link__detach(iface->bpf_xdp_lnk);
				iface->bpf_xdp_lnk = NULL;
			}
			return -1;
		}
	}

	/* After program attach to interface. */
	for (i = 0; i < p->tpl_n; i++)
		if (p->tpl[i]->iface_bound != NULL &&
		    p->tpl[i]->iface_bound(p, p->tpl_data[i], iface))
			return -1;

	return 0;
}

void
gtp_bpf_prog_detach(struct gtp_bpf_prog *p, struct gtp_interface *iface)
{
	int i;

	/* Detach program from interface */
	for (i = 0; i < p->tpl_n; i++)
		if (p->tpl[i]->iface_unbind != NULL)
			p->tpl[i]->iface_unbind(p, p->tpl_data[i], iface);

	if (iface->bpf_xdp_lnk != NULL) {
		bpf_link__destroy(iface->bpf_xdp_lnk);
		iface->bpf_xdp_lnk = NULL;
	}
	if (iface->bpf_tc_lnk != NULL) {
		bpf_link__destroy(iface->bpf_tc_lnk);
		iface->bpf_tc_lnk = NULL;
	}
}

void
gtp_bpf_prog_unload(struct gtp_bpf_prog *p)
{
	int i;

	for (i = 0; i < p->tpl_n; i++) {
		if (p->tpl[i]->udata_alloc_size)
			free(p->tpl_data[i]);
	}
	p->tc.bpf_prg = NULL;
	p->xdp.bpf_prg = NULL;
	if (p->bpf_obj != NULL)
		bpf_object__close(p->bpf_obj);
	p->bpf_obj = NULL;
	p->tpl_n = 0;
}

int
gtp_bpf_prog_destroy(struct gtp_bpf_prog *p)
{
	gtp_bpf_prog_unload(p);
	list_head_del(&p->next);
	FREE(p);
	return 0;
}

int
gtp_bpf_prog_tpl_data_set(struct gtp_bpf_prog *p, const char *tpl_name, void *udata)
{
	int i;

	for (i = 0; i < p->tpl_n; i++)
		if (!p->tpl[i]->udata_alloc_size &&
		    !strcmp(p->tpl[i]->name, tpl_name)) {
			p->tpl_data[i] = udata;
			return 0;
		}

	return -1;
}


/*
 *	BPF progs related
 */
void
gtp_bpf_prog_foreach_prog(int (*hdl) (struct gtp_bpf_prog *, void *), void *arg,
			  const char *filter_mode)
{
	struct gtp_bpf_prog *p;

	/* filter_mode == NULL means dump all */
	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		if (filter_mode == NULL ||
		    gtp_bpf_prog_has_tpl_mode(p, filter_mode)) {
			__sync_add_and_fetch(&p->refcnt, 1);
			(*(hdl)) (p, arg);
			__sync_sub_and_fetch(&p->refcnt, 1);
		}
	}
}

struct gtp_bpf_prog *
gtp_bpf_prog_get(const char *name)
{
	struct gtp_bpf_prog *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		if (!strncmp(p->name, name, strlen(name))) {
			__sync_add_and_fetch(&p->refcnt, 1);
			return p;
		}
	}

	return NULL;
}

int
gtp_bpf_prog_put(struct gtp_bpf_prog *p)
{
	__sync_sub_and_fetch(&p->refcnt, 1);
	return 0;
}

struct gtp_bpf_prog *
gtp_bpf_prog_alloc(const char *name)
{
	struct gtp_bpf_prog *new;

	PMALLOC(new);
	bsd_strlcpy(new->name, name, GTP_STR_MAX_LEN - 1);

	list_add_tail(&new->next, &daemon_data->bpf_progs);

	return new;
}

int
gtp_bpf_progs_destroy(void)
{
	struct list_head *l = &daemon_data->bpf_progs;
	struct gtp_bpf_prog *p, *_p;

	list_for_each_entry_safe(p, _p, l, next) {
		gtp_bpf_prog_destroy(p);
	}
	return 0;
}



/*
 *	BPF progs template.
 *
 * each module handling bpf program (eg. gtp_fwd, cgn, ...) registers itself
 * with its specific callbacks.
 *
 * then, a bpf program will be attached to a bpf program template.
 * vty's mode-* command does it.
 */


/* local data */
static LIST_HEAD(bpf_prog_tpl_list);

void
gtp_bpf_prog_tpl_register(struct gtp_bpf_prog_tpl *tpl)
{
	list_add(&tpl->next, &bpf_prog_tpl_list);
}

const struct gtp_bpf_prog_tpl *
gtp_bpf_prog_tpl_get(const char *name)
{
	struct gtp_bpf_prog_tpl *tpl;

	list_for_each_entry(tpl, &bpf_prog_tpl_list, next) {
		if (!strcmp(tpl->name, name))
			return tpl;
	}
	return NULL;
}
