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

#include <btf.h>

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;

/* Forward declaration */
static gtp_bpf_prog_mode_t gtp_bpf_prog_tpl_str2mode(const char *name);


/*
 *	BPF Object variable update.
 *
 *  This only apply to global variables as present in .rodata section,
 *  without using generated skeleton from libbpf.
 *  They can be modified *only* before program is loaded into kernel.
 *  it should be the same for variables in .data or .bss sections.
 */

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
gtp_bpf_prog_obj_update_var(struct bpf_object *obj, const gtp_bpf_prog_var_t *consts)
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

static const gtp_bpf_prog_tpl_t *
gtp_bpf_prog_obj_get_mode(struct bpf_object *obj)
{
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	const gtp_bpf_prog_tpl_t *tpl;
	char buf[GTP_STR_MAX_LEN];
	void *data;
	int i;

	sec = _get_datasec_type(obj, ".rodata", &data);
	if (sec == NULL)
		return NULL;

	btf = bpf_object__btf(obj);
	secinfo = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++) {
		const struct btf_type *t = btf__type_by_id(btf, secinfo[i].type);
		const char *name = btf__name_by_offset(btf, t->name_off);
		if (strcmp(name, "_mode"))
			continue;
		memcpy(buf, data + secinfo[i].offset, secinfo[i].size);
		buf[secinfo[i].size - 1] = 0;
		tpl = gtp_bpf_prog_tpl_get(gtp_bpf_prog_tpl_str2mode(buf));
		if (tpl == NULL)
			log_message(LOG_INFO, "%s(): bpf program refers to "
				    "mode '%s', which is unknown !!!",
				    __FUNCTION__, name);
		return tpl;
	}

	log_message(LOG_INFO, "%s(): cannot find var '_mode' in DATASEC(mode) !!!",
		    __FUNCTION__);

	return NULL;
}



/*
 *	BPF helpers
 */
int
gtp_bpf_prog_attr_reset(gtp_bpf_prog_attr_t *attr)
{
	attr->lnk = NULL;
	attr->prog = NULL;
	return 0;
}

static int
gtp_bpf_qdisc_clsact_add(struct bpf_tc_hook *q_hook)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	bpf_tc_hook_destroy(q_hook);	/* Release previously stalled entry */
	err = bpf_tc_hook_create(q_hook);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant create TC_HOOK to ifindex:%d (%s)"
				    , __FUNCTION__
				    , q_hook->ifindex
				    , errmsg);
		return -1;
	}

	return 0;
}

static int
gtp_bpf_tc_filter_add(struct bpf_tc_hook *q_hook, enum bpf_tc_attach_point direction,
		      const struct bpf_program *bpf_prog)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 0,
			    .flags = BPF_TC_F_REPLACE);
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	q_hook->attach_point = direction;
	tc_opts.prog_fd = bpf_program__fd(bpf_prog);
	err = bpf_tc_attach(q_hook, &tc_opts);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant attach eBPF prog_fd:%d to ifindex:%d %s (%s)"
				    , __FUNCTION__
				    , tc_opts.prog_fd
				    , q_hook->ifindex
				    , (direction == BPF_TC_INGRESS) ? "ingress" : "egress"
				    , errmsg);
		return -1;
	}

	return 0;
}

void
gtp_bpf_prog_detach_tc(gtp_bpf_prog_t *p, gtp_interface_t *iface)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, q_hook, .ifindex = iface->ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	bpf_tc_hook_destroy(&q_hook);
}

int
gtp_bpf_prog_attach_tc(gtp_bpf_prog_t *p, gtp_interface_t *iface)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, q_hook, .ifindex = iface->ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	int err;

	/* TODO: Port this to new TCX interface so bpf_link will be used */

	/* Create Qdisc Clsact & attach {in,e}gress filters */
	err = gtp_bpf_qdisc_clsact_add(&q_hook);
	err = err ? : gtp_bpf_tc_filter_add(&q_hook, BPF_TC_INGRESS, p->bpf_prog);
	err = err ? : gtp_bpf_tc_filter_add(&q_hook, BPF_TC_EGRESS, p->bpf_prog);

	return err;
}

int
gtp_bpf_prog_detach_xdp(struct bpf_link *link)
{
	return bpf_link__destroy(link);
}

struct bpf_link *
gtp_bpf_prog_attach_xdp(gtp_bpf_prog_t *p, gtp_interface_t *iface)
{
	struct bpf_link *link;
	int ifindex = iface->ifindex;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	/* Detach previously stalled XDP programm */
	err = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant detach previous XDP program (%s)"
				    , __FUNCTION__
				    , errmsg);
	}

	/* Attach program to interface, let prog template know. */
	if (p->tpl->bind_itf != NULL && p->tpl->bind_itf(p, iface))
		return NULL;

	/* Load program, if not already */
	if (gtp_bpf_prog_load(p) < 0)
		return NULL;

	/* Attach XDP */
	link = bpf_program__attach_xdp(p->bpf_prog, ifindex);
	if (link)
		return link;

	libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
	log_message(LOG_INFO, "%s(): XDP: error attaching program:%s to ifindex:%d err:%d (%s)"
			    , __FUNCTION__
			    , bpf_program__name(p->bpf_prog)
			    , ifindex
			    , errno, errmsg);
	return NULL;
}

int
gtp_bpf_prog_open(gtp_bpf_prog_t *p)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	struct bpf_object *bpf_obj;
	const gtp_bpf_prog_tpl_t *t;

	/* Already opened */
	if (p->bpf_obj)
		return 0;

	/* Open eBPF file */
	bpf_obj = bpf_object__open(p->path);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error opening bpf file err:%d (%s)"
				    , errno, errmsg);
		return -1;
	}

	/* Get template mode, from const char *_mode */
	t = gtp_bpf_prog_obj_get_mode(bpf_obj);
	if (t == NULL) {
		bpf_object__close(bpf_obj);
		return -1;
	}

	/* Get default path/programe if not set */
	if (!*p->progname && *t->def_progname) {
		bsd_strlcpy(p->progname, t->def_progname,
			    GTP_STR_MAX_LEN - 1);
	}

	p->bpf_obj = bpf_obj;
	p->tpl = t;
	return 0;
}

static int
gtp_bpf_prog_set_type(gtp_bpf_prog_t *p)
{
	enum bpf_attach_type atype;

	atype = bpf_program__expected_attach_type(p->bpf_prog);
	if (atype == BPF_CGROUP_INET_INGRESS) {
		p->type = GTP_BPF_PROG_TYPE_TC;
	} else if (atype == BPF_XDP) {
		p->type = GTP_BPF_PROG_TYPE_XDP;
	} else {
		log_message(LOG_INFO, "%s(): eBPF: program type '%s' not supported"
				      " in file:%s"
				    , __FUNCTION__
				    , libbpf_bpf_attach_type_str(atype)
				    , p->path);
		return -1;
	}

	return 0;
}

int
gtp_bpf_prog_load(gtp_bpf_prog_t *p)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	/* Already loaded */
	if (p->bpf_prog)
		return 0;

	/* Open bpf file (if not done yet) */
	if (gtp_bpf_prog_open(p) < 0)
		return -1;

	if (p->tpl->opened != NULL && p->tpl->opened(p, p->bpf_obj))
		goto err;

	/* Finally load it */
	err = bpf_object__load(p->bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error loading bpf_object err:%d (%s)"
				    , err, errmsg);
		goto err;
	}

	if (p->tpl->loaded != NULL && p->tpl->loaded(p, p->bpf_obj))
		goto err;

	/* prog lookup */
	if (p->progname[0]) {
		p->bpf_prog = bpf_object__find_program_by_name(p->bpf_obj, p->progname);
		if (p->bpf_prog)
			return 0;
		log_message(LOG_INFO, "%s(): eBPF: unknown program:%s (fallback to first one)"
				    , __FUNCTION__
				    , p->progname);
	}
	p->bpf_prog = bpf_object__next_program(p->bpf_obj, NULL);
	if (!p->bpf_prog) {
		log_message(LOG_INFO, "%s(): eBPF: no program found in file:%s"
				    , __FUNCTION__
				    , p->path);
		goto err;
	}

	err = gtp_bpf_prog_set_type(p);
	if (!err)
		return 0;

 err:
	bpf_object__close(p->bpf_obj);
	p->bpf_obj = NULL;
	return -1;
}

void
gtp_bpf_prog_unload(gtp_bpf_prog_t *p)
{
	if (__sync_add_and_fetch(&p->refcnt, 0))
		return;

	FREE_PTR(p->bpf_maps);
	bpf_object__close(p->bpf_obj);
}

int
gtp_bpf_prog_destroy(gtp_bpf_prog_t *p)
{
	if (__sync_add_and_fetch(&p->refcnt, 0))
		return -1;

	gtp_bpf_prog_unload(p);
	list_head_del(&p->next);
	FREE(p);
	return 0;
}


/*
 *	BPF progs related
 */
void
gtp_bpf_prog_foreach_prog(int (*hdl) (gtp_bpf_prog_t *, void *), void *arg,
			  gtp_bpf_prog_mode_t filter_mode)
{
	gtp_bpf_prog_t *p;

	/* filter_mode == BPF_PROG_MODE_MAX means dump all */
	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		if (filter_mode == BPF_PROG_MODE_MAX ||
		    (filter_mode < BPF_PROG_MODE_MAX &&
		     p->tpl && filter_mode == p->tpl->mode)) {
			__sync_add_and_fetch(&p->refcnt, 1);
			(*(hdl)) (p, arg);
			__sync_sub_and_fetch(&p->refcnt, 1);
		}
	}
}

gtp_bpf_prog_t *
gtp_bpf_prog_get(const char *name)
{
	gtp_bpf_prog_t *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		if (!strncmp(p->name, name, strlen(name))) {
			__sync_add_and_fetch(&p->refcnt, 1);
			return p;
		}
	}

	return NULL;
}

int
gtp_bpf_prog_put(gtp_bpf_prog_t *p)
{
	__sync_sub_and_fetch(&p->refcnt, 1);
	return 0;
}

gtp_bpf_prog_t *
gtp_bpf_prog_alloc(const char *name)
{
	gtp_bpf_prog_t *new;

	PMALLOC(new);
	bsd_strlcpy(new->name, name, GTP_STR_MAX_LEN - 1);

	list_add_tail(&new->next, &daemon_data->bpf_progs);

	return new;
}

int
gtp_bpf_progs_destroy(void)
{
	list_head_t *l = &daemon_data->bpf_progs;
	gtp_bpf_prog_t *p, *_p;

	list_for_each_entry_safe(p, _p, l, next) {
		gtp_bpf_prog_unload(p);
		list_head_del(&p->next);
		FREE(p);
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

const char *
gtp_bpf_prog_tpl_mode2str(gtp_bpf_prog_mode_t mode)
{
	switch (mode) {
	case BPF_PROG_MODE_GTP_FORWARD:
		return "gtp_fwd";
	case BPF_PROG_MODE_GTP_ROUTE:
		return "gtp_route";
	case BPF_PROG_MODE_GTP_MIRROR:
		return "gtp_mirror";
	case BPF_PROG_MODE_CGN:
		return "cgn";
	case BPF_PROG_MODE_MAX:
		return NULL;
	}

	return NULL;
}

static gtp_bpf_prog_mode_t
gtp_bpf_prog_tpl_str2mode(const char *name)
{
	if (!strcmp(name, "gtp_fwd"))
		return BPF_PROG_MODE_GTP_FORWARD;
	else if (!strcmp(name, "gtp_route"))
		return BPF_PROG_MODE_GTP_ROUTE;
	else if (!strcmp(name, "gtp_mirror"))
		return BPF_PROG_MODE_GTP_MIRROR;
	else if (!strcmp(name, "cgn"))
		return BPF_PROG_MODE_CGN;

	return BPF_PROG_MODE_MAX;
}

void
gtp_bpf_prog_tpl_register(gtp_bpf_prog_tpl_t *tpl)
{
	list_add(&tpl->next, &bpf_prog_tpl_list);
}

const gtp_bpf_prog_tpl_t *
gtp_bpf_prog_tpl_get(gtp_bpf_prog_mode_t mode)
{
	gtp_bpf_prog_tpl_t *tpl;

	list_for_each_entry(tpl, &bpf_prog_tpl_list, next) {
		if (tpl->mode == mode)
			return tpl;
	}
	return NULL;
}
