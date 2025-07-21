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

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	BPF helpers
 */
int
gtp_bpf_prog_detach(struct bpf_link *link)
{
	return bpf_link__destroy(link);
}

struct bpf_link *
gtp_bpf_prog_attach(gtp_bpf_prog_t *p, int ifindex)
{
	struct bpf_link *link;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	/* Detach previously stalled XDP programm */
	err = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant detach previous XDP programm (%s)"
				    , __FUNCTION__
				    , errmsg);
	}

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

static struct bpf_object *
gtp_bpf_prog_load_file(gtp_bpf_prog_t *p)
{
	struct bpf_object *bpf_obj;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err;

	/* open eBPF file */
	bpf_obj = bpf_object__open(p->path);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error opening bpf file err:%d (%s)"
				    , errno, errmsg);
		return NULL;
	}

	if (p->tpl->opened != NULL)
		p->tpl->opened(p, bpf_obj);

	/* Global vars update */
	gtp_bpf_obj_update_global_vars(bpf_obj);

	/* Finally load it */
	err = bpf_object__load(bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error loading bpf_object err:%d (%s)"
				    , err, errmsg);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	if (p->tpl->loaded != NULL)
		p->tpl->loaded(p, bpf_obj);

	return bpf_obj;
}

int
gtp_bpf_prog_load(gtp_bpf_prog_t *p)
{
	struct bpf_program *bpf_prog = NULL;
	struct bpf_object *bpf_obj;

	/* Already loaded */
	if (p->bpf_prog)
		return 0;

	/* a template MUST be attached */
	if (p->tpl == NULL)
		return -1;

	/* get default path/programe if not set */
	if (!*p->path && *p->tpl->def_path) {
		bsd_strlcpy(p->path, p->tpl->def_path,
			    GTP_PATH_MAX_LEN - 1);
	}
	if (!*p->progname && *p->tpl->def_progname) {
		bsd_strlcpy(p->progname, p->tpl->def_progname,
			    GTP_STR_MAX_LEN - 1);
	}

	/* Load object */
	bpf_obj = gtp_bpf_prog_load_file(p);
	if (!bpf_obj)
		return -1;

	/* prog lookup */
	if (p->progname[0]) {
		bpf_prog = bpf_object__find_program_by_name(bpf_obj, p->progname);
		if (!bpf_prog) {
			log_message(LOG_INFO, "%s(): eBPF: unknown program:%s (fallback to first one)"
					    , __FUNCTION__
					    , p->progname);
		}
	}

	if (bpf_prog)
		goto end;

	bpf_prog = bpf_object__next_program(bpf_obj, NULL);
	if (!bpf_prog) {
		log_message(LOG_INFO, "%s(): eBPF: no program found in file:%s"
				    , __FUNCTION__
				    , p->path);
		bpf_object__close(bpf_obj);
		return -1;
	}

  end:
	p->bpf_obj = bpf_obj;
	p->bpf_prog = bpf_prog;
	return 0;
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
gtp_bpf_prog_foreach_prog(int (*hdl) (gtp_bpf_prog_t *, void *), void *arg)
{
	gtp_bpf_prog_t *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		__sync_add_and_fetch(&p->refcnt, 1);
		(*(hdl)) (p, arg);
		__sync_sub_and_fetch(&p->refcnt, 1);
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
gtp_bpf_prog_tpl_mode2str(const gtp_bpf_prog_tpl_t *tpl)
{
	switch (tpl->mode) {
	case GTP_FORWARD:
		return "mode-gtp-forward";
	case GTP_ROUTE:
		return "mode-gtp-route";
	case CGN:
		return "mode-cgn";
	}

	return NULL;
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
