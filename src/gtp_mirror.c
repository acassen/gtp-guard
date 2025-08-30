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

#include "gtp_data.h"
#include "gtp_mirror.h"
#include "gtp_bpf.h"
#include "gtp_bpf_mirror.h"
#include "addr.h"
#include "memory.h"
#include "bitops.h"
#include "utils.h"

/* Extern data */
extern data_t *daemon_data;

/*
 *	Rules helpers
 */
gtp_mirror_rule_t *
gtp_mirror_rule_get(gtp_mirror_t *m, const struct sockaddr_storage *addr,
		    uint8_t protocol, int ifindex)
{
	list_head_t *l = &m->rules;
	gtp_mirror_rule_t *r;

	list_for_each_entry(r, l, next) {
		if (!ss_cmp(addr, &r->addr) &&
		    r->protocol == protocol &&
		    r->ifindex == ifindex) {
			return r;
		}
	}

	return NULL;
}

gtp_mirror_rule_t *
gtp_mirror_rule_add(gtp_mirror_t *m, const struct sockaddr_storage *addr,
		    uint8_t protocol, int ifindex)
{
	list_head_t *l = &m->rules;
	gtp_mirror_rule_t *r;

	PMALLOC(r);
	INIT_LIST_HEAD(&r->next);
	r->addr = *addr;
	r->protocol = protocol;
	r->ifindex = ifindex;

	list_add_tail(&r->next, l);

	return r;
}

void
gtp_mirror_rule_del(gtp_mirror_rule_t *r)
{
	list_head_del(&r->next);
}

static void
gtp_mirror_action(gtp_mirror_t *m, int action, int ifindex)
{
	list_head_t *l = &m->rules;
	gtp_mirror_rule_t *r;

	list_for_each_entry(r, l, next) {
		if (r->ifindex != ifindex)
			continue;

		gtp_bpf_mirror_action(action, r, m->bpf_prog);
	}
}

void
gtp_mirror_brd_action(int action, int ifindex)
{
	list_head_t *l = &daemon_data->mirror;
	gtp_mirror_t *m;

	list_for_each_entry(m, l, next) {
		__sync_add_and_fetch(&m->refcnt, 1);
		gtp_mirror_action(m, action, ifindex);
		__sync_sub_and_fetch(&m->refcnt, 1);
	}
}

static void
gtp_mirror_action_bpf(gtp_mirror_t *m, int action)
{
	list_head_t *l = &m->rules;
	gtp_mirror_rule_t *r;

	list_for_each_entry(r, l, next) {
		gtp_bpf_mirror_action(action, r, m->bpf_prog);
	}
}

void
gtp_mirror_load_bpf(gtp_mirror_t *m)
{
	gtp_mirror_action_bpf(m, RULE_ADD);
}

void
gtp_mirror_unload_bpf(gtp_mirror_t *m)
{
	gtp_mirror_action_bpf(m, RULE_DEL);
}

/*
 *	Mirror helpers
 */
void
gtp_mirror_foreach(int (*hdl) (gtp_mirror_t *, void *), void *arg)
{
	list_head_t *l = &daemon_data->mirror;
	gtp_mirror_t *m;

	list_for_each_entry(m, l, next) {
		__sync_add_and_fetch(&m->refcnt, 1);
		(*(hdl)) (m, arg);
		__sync_sub_and_fetch(&m->refcnt, 1);
	}
}

gtp_mirror_t *
gtp_mirror_get(const char *name)
{
	list_head_t *l = &daemon_data->mirror;
	gtp_mirror_t *m;

	list_for_each_entry(m, l, next) {
		if (!strncmp(m->name, name, strlen(name))) {
			__sync_add_and_fetch(&m->refcnt, 1);
			return m;
		}
	}

	return NULL;
}

int
gtp_mirror_put(gtp_mirror_t *m)
{
	__sync_sub_and_fetch(&m->refcnt, 1);
	return 0;
}

gtp_mirror_t *
gtp_mirror_alloc(const char *name)
{
	gtp_mirror_t *new;

	PMALLOC(new);
	if (!new)
		return NULL;

	INIT_LIST_HEAD(&new->rules);
	INIT_LIST_HEAD(&new->next);
	if (name)
		bsd_strlcpy(new->name, name, GTP_STR_MAX_LEN - 1);
	__set_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &new->flags);

	list_add_tail(&new->next, &daemon_data->mirror);
	__sync_add_and_fetch(&new->refcnt, 1);

	return new;
}

int
__gtp_mirror_destroy(gtp_mirror_t *m)
{
	gtp_mirror_rule_t *r, *_r;
	list_head_t *l = &m->rules;

	list_for_each_entry_safe(r, _r, l, next) {
		list_head_del(&r->next);
		FREE(r);
	}

	list_head_del(&m->next);
	FREE(m);
	return 0;
}

int
gtp_mirror_destroy(gtp_mirror_t *m)
{
	__gtp_mirror_destroy(m);
	return 0;
}

int
gtp_mirrors_destroy(void)
{
	list_head_t *l = &daemon_data->mirror;
	gtp_mirror_t *m, *_m;

	list_for_each_entry_safe(m, _m, l, next)
		__gtp_mirror_destroy(m);
	return 0;
}
