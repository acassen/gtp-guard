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

/* system includes */
#include <pthread.h>
#include <sys/stat.h>

/* local includes */
#include "bitops.h"
#include "memory.h"
#include "utils.h"
#include "timer.h"
#include "mpool.h"
#include "vector.h"
#include "list_head.h"
#include "json_writer.h"
#include "vty.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_xdp.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	Mirroring rules
 */

gtp_mirror_rule_t *
gtp_mirror_rule_get(const struct sockaddr_storage *addr, uint8_t protocol, int ifindex)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r;

	list_for_each_entry(r, l, next) {
		if (sockstorage_equal(addr, &r->addr) &&
		    r->protocol == protocol &&
		    r->ifindex == ifindex) {
			return r;
		}
	}

	return NULL;
}


gtp_mirror_rule_t *
gtp_mirror_rule_add(const struct sockaddr_storage *addr, uint8_t protocol, int ifindex)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r;

	PMALLOC(r);
	r->addr = *addr;
	r->protocol = protocol;
	r->ifindex = ifindex;
	INIT_LIST_HEAD(&r->next);

	list_add_tail(&r->next, l);

	return r;
}

void
gtp_mirror_rule_del(gtp_mirror_rule_t *r)
{
	list_head_del(&r->next);
}

static int
gtp_mirror_destroy(void)
{
	list_head_t *l = &daemon_data->mirror_rules;
	gtp_mirror_rule_t *r, *_r;

	list_for_each_entry_safe(r, _r, l, next) {
		list_head_del(&r->next);
		FREE(r);
	}

	return 0;
}


/*
 *	Daemon Control Block helpers
 */
data_t *
alloc_daemon_data(void)
{
	data_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->gtp_apn);
	INIT_LIST_HEAD(&new->gtp_ctx);
	INIT_LIST_HEAD(&new->mirror_rules);

	return new;
}

void
free_daemon_data(void)
{
	if (__test_bit(GTP_FL_GTPU_LOADED_BIT, &daemon_data->flags))
		gtp_xdp_fwd_unload(&daemon_data->xdp_gtpu);
	if (__test_bit(GTP_FL_MIRROR_LOADED_BIT, &daemon_data->flags))
		gtp_xdp_mirror_unload(&daemon_data->xdp_mirror);
	gtp_mirror_destroy();
	gtp_apn_destroy();
	gtp_switch_destroy();
	FREE(daemon_data);
}

