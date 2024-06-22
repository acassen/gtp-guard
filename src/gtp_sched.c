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
#include <pthread.h>

/* local includes */
#include "gtp_guard.h"


/*
 *	Scheduling decision
 */
static gtp_pgw_t *
gtp_sched_pgw_wlc(gtp_naptr_t *naptr, struct sockaddr_in *addr_skip)
{
	uint64_t loh = 0, doh;
	gtp_pgw_t *pgw, *least = NULL;
	struct sockaddr_in *paddr;
	uint16_t priority = 0;

	/* Second stage: wlc over lower priority */
	list_for_each_entry(pgw, &naptr->pgw, next) {
		paddr = (struct sockaddr_in *) &pgw->addr;
		if (paddr->sin_addr.s_addr == addr_skip->sin_addr.s_addr)
			continue;

		/* first least priority init */
		if (!priority)
			priority = pgw->priority;

		/* weight=0 is quiesced and will not receive any connections */
		if (!pgw->weight)
			continue;

		/* Switching to next priority */
		if (!least && pgw->priority != priority)
			priority = pgw->priority;

		if (pgw->priority != priority)
			continue;

		doh = __sync_add_and_fetch(&pgw->cnt, 0);
		if (!doh) {
			least = pgw;
			break;
		}

		/* The comparison of h1*w2 > h2*w1 is equivalent to that of
		 * h1/w1 > h2/w2 */
		if (!least || doh*least->weight < loh*pgw->weight) {
			least = pgw;
			loh = doh;
		}
	}

	if (!least)
		return NULL;

	__sync_add_and_fetch(&least->cnt, 1);
	return least;
}

static gtp_pgw_t *
gtp_sched_naptr(list_head_t *l, const char *service, struct sockaddr_in *addr_skip)
{
	gtp_naptr_t *naptr, *least = NULL;
	gtp_pgw_t *pgw = NULL;

	/* First stage: Reset previous scheduling flags */
	list_for_each_entry(naptr, l, next)
		naptr->fl = 0;

	/* Second stage : Schedule by order until pgw election */
  shoot_again:
	list_for_each_entry(naptr, l, next) {
		if (!strstr(naptr->service, service) ||
		    __test_bit(GTP_SCHEDULE_FL_SKIP, &naptr->fl))
			continue;

		if (!least || naptr->order < least->order)
			least = naptr;
	}

	if (!least)
		return NULL;

	pgw = gtp_sched_pgw_wlc(least, addr_skip);
	if (!pgw) {
		__set_bit(GTP_SCHEDULE_FL_SKIP, &least->fl);
		least = NULL;
		/* Same player */
		goto shoot_again;
	}

	return pgw;
}

static int
gtp_sched_generic(gtp_apn_t *apn, list_head_t *l, struct sockaddr_in *addr, struct sockaddr_in *addr_skip)
{
	gtp_service_t *service;
	gtp_pgw_t *pgw = NULL;

	/* Service selection list is already sorted by prio */
	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry(service, &apn->service_selection, next) {
		pgw = gtp_sched_naptr(l, service->str, addr_skip);
		if (pgw) {
			*addr = *(struct sockaddr_in *) &pgw->addr;
			pthread_mutex_unlock(&apn->mutex);
			return 0;
		}
	}
	pthread_mutex_unlock(&apn->mutex);

	return -1;
}

int
gtp_sched(gtp_apn_t *apn, struct sockaddr_in *addr, struct sockaddr_in *addr_skip)
{
	return gtp_sched_generic(apn, &apn->naptr, addr, addr_skip);
}

int
gtp_sched_dynamic(gtp_apn_t *apn, const char *apn_name, const char *plmn, struct sockaddr_in *addr, struct sockaddr_in *addr_skip)
{
	gtp_resolv_ctx_t *ctx;
	list_head_t l;
	int err = 0;

	ctx = gtp_resolv_ctx_alloc(apn);
	if (!ctx)
		return -1;

	INIT_LIST_HEAD(&l);
	err = gtp_resolv_naptr(ctx, &l, "%s.apn.epc.%s.3gppnetwork.org.", apn_name, plmn);
	if (err) {
		log_message(LOG_INFO, "%s(): Unable to resolv apn:'%s.apn.epc.%s.3gppnetwork.org.'"
				    , __FUNCTION__, apn_name, plmn);
		goto end;
	}

	err = gtp_resolv_pgw(ctx, &l);
	if (err) {
		log_message(LOG_INFO, "%s(): Unable resolv pgw for apn:'%s.apn.epc.%s.3gppnetwork.org.'"
				    , __FUNCTION__, apn_name, plmn);
		goto end;
	}

	err = gtp_sched_generic(apn, &l, addr, addr_skip);

  end:
	gtp_resolv_ctx_destroy(ctx);
	gtp_naptr_destroy(&l);
	return err;
}