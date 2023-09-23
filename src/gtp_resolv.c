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
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netdb.h>
#include <resolv.h>
#include <errno.h>

/* local includes */
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "timer.h"
#include "mpool.h"
#include "vector.h"
#include "command.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "list_head.h"
#include "json_writer.h"
#include "jhash.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_utils.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

cmd_node_t apn_node = {
	APN_NODE,
	"%s(gtp-apn)# ",
	1,
};


/* Local data */
pthread_mutex_t gtp_apn_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 *	Loadbalancing decision
 */
static int
gtp_resolv_pgw_lc(gtp_naptr_t *naptr, struct sockaddr_in *addr, struct sockaddr_in *addr_skip)
{
	uint32_t loh = 0, doh;
	gtp_pgw_t *pgw, *least = NULL;
	struct sockaddr_in *paddr;

	if (!naptr)
		return -1;

	list_for_each_entry(pgw, &naptr->pgw, next) {
		paddr = (struct sockaddr_in *) &pgw->addr;
		if (paddr->sin_addr.s_addr == addr_skip->sin_addr.s_addr)
			continue;

		doh = __sync_add_and_fetch(&pgw->cnt, 0);
		if (!doh) {
			least = pgw;
			break;
		}

		if (!least || doh < loh) {
			least = pgw;
			loh = doh;
		}
	}

	if (!least)
		return -1;

	__sync_add_and_fetch(&least->cnt, 1);
	*addr = *(struct sockaddr_in *) &least->addr;
	return 0;
}

int
gtp_resolv_schedule_pgw(gtp_apn_t *apn, struct sockaddr_in *addr, struct sockaddr_in *addr_skip)
{
	gtp_service_t *service, *least = NULL;
	int ret = 0;

	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry(service, &apn->service_selection, next) {
		if (!service->naptr)
			continue;

		/* lower prio means high priority */
		if (!least || service->prio < least->prio)
			least = service;
	}

	if (!least) {
		pthread_mutex_unlock(&apn->mutex);
		return -1;
	}

	ret = gtp_resolv_pgw_lc(least->naptr, addr, addr_skip);
	pthread_mutex_unlock(&apn->mutex);
	return ret;
}

/*
 *	APN resolver
 */
static size_t
ns_srvname_offset(char *buffer, size_t size)
{
	const char *cp = buffer + size;
	size_t offset = 0;

	for (cp = buffer + size; !isspace(*cp); cp--)
		offset++;
	return strlen(buffer) - offset + 1;
}

static void
ns_log_error(const char *dn, int error)
{
	switch(error) {
	case HOST_NOT_FOUND:
		log_message(LOG_INFO, "resolv[%s]: unknown zone", dn);
		break;
	case TRY_AGAIN:
		log_message(LOG_INFO, "resolv[%s]: No response for NS query", dn);
		break;
	case NO_RECOVERY:
		log_message(LOG_INFO, "resolv[%s]: Unrecoverable error", dn);
		break;
	case NO_DATA:
		log_message(LOG_INFO, "resolv[%s]: No NS records", dn);
		break;
	default:
		log_message(LOG_INFO, "resolv[%s]: Unexpected error", dn);
	}
}

static int
ns_res_nquery_retry(gtp_apn_t *apn, res_state statep, const char *dname, int class, int type,
		    unsigned char *answer, int anslen)
{
	int retry_count = 0;
	int ret;

retry:
	ret = res_nquery(statep, dname, class, type, answer, GTP_RESOLV_BUFFER_LEN);
	if (ret < 0) {
		ns_log_error(dname, h_errno);
		if (h_errno == TRY_AGAIN && retry_count++ < apn->resolv_max_retry) {
			log_message(LOG_INFO, "resolv[%s]: retry #%d", dname, retry_count);
			goto retry;
		}
	}

	return ret;
}

static int
gtp_naptr_parse_server_type(gtp_naptr_t *naptr, char *buffer, size_t size)
{
	const char *end = buffer + size;
	const char *cp;

	for (cp = buffer; cp < end; cp++) {
		/* First column match Server type */
		if (*cp == '"') {
			if (*(cp+1) == 'S')
				naptr->server_type = ns_t_srv;
			if (*(cp+1) == 'A')
				naptr->server_type = ns_t_a;
			return 0;
		}
	}

	return 0;
}

static int
gtp_naptr_parse_service(gtp_naptr_t *naptr, char *buffer, size_t size)
{
	const char *end = buffer + size;
	const char *cp;
	int match = 0, i = 0;

	for (cp = buffer; cp < end; cp++) {
		/* Third column match Server type */
		if (*cp == '"' && ++match == 3) {
			for (++cp; cp < end && *cp !='"'; cp++)
				naptr->service[i++] = *cp;
			return 0;
		}
	}

	return 0;
}

static int
gtp_pgw_set(gtp_pgw_t *pgw, char *buffer, size_t size)
{
	inet_stosockaddr(buffer, "2123", &pgw->addr);
	return 0;
}

static int
gtp_resolv_srv_a(gtp_pgw_t *pgw)
{
	struct __res_state ns_rs;
	gtp_naptr_t *naptr = pgw->naptr;
	gtp_apn_t *apn = naptr->apn;
	int ret, i, err;
	ns_msg msg;
	ns_rr rr;
	size_t offset;
	struct sockaddr_storage *nsaddr;

	/* Name Server selection */
	nsaddr = (apn->nameserver.ss_family) ? &apn->nameserver : &daemon_data->nameserver;
	if (!nsaddr->ss_family) {
		log_message(LOG_INFO, "%s(): No nameserver configured... Ignoring..."
				    , __FUNCTION__);
		return -1;
	}

	/* Context init */
	res_ninit(&ns_rs);
	ns_rs.nsaddr_list[0] = *((struct sockaddr_in *) nsaddr);
	ns_rs.nscount = 1;

	/* Perform Query */
	snprintf(apn->nsdisp, GTP_DISPLAY_BUFFER_LEN - 1, "%s", pgw->srv_name);
	ret = ns_res_nquery_retry(apn, &ns_rs, apn->nsdisp, ns_c_in, ns_t_a,
				  apn->nsbuffer, GTP_RESOLV_BUFFER_LEN);
	if (ret < 0) {
		res_nclose(&ns_rs);
		return -1;
	}

	ns_initparse(apn->nsbuffer, ret, &msg);
	ret = ns_msg_count(msg, ns_s_an);
	for (i = 0; i < ret; i++) {
		err = ns_parserr(&msg, ns_s_an, i, &rr);
		if (err < 0)
			continue;

		/* That is crappy here, but anyway resolver perform
		 * string stuff and dont need to expand code from ns_print.
		 */
		memset(apn->nsdisp, 0, GTP_DISPLAY_BUFFER_LEN);
		ns_sprintrr(&msg, &rr, NULL, NULL, apn->nsdisp, GTP_DISPLAY_BUFFER_LEN);
                offset = ns_srvname_offset(apn->nsdisp, strlen(apn->nsdisp));
		gtp_pgw_set(pgw, apn->nsdisp+offset, strlen(apn->nsdisp)-offset);
        }

	/* Context release */
	res_nclose(&ns_rs);
	return 0;
}

static int
gtp_resolv_pgw_srv(gtp_naptr_t *naptr)
{
	gtp_pgw_t *pgw;

	list_for_each_entry(pgw, &naptr->pgw, next) {
		gtp_resolv_srv_a(pgw);
	}

	return 0;
}


static int
gtp_pgw_append(gtp_naptr_t *naptr, char *buffer, size_t size)
{
	gtp_pgw_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->naptr = naptr;
	strncpy(new->srv_name, buffer, size);
	list_add_tail(&new->next, &naptr->pgw);

	return 0;
}

static int
gtp_resolv_naptr_srv(gtp_naptr_t *naptr)
{
	struct __res_state ns_rs;
	gtp_apn_t *apn = naptr->apn;
	int ret, i, err;
	ns_msg msg;
	ns_rr rr;
	size_t offset;
	struct sockaddr_storage *nsaddr;

	/* Name Server selection */
	nsaddr = (apn->nameserver.ss_family) ? &apn->nameserver : &daemon_data->nameserver;
	if (!nsaddr->ss_family) {
		log_message(LOG_INFO, "%s(): No nameserver configured... Ignoring..."
				    , __FUNCTION__);
		return -1;
	}

	/* Context init */
	res_ninit(&ns_rs);
	ns_rs.nsaddr_list[0] = *((struct sockaddr_in *) nsaddr);
	ns_rs.nscount = 1;

	/* Perform Query */
	snprintf(apn->nsdisp, GTP_DISPLAY_BUFFER_LEN - 1, "%s", naptr->server);
	ret = ns_res_nquery_retry(apn, &ns_rs, apn->nsdisp, ns_c_in, ns_t_srv,
				  apn->nsbuffer, GTP_RESOLV_BUFFER_LEN);
        if (ret < 0) {
		res_nclose(&ns_rs);
		return -1;
	}

        ns_initparse(apn->nsbuffer, ret, &msg);
        ret = ns_msg_count(msg, ns_s_an);
        for (i = 0; i < ret; i++) {
                err = ns_parserr(&msg, ns_s_an, i, &rr);
		if (err < 0)
			continue;

		/* That is crappy here, by anyway resolver perform
		 * string stuff and dont need to expand code from ns_print.
		 */
		memset(apn->nsdisp, 0, GTP_DISPLAY_BUFFER_LEN);
		ns_sprintrr(&msg, &rr, NULL, NULL, apn->nsdisp, GTP_DISPLAY_BUFFER_LEN);
                offset = ns_srvname_offset(apn->nsdisp, strlen(apn->nsdisp));
		gtp_pgw_append(naptr, apn->nsdisp+offset, strlen(apn->nsdisp)-offset);
        }

	/* Context release */
	res_nclose(&ns_rs);
	return 0;
}

static int
gtp_resolv_pgw(gtp_apn_t *apn, list_head_t *l)
{
	gtp_naptr_t *naptr;
	int ret;

	list_for_each_entry(naptr, l, next) {
		if (naptr->server_type == ns_t_srv) {
			ret = gtp_resolv_naptr_srv(naptr);
			if (ret < 0)
				return -1;

			ret = gtp_resolv_pgw_srv(naptr);
			if (ret < 0)
				return -1;
			continue;
		}

		if (naptr->server_type == ns_t_a) {
			gtp_pgw_append(naptr, naptr->server, strlen(naptr->server));
			ret = gtp_resolv_pgw_srv(naptr);
			if (ret < 0)
				return -1;
		}
	}

	return 0;
}


static gtp_naptr_t *
gtp_naptr_alloc(gtp_apn_t *apn, list_head_t *l, char *buffer, size_t size)
{
	gtp_naptr_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->pgw);
	INIT_LIST_HEAD(&new->next);
	new->apn = apn;
	strncpy(new->server, buffer, size);
	list_add_tail(&new->next, l);

	return new;
}


static int
gtp_resolv_naptr(gtp_apn_t *apn, list_head_t *l)
{
	gtp_naptr_t *naptr;
	struct __res_state ns_rs;
	int ret, i, err;
	ns_msg msg;
	ns_rr rr;
	size_t offset;
	char *realm;
	struct sockaddr_storage *nsaddr;

	/* Name Server selection */
	nsaddr = (apn->nameserver.ss_family) ? &apn->nameserver : &daemon_data->nameserver;
	if (!nsaddr->ss_family) {
		log_message(LOG_INFO, "%s(): No nameserver configured... Ignoring..."
				    , __FUNCTION__);
		return -1;
	}

	/* Context init */
	res_ninit(&ns_rs);
	ns_rs.nsaddr_list[0] = *((struct sockaddr_in *) nsaddr);
	ns_rs.nscount = 1;

	/* Perform Query */
	realm = (strlen(apn->realm)) ? apn->realm : daemon_data->realm;
	if (!strlen(realm)) {
		log_message(LOG_INFO, "%s(): No Realm configured... Ignoring..."
				    , __FUNCTION__);
		return -1;
	}

	snprintf(apn->nsdisp, GTP_DISPLAY_BUFFER_LEN - 1, "%s.%s", apn->name, realm);
	ret = ns_res_nquery_retry(apn, &ns_rs, apn->nsdisp, ns_c_in, ns_t_naptr,
				  apn->nsbuffer, GTP_RESOLV_BUFFER_LEN);
	if (ret < 0) {
		res_nclose(&ns_rs);
		return -1;
	}

        ns_initparse(apn->nsbuffer, ret, &msg);
        ret = ns_msg_count(msg, ns_s_an);
        for (i = 0; i < ret; i++) {
                err = ns_parserr(&msg, ns_s_an, i, &rr);
		if (err < 0)
			continue;

		/* That is crappy here, but anyway resolver perform
		 * string stuff and dont need to expand code from ns_print.
		 */
		memset(apn->nsdisp, 0, GTP_DISPLAY_BUFFER_LEN);
		ns_sprintrr(&msg, &rr, NULL, NULL, apn->nsdisp, GTP_DISPLAY_BUFFER_LEN);
		offset = ns_srvname_offset(apn->nsdisp, strlen(apn->nsdisp));
		naptr = gtp_naptr_alloc(apn, l, apn->nsdisp+offset, strlen(apn->nsdisp)-offset);
		gtp_naptr_parse_server_type(naptr, apn->nsdisp, strlen(apn->nsdisp));
		gtp_naptr_parse_service(naptr, apn->nsdisp, strlen(apn->nsdisp));
        }

	/* Context release */
	res_nclose(&ns_rs);
	return 0;
}

gtp_apn_t *
gtp_apn_alloc(const char *name)
{
	gtp_apn_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->naptr);
	INIT_LIST_HEAD(&new->service_selection);
	INIT_LIST_HEAD(&new->imsi_match);
	INIT_LIST_HEAD(&new->oi_match);
	INIT_LIST_HEAD(&new->next);
        pthread_mutex_init(&new->mutex, NULL);
	memcpy(new->name, name, GTP_APN_MAX_LEN - 1);

	/* FIXME: lookup before insert */
	pthread_mutex_lock(&gtp_apn_mutex);
	list_add_tail(&new->next, &daemon_data->gtp_apn);
	pthread_mutex_unlock(&gtp_apn_mutex);

	/* Point default pGW to list head */

	return new;
}

gtp_apn_t *
gtp_apn_get(const char *name)
{
	gtp_apn_t *apn;

	pthread_mutex_lock(&gtp_apn_mutex);
	list_for_each_entry(apn, &daemon_data->gtp_apn, next) {
		if (!strncmp(name, apn->name, strlen(name))) {
			pthread_mutex_unlock(&gtp_apn_mutex);
			return apn;
		}

	}
	pthread_mutex_unlock(&gtp_apn_mutex);

	return NULL;
}

static int
gtp_pgw_destroy(list_head_t *l)
{
	gtp_pgw_t *pgw, *pgw_tmp;

	list_for_each_entry_safe(pgw, pgw_tmp, l, next) {
		list_head_del(&pgw->next);
		FREE(pgw);
	}

	return 0;
}

static int
gtp_naptr_destroy(list_head_t *l)
{
	gtp_naptr_t *naptr, *naptr_tmp;

	list_for_each_entry_safe(naptr, naptr_tmp, l, next) {
		gtp_pgw_destroy(&naptr->pgw);
		list_head_del(&naptr->next);
		FREE(naptr);
	}

	return 0;
}

static gtp_naptr_t *
__gtp_naptr_get(gtp_apn_t *apn, const char *name)
{
	gtp_naptr_t *naptr;

	if (!apn || list_empty(&apn->naptr))
		return NULL;

	if (!name)
		return list_first_entry(&apn->naptr, gtp_naptr_t, next);

	list_for_each_entry(naptr, &apn->naptr, next) {
		if (strstr(naptr->service, name))
			return naptr;
	}

	return NULL;
}

gtp_naptr_t *
gtp_naptr_get(gtp_apn_t *apn, const char *name)
{
	gtp_naptr_t *naptr = NULL;

	pthread_mutex_lock(&apn->mutex);
	naptr = __gtp_naptr_get(apn, name);
	pthread_mutex_unlock(&apn->mutex);

	return naptr;
}

static int
gtp_pgw_show(vty_t *vty, list_head_t *l)
{
	gtp_pgw_t *pgw;

	list_for_each_entry(pgw, l, next) {
		vty_out(vty, "  %s\t\t[%s]:%d%s"
			   , pgw->srv_name
			   , inet_sockaddrtos(&pgw->addr)
			   , ntohs(inet_sockaddrport(&pgw->addr))
			   , VTY_NEWLINE);
	}

	return 0;
}

static int
gtp_naptr_show(vty_t *vty, gtp_apn_t *apn)
{
	list_head_t *l = &apn->naptr;
	gtp_naptr_t *naptr;

	vty_out(vty, "Access-Point-Name %s%s", apn->name, VTY_NEWLINE);
	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry(naptr, l, next) {
		vty_out(vty, " %s\t(%s,%s)%s"
			   , naptr->server, (naptr->server_type == ns_t_srv) ? "SRV" : "A"
			   , naptr->service
			   , VTY_NEWLINE);
		gtp_pgw_show(vty, &naptr->pgw);
	}
	pthread_mutex_unlock(&apn->mutex);

	return 0;
}

static int
gtp_apn_show(vty_t *vty, gtp_apn_t *apn)
{
	list_head_t *l = &daemon_data->gtp_apn;
	gtp_apn_t *_apn;

	if (apn) {
		gtp_naptr_show(vty, apn);
		return 0;
	}

	list_for_each_entry(_apn, l, next)
		gtp_naptr_show(vty, _apn);

	return 0;
}

/*
 *	Service selection related
 */
static int
gtp_service_update(gtp_apn_t *apn)
{
	gtp_service_t *service;

	list_for_each_entry(service, &apn->service_selection, next) {
		service->naptr = __gtp_naptr_get(apn, service->str);
	}

	return 0;
}

static gtp_service_t *
gtp_service_alloc(gtp_apn_t *apn, gtp_naptr_t *naptr, const char *str, int prio)
{
	gtp_service_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->naptr = naptr;
	new->prio = prio;
	if (str)
		strncpy(new->str, str, GTP_APN_MAX_LEN - 1);

	pthread_mutex_lock(&apn->mutex);
	list_add_tail(&new->next, &apn->service_selection);
	pthread_mutex_unlock(&apn->mutex);

	return new;
}

/*
 *	Rewrite rule related
 */
static gtp_rewrite_rule_t *
gtp_rewrite_rule_alloc(gtp_apn_t *apn)
{
	gtp_rewrite_rule_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);

	return new;
}


/*
 *	APN Resolv cache maintain
 */
static int
apn_resolv_cache_realloc(gtp_apn_t *apn)
{
	list_head_t l, old_naptr;
	int ret;

	/* Create temp resolv */
	INIT_LIST_HEAD(&l);
	ret = gtp_resolv_naptr(apn, &l);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Unable to update resolv cache while resolving naptr... keeping previous..."
				    , __FUNCTION__);
		return -1;
	}
	ret = gtp_resolv_pgw(apn, &l);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Unable to update resolv cache while resolving pgw... keeping previous..."
				    , __FUNCTION__);
		return -1;
	}

	/* Swap list and update refs */
	log_message(LOG_INFO, "%s(): APN:%s - Performing resolv-cache update"
			    , __FUNCTION__, apn->name);
	pthread_mutex_lock(&apn->mutex);
	list_copy(&old_naptr, &apn->naptr);
	list_copy(&apn->naptr, &l);
	gtp_service_update(apn);
	pthread_mutex_unlock(&apn->mutex);

	/* Release previous elements */
	if (!list_empty(&old_naptr))
		log_message(LOG_INFO, "%s(): APN:%s - Releasing old resolv-cache"
				    , __FUNCTION__, apn->name);
	gtp_naptr_destroy(&old_naptr);
	apn->last_update = time(NULL);

	return 0;
}


void *
apn_resolv_cache_task(void *arg)
{
	gtp_apn_t *apn = arg;
	struct timeval tval;
	struct timespec timeout;

        /* Our identity */
        prctl(PR_SET_NAME, "resolv_cache", 0, 0, 0, 0);

  cache_process:
	/* Schedule interruptible timeout */
	pthread_mutex_lock(&apn->cache_mutex);
	gettimeofday(&tval, NULL);
	timeout.tv_sec = tval.tv_sec + apn->resolv_cache_update;
	timeout.tv_nsec = tval.tv_usec * 1000;
	pthread_cond_timedwait(&apn->cache_cond, &apn->cache_mutex, &timeout);
	pthread_mutex_unlock(&apn->cache_mutex);

	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		goto cache_finish;

	/* Update */
	apn_resolv_cache_realloc(apn);

	goto cache_process;

  cache_finish:
	return NULL;
}

static int
apn_resolv_cache_signal(gtp_apn_t *apn)
{
	pthread_mutex_lock(&apn->cache_mutex);
	pthread_cond_signal(&apn->cache_cond);
	pthread_mutex_unlock(&apn->cache_mutex);
	return 0;
}


/*
 *	Resolver init
 */
int
gtp_resolv_init(void)
{
	return 0;
}

int
gtp_resolv_destroy(void)
{

	/* FIXME: release cache stuffs */

	return 0;
}

/*
 *	VTY Command
 */
DEFUN(apn,
      apn_cmd,
      "access-point-name STRING",
      "Configure Access Point Name data\n")
{
        gtp_apn_t *new;

        if (argc < 1) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

	new = gtp_apn_get(argv[0]);
	if (new) {
		vty->node = APN_NODE;
		vty->index = new;
		return CMD_SUCCESS;
	}

	new = gtp_apn_alloc(argv[0]);
	vty->node = APN_NODE;
	vty->index = new;

	return CMD_SUCCESS;
}

DEFUN(apn_realm,
      apn_realm_cmd,
      "realm STRING",
      "Set Global PDN Realm\n"
      "name\n")
{
        gtp_apn_t *apn = vty->index;

        if (argc < 1) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

	memcpy(apn->realm, argv[0], GTP_PATH_MAX);
	apn_resolv_cache_realloc(apn);

        return CMD_SUCCESS;
}

DEFUN(apn_nameserver,
      apn_nameserver_cmd,
      "nameserver (A.B.C.D|X:X:X:X)",
      "Set Global PDN nameserver\n"
      "IPv4 Address\n"
      "IPv6 Address\n")
{
        gtp_apn_t *apn = vty->index;
	struct sockaddr_storage *addr = &apn->nameserver;
	int ret;

        if (argc < 1) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

	ret = inet_stosockaddr(argv[0], "53", addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	gtp_resolv_init();

        return CMD_SUCCESS;
}

DEFUN(apn_resolv_max_retry,
      apn_resolv_max_retry_cmd,
      "resolv-max-retry INTEGER",
      "Define maximum number of retry per nameserver query\n"
      "retry count\n")
{
	gtp_apn_t *apn = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn->resolv_max_retry = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(apn_resolv_cache_update,
      apn_resolv_cache_update_cmd,
      "resolv-cache-update <5-86400>",
      "Define periodic cache updates\n"
      "seconds\n")
{
	gtp_apn_t *apn = vty->index;
	int sec = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Seconds", sec, argv[0], 5, 86400);
	apn->resolv_cache_update = sec;
	__set_bit(GTP_RESOLV_FL_CACHE_UPDATE, &apn->flags);

	/* Launch dedicated task since resolver use its own internal network
	 * stuff and must be registered ouside our I/O MUX */
	pthread_mutex_init(&apn->cache_mutex, NULL);
	pthread_cond_init(&apn->cache_cond, NULL);
	pthread_create(&apn->cache_task, NULL, apn_resolv_cache_task, apn);

	return CMD_SUCCESS;
}

DEFUN(apn_resolv_cache_reload,
      apn_resolv_cache_reload_cmd,
      "resolv-cache-reload STRING",
      "Force resolv cache update\n"
      "access-point-name string")
{
	gtp_apn_t *apn;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn = gtp_apn_get(argv[0]);
	if (!apn) {
		vty_out(vty, "%% unkown access-point-name %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_RESOLV_FL_CACHE_UPDATE, &apn->flags)) {
		apn_resolv_cache_signal(apn);
	} else {
		apn_resolv_cache_realloc(apn);
	}

	return CMD_SUCCESS;
}


DEFUN(apn_service_selection,
      apn_service_selection_cmd,
      "service-selection STRING prio INTEGER",
      "Force service selection\n"
      "service\n"
      "priority\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_naptr_t *naptr;
	int prio = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc >= 1)
		prio = atoi(argv[1]);

	naptr = gtp_naptr_get(apn, argv[0]);
	if (!naptr) {
		vty_out(vty, "%% unknown service %s. Preparing for futur use%s", argv[0], VTY_NEWLINE);
	}

	gtp_service_alloc(apn, naptr, argv[0], prio);
	__set_bit(GTP_RESOLV_FL_SERVICE_SELECTION, &apn->flags);

	return CMD_SUCCESS;
}

DEFUN(apn_imsi_match,
      apn_imsi_match_cmd,
      "imsi-prefix-match STRING rewrite STRING",
      "IMSI rewriting based on prefix matching\n"
      "imsi prefix match\n"
      "imsi prefix rewrite\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_rewrite_rule_t *rule;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rule = gtp_rewrite_rule_alloc(apn);
	list_add_tail(&rule->next, &apn->imsi_match);

	stringtohex(argv[0], 15, rule->match, GTP_MATCH_MAX_LEN);
	swapbuffer((uint8_t *)rule->match, 8, (uint8_t *)rule->match);
	rule->match_len = strlen(argv[0]);
	stringtohex(argv[1], 15, rule->rewrite, GTP_MATCH_MAX_LEN);
	swapbuffer((uint8_t *)rule->rewrite, 8, (uint8_t *)rule->rewrite);
	rule->rewrite_len = strlen(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(apn_oi_match,
      apn_oi_match_cmd,
      "apn-oi-match STRING rewrite STRING",
      "APN OI rewriting based on prefix matching\n"
      "OI match\n"
      "OI rewrite\n")
{
	gtp_apn_t *apn = vty->index;
	gtp_rewrite_rule_t *rule;
	int match_label_cnt, rewrite_label_cnt;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strlen(argv[0]) != strlen(argv[1])) {
		vty_out(vty, "%% prefix match and rewrite MUST have the same length%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	match_label_cnt = gtp_ie_apn_labels_cnt(argv[0], strlen(argv[0]));
	rewrite_label_cnt = gtp_ie_apn_labels_cnt(argv[1], strlen(argv[1]));
	if (match_label_cnt != rewrite_label_cnt) {
		vty_out(vty, "%% match and rewrite MUST have the same label count%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rule = gtp_rewrite_rule_alloc(apn);
	list_add_tail(&rule->next, &apn->oi_match);
	strncpy(rule->match, argv[0], GTP_MATCH_MAX_LEN-1);
	strncpy(rule->rewrite, argv[1], GTP_MATCH_MAX_LEN-1);

	return CMD_SUCCESS;
}

DEFUN(apn_session_lifetime,
      apn_session_lifetime_cmd,
      "session-lifetime <5-864000>",
      "Define GTP session lifetime\n"
      "seconds\n")
{
	gtp_apn_t *apn = vty->index;
	int sec = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Seconds", sec, argv[0], 5, 864000);
	apn->session_lifetime = sec;

	return CMD_SUCCESS;
}


/* Show */
DEFUN(show_apn,
      show_apn_cmd,
      "show access-point-name [STRING]",
      SHOW_STR
      "Access-Point-Name ruleset\n")
{
	gtp_apn_t *apn = NULL;

	if (argc >= 1) {
		apn = gtp_apn_get(argv[0]);
		if (!apn) {
			vty_out(vty, "%% Unknown access-point-name:%s%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	gtp_apn_show(vty, apn);

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
apn_config_imsi_match(vty_t *vty, gtp_apn_t *apn)
{
        list_head_t *l = &apn->imsi_match;
	gtp_rewrite_rule_t *rule;
	char match_str[32], rewrite_str[32];
	char match[8], rewrite[8];

        list_for_each_entry(rule, l, next) {
		memset(match_str, 0, 32);
		memset(match, 0, 8);
		memset(rewrite_str, 0, 32);
		memset(rewrite, 0, 8);
		swapbuffer((uint8_t *)rule->match, 8, (uint8_t *)match);
		hextostring(match, rule->match_len / 2, match_str);
		if (!!(rule->match_len % 2))
			match_str[rule->match_len - 1] = hextochar((match[rule->match_len / 2] & 0xf0) >> 4);
		swapbuffer((uint8_t *)rule->rewrite, 8, (uint8_t *)rewrite);
		hextostring(rewrite, rule->rewrite_len / 2, rewrite_str);
		if (!!(rule->rewrite_len % 2))
			rewrite_str[rule->rewrite_len - 1] = hextochar((rewrite[rule->rewrite_len / 2] & 0xf0) >> 4);
		vty_out(vty, " imsi-prefix-match %s rewrite %s%s"
			   , match_str, rewrite_str , VTY_NEWLINE);
	}

	return 0;
}

static int
apn_config_apn_oi_match(vty_t *vty, gtp_apn_t *apn)
{
	list_head_t *l = &apn->oi_match;
	gtp_rewrite_rule_t *rule;

	list_for_each_entry(rule, l, next) {
		vty_out(vty, " apn-oi-match %s rewrite %s%s"
			   , rule->match, rule->rewrite, VTY_NEWLINE);
	}

	return 0;
}

static int
apn_config_write(vty_t *vty)
{
        list_head_t *l = &daemon_data->gtp_apn;
        gtp_apn_t *apn;
	gtp_service_t *service;

        list_for_each_entry(apn, l, next) {
        	vty_out(vty, "access-point-name %s%s", apn->name, VTY_NEWLINE);
		vty_out(vty, " nameserver %s%s", inet_sockaddrtos(&apn->nameserver), VTY_NEWLINE);
		if (apn->resolv_max_retry)
			vty_out(vty, " resolv-max-retry %d%s", apn->resolv_max_retry, VTY_NEWLINE);
		if (apn->resolv_cache_update)
			vty_out(vty, " resolv-cache-update %d%s", apn->resolv_cache_update, VTY_NEWLINE);
		vty_out(vty, " realm %s%s", apn->realm, VTY_NEWLINE);
		if (__test_bit(GTP_RESOLV_FL_SERVICE_SELECTION, &apn->flags)) {
			list_for_each_entry(service, &apn->service_selection, next) {
				if (service->prio)
					vty_out(vty, " service-selection %s prio %d%s"
						   , service->naptr->service
						   , service->prio
						   , VTY_NEWLINE);
				else
					vty_out(vty, " service-selection %s%s"
						   , service->naptr->service
						   , VTY_NEWLINE);
			}
		}
		apn_config_imsi_match(vty, apn);
		apn_config_apn_oi_match(vty, apn);
		if (apn->session_lifetime)
			vty_out(vty, " session-lifetime %d%s"
				   , apn->session_lifetime, VTY_NEWLINE);
        	vty_out(vty, "!%s", VTY_NEWLINE);
        }

	return CMD_SUCCESS;
}

/*
 *	VTY init
 */
int
gtp_apn_vty_init(void)
{

	/* Install PDN commands. */
	install_node(&apn_node, apn_config_write);
	install_element(CONFIG_NODE, &apn_cmd);

	install_default(APN_NODE);
	install_element(APN_NODE, &apn_nameserver_cmd);
	install_element(APN_NODE, &apn_resolv_max_retry_cmd);
	install_element(APN_NODE, &apn_resolv_cache_update_cmd);
	install_element(APN_NODE, &apn_realm_cmd);
	install_element(APN_NODE, &apn_service_selection_cmd);
	install_element(APN_NODE, &apn_imsi_match_cmd);
	install_element(APN_NODE, &apn_oi_match_cmd);
	install_element(APN_NODE, &apn_session_lifetime_cmd);
//	install_element(APN_NODE, &apn_force_pgw_selection_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_apn_cmd);
	install_element(ENABLE_NODE, &show_apn_cmd);
	install_element(ENABLE_NODE, &apn_resolv_cache_reload_cmd);

	return 0;
}
