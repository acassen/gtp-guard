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
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_utils.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Scheduling decision
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
 *	Resolver helpers
 */
static int8_t
gtp_naptr_strncpy(char *str, size_t str_len, const u_char *buffer, const u_char *end)
{
	uint8_t *len = (uint8_t *) buffer;

	/* overflow prevention */
	if ((buffer + *len > end) || (*len > str_len))
		return -1;

	if (!*len)
		return 1;

	memcpy(str, buffer+1, *len);
	return *len + 1;
}

static int16_t
gtp_naptr_name_strncat(char *str, size_t str_len, const u_char *buffer, const u_char *end)
{
	int16_t offset = 0;
	const uint8_t *cp = buffer;
	uint8_t len, i;

	for (cp = buffer; cp < end && *cp; cp++) {
		len = *cp;

		/* truncate when needed */
		if (offset + len + 1 > str_len)
			goto end;

		for (i = 0; i < len && cp < end; i++)
			str[offset++] = *++cp;
		str[offset++] = '.';
	}

  end:
	return offset;
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
gtp_pgw_set(gtp_pgw_t *pgw, const u_char *rdata, size_t rdlen)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *) &pgw->addr;
	pgw->addr.ss_family = AF_INET;
	addr4->sin_addr.s_addr = *(uint32_t *) rdata;
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

		/* Ensure only A are being used */
		if (ns_rr_type(rr) != ns_t_a)
			continue;

		gtp_pgw_set(pgw, ns_rr_rdata(rr), ns_rr_rdlen(rr));
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
gtp_pgw_append(gtp_naptr_t *naptr, char *name, size_t len)
{
	gtp_pgw_t *new;
	struct sockaddr_in *addr4;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->naptr = naptr;
	strncpy(new->srv_name, name, GTP_DISPLAY_SRV_LEN);

	/* Some default hard-coded value */
	addr4 = (struct sockaddr_in *) &new->addr;
	addr4->sin_port = htons(2123);
	new->priority = 10;
	new->weight = 20;

	list_add_tail(&new->next, &naptr->pgw);
	return 0;
}

static int
gtp_pgw_alloc(gtp_naptr_t *naptr, const u_char *rdata, size_t rdlen)
{
	gtp_pgw_t *new;
	const u_char *edata = rdata + rdlen;
	struct sockaddr_in *addr4;
	uint16_t port;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->naptr = naptr;
	addr4 = (struct sockaddr_in *) &new->addr;

	new->priority = ns_get16(rdata);
	rdata += NS_INT16SZ;
	new->weight = ns_get16(rdata);
	rdata += NS_INT16SZ;
	port = ns_get16(rdata);
	addr4->sin_port = htons(port);
	rdata += NS_INT16SZ;
	gtp_naptr_name_strncat(new->srv_name, GTP_DISPLAY_SRV_LEN, rdata, edata);

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

		/* Ensure only SRV are being used */
		if (ns_rr_type(rr) != ns_t_srv)
			continue;

		gtp_pgw_alloc(naptr, ns_rr_rdata(rr), ns_rr_rdlen(rr));
        }

	/* Context release */
	res_nclose(&ns_rs);
	return 0;
}

int
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

static int
gtp_naptr_alloc(gtp_apn_t *apn, list_head_t *l, const u_char *rdata, size_t rdlen)
{
	gtp_naptr_t *new;
	const u_char *edata = rdata + rdlen;
	int16_t len = 0;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->pgw);
	INIT_LIST_HEAD(&new->next);
	new->apn = apn;

	/* Parse ns response according to IETF-RFC2915.8 */
	new->order = ns_get16(rdata);
	rdata += NS_INT16SZ;
	new->preference = ns_get16(rdata);
	rdata += NS_INT16SZ;

	/* Flags */
	len = gtp_naptr_strncpy(new->flags, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;
	rdata += len;
	if (*new->flags == 'A')
		new->server_type = ns_t_a;
	else if (*new->flags == 'S')
		new->server_type = ns_t_srv;

	/* Services */
	len = gtp_naptr_strncpy(new->service, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;
	rdata += len;

	/* REGEXP */
	len = gtp_naptr_strncpy(new->regexp, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;
	rdata += len;

	/* Server */
	len = gtp_naptr_name_strncat(new->server, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;

  end:
	list_add_tail(&new->next, l);
	return 0;
}


int
gtp_resolv_naptr(gtp_apn_t *apn, list_head_t *l)
{
	struct __res_state ns_rs;
	int ret, i, err;
	ns_msg msg;
	ns_rr rr;
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

		/* Ensure only NAPTR are being used */
		if (ns_rr_type(rr) != ns_t_naptr)
			continue;

		gtp_naptr_alloc(apn, l, ns_rr_rdata(rr), ns_rr_rdlen(rr));
        }

	/* Context release */
	res_nclose(&ns_rs);
	return 0;
}

/*
 *	Resolver helpers
 */
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
gtp_pgw_show(vty_t *vty, list_head_t *l)
{
	gtp_pgw_t *pgw;

	list_for_each_entry(pgw, l, next) {
		vty_out(vty, "  %s\t\t[%s]:%d\tPrio:%d Weight:%d%s"
			   , pgw->srv_name
			   , inet_sockaddrtos(&pgw->addr)
			   , ntohs(inet_sockaddrport(&pgw->addr))
			   , pgw->priority
			   , pgw->weight
			   , VTY_NEWLINE);
	}

	return 0;
}

int
gtp_naptr_show(vty_t *vty, gtp_apn_t *apn)
{
	list_head_t *l = &apn->naptr;
	gtp_naptr_t *naptr;

	vty_out(vty, "Access-Point-Name %s%s", apn->name, VTY_NEWLINE);
	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry(naptr, l, next) {
		vty_out(vty, " %s\t(%s, %s, Order:%d, Pref:%d)%s"
			   , naptr->server, (naptr->server_type == ns_t_srv) ? "SRV" : "A"
			   , naptr->service
			   , naptr->order
			   , naptr->preference
			   , VTY_NEWLINE);
		gtp_pgw_show(vty, &naptr->pgw);
	}
	pthread_mutex_unlock(&apn->mutex);

	return 0;
}


int
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

gtp_naptr_t *
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
