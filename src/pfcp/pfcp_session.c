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

#include <inttypes.h>
#include <stdint.h>
#include "pfcp_session.h"
#include "pfcp_teid.h"
#include "pfcp_msg.h"
#include "pfcp_router.h"
#include "gtp_conn.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "jhash.h"


/* Extern data */
extern struct thread_master *master;

/* Local data */
static struct list_head pfcp_session_unuse;
static int pfcp_session_unuse_count;
static struct hlist_head *pfcp_session_tab;
static int pfcp_sessions_count = 0;
static void pfcp_session_expire(struct thread *t);


/*
 *	Recycle handling
 */
static int
pfcp_session_unuse_destroy(void)
{
	struct pfcp_session *s, *_s;

	list_for_each_entry_safe(s, _s, &pfcp_session_unuse, next) {
		list_head_del(&s->next);
		free(s);
	}
	INIT_LIST_HEAD(&pfcp_session_unuse);

	return 0;
}

int
pfcp_session_unuse_queue_size(void)
{
	return pfcp_session_unuse_count;
}

static struct pfcp_session *
pfcp_session_unuse_trim_head(void)
{
	struct pfcp_session *s;

	if (list_empty(&pfcp_session_unuse))
		return NULL;

	s = list_first_entry(&pfcp_session_unuse, struct pfcp_session, next);
	list_head_del(&s->next);
	memset(s, 0, sizeof(*s));

	__sync_sub_and_fetch(&pfcp_session_unuse_count, 1);
	return s;
}


static struct pfcp_session *
pfcp_session_malloc(void)
{
	struct pfcp_session *s;

	s = pfcp_session_unuse_trim_head();
	if (!s)
		s = calloc(1, sizeof(*s));

	return s;
}

void
pfcp_session_free(struct pfcp_session *s)
{
	INIT_LIST_HEAD(&s->next);
	list_add_tail(&s->next, &pfcp_session_unuse);
	__sync_add_and_fetch(&pfcp_session_unuse_count, 1);
}


/*
 *	PFCP Session hash handling
 */
static struct hlist_head *
pfcp_session_hashkey(struct hlist_head *h, uint64_t id)
{
	return h + (jhash_2words((uint32_t)id, (uint32_t) (id >> 32), 0) & PFCP_SESSION_HASHTAB_MASK);
}

static struct pfcp_session *
_pfcp_session_get(struct hlist_head *h, uint64_t id)
{
	struct hlist_head *head = pfcp_session_hashkey(h, id);
	struct pfcp_session *s;

	hlist_for_each_entry(s, head, hlist) {
		if (s->seid == id) {
			__sync_add_and_fetch(&s->refcnt, 1);
			return s;
		}
	}

	return NULL;
}

struct pfcp_session *
pfcp_session_get(uint64_t id)
{
	return _pfcp_session_get(pfcp_session_tab, id);
}

int
pfcp_session_put(struct pfcp_session *s)
{
	if (!s)
		return -1;

	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
_pfcp_session_hash(struct hlist_head *h, struct pfcp_session *s)
{
	struct hlist_head *head = pfcp_session_hashkey(h, s->seid);

	if (__test_and_set_bit(PFCP_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): pfcp-session:0x%" PRIx64 " already hashed !!!"
				    , __FUNCTION__, s->seid);
		return -1;
	}

	hlist_add_head(&s->hlist, head);
	__sync_add_and_fetch(&s->refcnt, 1);
	return 0;
}

static int
_pfcp_session_unhash(struct hlist_head *h, struct pfcp_session *s)
{
	if (!s)
		return -1;

	if (!__test_and_clear_bit(PFCP_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): pfcp-session:0x%" PRIx64 " already unhashed !!!"
				    , __FUNCTION__, s->seid);
		return -1;
	}
	hlist_del_init(&s->hlist);
	__sync_sub_and_fetch(&s->refcnt, 1);
	return 0;
}

int
pfcp_session_unhash(struct pfcp_session *s)
{
	return _pfcp_session_unhash(pfcp_session_tab, s);
}

int
pfcp_session_hash(struct pfcp_session *s)
{
	return _pfcp_session_hash(pfcp_session_tab, s);
}


/*
 *	PFCP Sessions handling
 */
int
pfcp_sessions_count_read(void)
{
	return pfcp_sessions_count;
}

void
pfcp_session_mod_timer(struct pfcp_session *s, int timeout)
{
	if (!s->timer)
		s->timer = thread_add_timer(master, pfcp_session_expire, s,
					    (uint64_t) timeout * TIMER_HZ);
	else
		thread_mod_timer(s->timer, (uint64_t) timeout * TIMER_HZ);
}

static void
pfcp_session_add_timer(struct pfcp_session *s)
{
	struct gtp_apn *apn = s->apn;

	if (!apn->session_lifetime)
		return;

	/* Sort it by timeval */
	pfcp_session_mod_timer(s, apn->session_lifetime);
}

static int
pfcp_session_add(struct gtp_conn *c, struct pfcp_session *s)
{
	list_add_tail(&s->next, &c->pfcp_sessions);
	__sync_add_and_fetch(&c->refcnt, 1);
	__sync_add_and_fetch(&pfcp_sessions_count, 1);
	return 0;
}

static uint64_t
pfcp_session_seid_alloc(struct pfcp_router *r)
{
	struct pfcp_session *s;
	uint64_t seid = 0;
	int retry = 0;

shoot_again:
	/* TODO: Do we really need random seid ? it avoid seid prediction
	 * but need proper security investigation to ensure if it is really
	 * needed. For now, asume random is best... */
	seid = xorshift_prng(&r->seed);
	s = pfcp_session_get(seid);
	if (!s)
		return seid;

	pfcp_session_put(s);

	/* allocation active loop prevention */
	if (retry++ < 5)
		goto shoot_again;

	return 0;
}

struct pfcp_session *
pfcp_session_alloc(struct gtp_conn *c, struct gtp_apn *apn, struct pfcp_router *r)
{
	struct pfcp_session *new;
	uint64_t seid;

	new = pfcp_session_malloc();
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&new->next);
	new->apn = apn;
	new->conn = c;
	new->router = r;
	time_now_to_calendar(&new->creation_time);
	seid = pfcp_session_seid_alloc(r);
	if (!seid) {
		log_message(LOG_INFO, "%s(): Something weird while allocating seid !!!"
				    , __FUNCTION__);
		free(new);
		return NULL;
	}
	new->seid = seid;

	/* CDR context */
	if (apn->cdr_spool)
		new->cdr = gtp_cdr_alloc();

	pfcp_session_add(c, new);
	pfcp_session_hash(new);
	pfcp_session_add_timer(new);
	__sync_add_and_fetch(&apn->session_count, 1);
	return new;
}

static int
pfcp_session_release(struct pfcp_session *s)
{
	__sync_sub_and_fetch(&s->apn->session_count, 1);
	__sync_sub_and_fetch(&pfcp_sessions_count, 1);
	gtp_apn_cdr_commit(s->apn, s->cdr);
//	pfcp_session_bpf__destroy(s);
	list_head_del(&s->next);
	pfcp_session_unhash(s);
	pfcp_session_free(s);
	return 0;
}

int
pfcp_session_destroy(struct pfcp_session *s)
{
	struct gtp_conn *c = s->conn;

	thread_del(s->timer);
	pfcp_session_release(s);

	/* Release connection if no more sessions */
	if (__sync_sub_and_fetch(&c->refcnt, 1) == 0) {
		gtp_conn_unhash(c);
		log_message(LOG_INFO, "IMSI:%ld - no more sessions - Releasing tracking"
				    , c->imsi);
		free(c);
	}

	return 0;
}


/*
 *	Session expiration handling
 */
static void
pfcp_session_expire(struct thread *t)
{
	struct pfcp_session *s = THREAD_ARG(t);

	log_message(LOG_INFO, "IMSI:%ld - Expiring pfcp-session-id:0x%" PRIx64 ""
			    , s->conn->imsi, s->seid);
	pfcp_session_destroy(s);
}

int
pfcp_sessions_release(struct gtp_conn *c)
{
	struct list_head *l = &c->pfcp_sessions;
	struct pfcp_session *s, *_s;

	/* Release sessions */
	list_for_each_entry_safe(s, _s, l, next)
		pfcp_session_destroy(s);

	return 0;
}

int
pfcp_sessions_free(struct gtp_conn *c)
{
	struct list_head *l = &c->pfcp_sessions;
	struct pfcp_session *s, *_s;

	list_for_each_entry_safe(s, _s, l, next) {
		thread_del(s->timer);
		pfcp_session_release(s);
	}

	return 0;
}


/*
 *	PFCP Sessions.
 */
int
pfcp_sessions_int(void)
{
	INIT_LIST_HEAD(&pfcp_session_unuse);
	pfcp_session_tab = calloc(PFCP_SESSION_HASHTAB_SIZE, sizeof(struct hlist_head));
	return 0;
}

int
pfcp_sessions_destroy(void)
{
	struct hlist_node *n;
	struct pfcp_session *s;
	int i;

	for (i = 0; i < PFCP_SESSION_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(s, n, &pfcp_session_tab[i], hlist) {
			free(s);
		}
	}

	free(pfcp_session_tab);
	pfcp_session_unuse_destroy();
	return 0;
}



/****************************************************************************************
 *                                  Session Decoders                                    *
 ****************************************************************************************/
static struct traffic_endpoint *
pfcp_session_get_te_by_id(struct pfcp_session *s, uint8_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->te[i].id; i++) {
		if (s->te[i].id == id)
			return &s->te[i];
	}

	return NULL;
}

static struct far *
pfcp_session_get_far_by_id(struct pfcp_session *s, uint32_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->far[i].id; i++) {
		if (s->far[i].id == id)
			return &s->far[i];
	}

	return NULL;
}

static struct qer *
pfcp_session_get_qer_by_id(struct pfcp_session *s, uint32_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->qer[i].id; i++) {
		if (s->qer[i].id == id)
			return &s->qer[i];
	}

	return NULL;
}

static struct urr *
pfcp_session_get_urr_by_id(struct pfcp_session *s, uint32_t id)
{
	int i;

	for (i = 0; i < PFCP_MAX_NR_ELEM && s->urr[i].id; i++) {
		if (s->urr[i].id == id)
			return &s->urr[i];
	}

	return NULL;
}

static union addr *
pfcp_session_get_addr_by_interface(struct pfcp_router *r, uint8_t interface)
{
	union addr *gtpu_addr = NULL;

	switch (interface) {
	case PFCP_3GPP_INTERFACE_S1U:
		if (__test_bit(PFCP_ROUTER_FL_S1U, &r->flags))
			gtpu_addr = &r->gtpu_s1;
		break;

	case PFCP_3GPP_INTERFACE_S5U:
		if (__test_bit(PFCP_ROUTER_FL_S5U, &r->flags))
			gtpu_addr = &r->gtpu_s5;
		break;

	case PFCP_3GPP_INTERFACE_S8U:
		if (__test_bit(PFCP_ROUTER_FL_S8U, &r->flags))
			gtpu_addr = &r->gtpu_s8;
		break;

	case PFCP_3GPP_INTERFACE_N9:
		if (__test_bit(PFCP_ROUTER_FL_N9U, &r->flags))
			gtpu_addr = &r->gtpu_n9;
		break;
	}

	if (!gtpu_addr && __test_bit(PFCP_ROUTER_FL_ALL, &r->flags))
		gtpu_addr = &r->gtpu;

	if (!gtpu_addr)
		log_message(LOG_INFO, "%s(): pfcp-router:'%s' No GTP-U interface configured !!!"
				    , __FUNCTION__, r->name);

	return gtpu_addr;
}

static struct pfcp_teid *
pfcp_session_alloc_teid(struct pfcp_session *s, uint32_t *id, uint8_t interface)
{
	struct pfcp_router *r = s->router;
	union addr *gtpu_addr = NULL;
	struct in_addr *ipv4;
	struct in6_addr *ipv6;
	struct pfcp_teid *t;
	uint32_t new_id;

	gtpu_addr = pfcp_session_get_addr_by_interface(r, interface);
	if (!gtpu_addr)
		return NULL;

	ipv4 = (gtpu_addr->family == AF_INET) ? &gtpu_addr->sin.sin_addr : NULL;
	ipv6 = (gtpu_addr->family == AF_INET6) ? &gtpu_addr->sin6.sin6_addr : NULL;

	/* Try to use same TEID for different IP Address */
	if (!*id)  {
		new_id = pfcp_teid_roll_the_dice(r, ipv4, ipv6);
		if (!new_id)
			return NULL;
		*id = new_id;
	}

	t = pfcp_teid_alloc(r, *id, ipv4, ipv6);
	if (!t)
		return NULL;

#if 0
	char buffer[1024];
	pfcp_teid_dump(t, buffer, 1024);
	printf("Allocating: %s\n", buffer);
#endif

	return t;
}

static int
pfcp_session_decode_te(struct pfcp_session *s, struct traffic_endpoint *te,
		       struct pfcp_ie_create_traffic_endpoint *ie, uint32_t *id)
{
	struct pfcp_teid *t;

	te->id = ie->traffic_endpoint_id->value;

	if (ie->ue_ip_address->v4)
		te->ue_ipv4 = ie->ue_ip_address->ip_address.v4;

	if (ie->ue_ip_address->v6)
		te->ue_ipv6 = ie->ue_ip_address->ip_address.v6;

	if (ie->local_f_teid->chid)
		te->choose_id = ie->local_f_teid->choose_id;

	if (!ie->local_f_teid->ch) {
		/* Restoration procedure */
		t = pfcp_teid_restore(s->router, ie->local_f_teid);
		if (!t)
			return -1;

		te->teid[PFCP_DIR_EGRESS] = t;
		__set_bit(PFCP_TEID_F_EGRESS, &t->flags);
	} else {
		t = pfcp_session_alloc_teid(s, id, te->interface);
		if (!t)
			return -1;

		te->teid[PFCP_DIR_EGRESS] = t;
		__set_bit(PFCP_TEID_F_EGRESS, &t->flags);
	}

	if (ie->source_interface_type)
		te->interface = ie->source_interface_type->value;

	return 0;
}

static int
pfcp_session_decode_far(struct pfcp_session *s, struct far *far, struct pfcp_ie_create_far *ie)
{
	struct pfcp_ie_forwarding_parameters *fwd;

	far->id = ie->far_id->value;

	/* Optional: Forwarding Parameters */
	if (!ie->forwarding_parameters)
		return 0;

	fwd = ie->forwarding_parameters;

	if (fwd->destination_interface)
		far->dst_interface = fwd->destination_interface->value;

	if (fwd->destination_interface_type)
		far->dst_interface_type = fwd->destination_interface_type->value;

	if (fwd->transport_level_marking) {
		far->tos_tclass = ntohs(fwd->transport_level_marking->traffic_class) & 0xff;
		far->tos_mask = (ntohs(fwd->transport_level_marking->traffic_class) >> 8) & 0xff;
	}

	if (fwd->linked_traffic_endpoint_id)
		far->dst_te = pfcp_session_get_te_by_id(s, fwd->linked_traffic_endpoint_id->value);

	return 0;
}

static int
pfcp_session_decode_qer(struct pfcp_session *s, struct qer *qer, struct pfcp_ie_create_qer *ie)
{
	qer->id = ie->qer_id->value;

	if (ie->maximum_bitrate) {
		qer->ul_mbr = ntohl(ie->maximum_bitrate->ul_mbr);
		qer->dl_mbr = ntohl(ie->maximum_bitrate->dl_mbr);
	}

	return 0;
}

static int
pfcp_session_decode_urr(struct pfcp_session *s, struct urr *urr, struct pfcp_ie_create_urr *ie)
{
	urr->id = ie->urr_id->value;

	urr->measurement_method = ie->measurement_method->measurement_method;

	urr->triggers = ntohs(ie->reporting_triggers->triggers);

	if (ie->measurement_information)
		urr->measurement_info = ie->measurement_information->flags;

	if (ie->quota_holding_time)
		urr->quota_holdtime = ntohl(ie->quota_holding_time->value);

	if (ie->volume_threshold) {
		/* Use total volume if present, otherwise fallback to uplink or downlink */
		if (ie->volume_threshold->tovol)
			urr->volume_threshold = be64toh(ie->volume_threshold->total_volume);
		else if (ie->volume_threshold->ulvol)
			urr->volume_threshold = be64toh(ie->volume_threshold->uplink_volume);
		else if (ie->volume_threshold->dlvol)
			urr->volume_threshold = be64toh(ie->volume_threshold->downlink_volume);
	}

	return 0;
}

static int
pfcp_session_decode_pdr(struct pfcp_session *s, struct pdr *pdr, struct pfcp_ie_create_pdr *ie,
			uint32_t *id)
{
	struct pfcp_ie_pdi *pdi;
	struct pfcp_teid *t;
	int i;

	pdr->id = ie->pdr_id->rule_id;

	pdr->precedence = be32toh(ie->precedence->value);

	pdi = ie->pdi;
	if (pdi) {
		if (pdi->traffic_endpoint_id) {
			pdr->te = pfcp_session_get_te_by_id(s, pdi->traffic_endpoint_id->value);
			if (!pdr->te)
				return -1;
		} else if (pdi->local_f_teid) {
			if (!pdi->source_interface_type)
				return -1;

			t = pfcp_session_alloc_teid(s, id, pdi->source_interface_type->value);
			if (!t)
				return -1;

printf("[3]\n");
			pdr->teid[PFCP_DIR_EGRESS] = t;
			__set_bit(PFCP_TEID_F_EGRESS, &t->flags);
		}
	}

	if (ie->far_id)
		pdr->far = pfcp_session_get_far_by_id(s, ie->far_id->value);

	if (ie->urr_id) {
		for (i = 0; i < ie->nr_urr_id && i < PFCP_MAX_NR_ELEM; i++) {
			pdr->urr[i] = pfcp_session_get_urr_by_id(s, ie->urr_id[i]->value);
			if (!pdr->urr[i])
				return -1;
		}
	}

	if (ie->qer_id) {
		pdr->qer = pfcp_session_get_qer_by_id(s, ie->qer_id->value);
		if (!pdr->qer)
			return -1;
	}

	if (ie->activate_predefined_rules) {
		size_t len = ntohs(ie->activate_predefined_rules->h.length);
		if (len > 0 && len < PFCP_STR_MAX_LEN)
			memcpy(pdr->predifined_rule,
			       ie->activate_predefined_rules->predefined_rules_name, len);
	}

	return 0;
}

int
pfcp_session_decode(struct pfcp_session *s, struct pfcp_session_establishment_request *req,
		    struct sockaddr_storage *addr)
{
	int i, err = 0;
	uint32_t id = 0;

	/* Remote SEID */
	s->remote_seid.id = req->cp_f_seid->seid;
	s->remote_seid.addr = *addr;

	/* Traffic Endpoint */
	for (i = 0; i < req->nr_create_traffic_endpoint && i < PFCP_MAX_NR_ELEM; i++) {
		err = pfcp_session_decode_te(s, &s->te[i], req->create_traffic_endpoint[i], &id);
		if (err)
			return -1;
	}

	/* FAR */
	for (i = 0; i < req->nr_create_far && i < PFCP_MAX_NR_ELEM; i++)
		pfcp_session_decode_far(s, &s->far[i], req->create_far[i]);

	/* QER */
	for (i = 0; i < req->nr_create_qer && i < PFCP_MAX_NR_ELEM; i++)
		pfcp_session_decode_qer(s, &s->qer[i], req->create_qer[i]);

	/* URR */
	for (i = 0; i < req->nr_create_urr && i < PFCP_MAX_NR_ELEM; i++)
		pfcp_session_decode_urr(s, &s->urr[i], req->create_urr[i]);

	/* PDR will reference parsed elem */
	for (i = 0; i < req->nr_create_pdr && i < PFCP_MAX_NR_ELEM; i++) {
		err = pfcp_session_decode_pdr(s, &s->pdr[i], req->create_pdr[i], &id);
		if (err)
			return -1;
	}

	return 0;
}
