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
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "list_head.h"
#include "gtp_vrf.h"
#include "gtp_cdr.h"
#include "gtp_cdr_spool.h"

/* defines */
#define GTP_APN_MAX_LEN		256
#define GTP_REALM_LEN		128
#define GTP_RESOLV_BUFFER_LEN	20*1024
#define GTP_DISPLAY_BUFFER_LEN	512
#define GTP_DISPLAY_SRV_LEN	256
#define GTP_MATCH_MAX_LEN	256
#define GTP_PLMN_MAX_LEN	3

/* flags */
enum gtp_apn_flags {
	GTP_RESOLV_FL_SERVICE_SELECTION,
	GTP_RESOLV_FL_CACHE_UPDATE,
	GTP_RESOLV_FL_CNX_PERSISTENT,
	GTP_APN_FL_SESSION_UNIQ_PTYPE,
	GTP_APN_FL_REALM_DYNAMIC,
	GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4,
	GTP_APN_FL_TAG_ULI_WITH_EGCI_PLMN,
};

enum gtp_pco_flags {
	GTP_PCO_IPCP_PRIMARY_NS,
	GTP_PCO_IPCP_SECONDARY_NS,
	GTP_PCO_IP_NS,
};

/* Protocol Configuration Option */
struct gtp_ns {
	struct sockaddr_storage	addr;

	struct list_head	next;
};

struct gtp_pco {
	struct list_head	ns;
	struct sockaddr_storage	ipcp_primary_ns;
	struct sockaddr_storage	ipcp_secondary_ns;
	uint16_t		link_mtu;
	uint8_t			selected_bearer_control_mode;

	unsigned long		flags;
};

struct gtp_ip_pool {
	uint32_t		network;
	uint32_t		netmask;
	bool			*lease;
	int			next_lease_idx;
};

/* Rewriting rule */
struct gtp_rewrite_rule {
	char			match[GTP_MATCH_MAX_LEN];
	size_t			match_len;
	char			rewrite[GTP_MATCH_MAX_LEN];
	size_t			rewrite_len;

	struct list_head	next;
};

/* HPLMN */
struct gtp_plmn {
	uint8_t			plmn[GTP_PLMN_MAX_LEN];

	struct list_head	next;
};

/* Access-Point-Name */
struct gtp_apn {
	char			name[GTP_APN_MAX_LEN];
	char			realm[GTP_REALM_LEN];
	struct sockaddr_storage	nameserver;
	struct sockaddr_storage	nameserver_bind;
	int			nameserver_timeout;
	uint8_t			resolv_max_retry;
	int			resolv_cache_update;
	int			session_lifetime;
	uint8_t			eps_bearer_id;
	uint8_t			restriction;
	unsigned long		indication_flags;
	struct gtp_pco		*pco;
	struct gtp_ip_pool	*ip_pool;
	struct ip_vrf		*vrf;
	struct gtp_plmn		egci_plmn;
	struct gtp_cdr_spool	*cdr_spool;
	int			session_count;

	struct list_head	naptr;
	struct list_head	service_selection;
	struct list_head	imsi_match;
	struct list_head	oi_match;
	struct list_head	hplmn;
	pthread_mutex_t		mutex;

	pthread_t		cache_task;
	pthread_cond_t		cache_cond;
	pthread_mutex_t		cache_mutex;
	time_t			last_update;

	struct list_head	next;

	unsigned long		flags;
};


/* Prototypes */
void gtp_apn_foreach(int (*hdl) (struct gtp_apn *, void *), void *);
struct gtp_rewrite_rule *gtp_rewrite_rule_alloc(struct gtp_apn *, struct list_head *);
int apn_resolv_cache_realloc(struct gtp_apn *);
void *apn_resolv_cache_task(void *);
int apn_resolv_cache_signal(struct gtp_apn *);
struct gtp_ip_pool *gtp_ip_pool_alloc(uint32_t, uint32_t);
void gtp_ip_pool_destroy(struct gtp_ip_pool *);
uint32_t gtp_ip_pool_get(struct gtp_apn *);
int gtp_ip_pool_put(struct gtp_apn *, uint32_t);
struct gtp_plmn *gtp_apn_hplmn_alloc(struct gtp_apn *, uint8_t *);
void gtp_apn_hplmn_del(struct gtp_apn *, struct gtp_plmn *);
void gtp_apn_hplmn_destroy(struct gtp_apn *);
struct gtp_plmn *gtp_apn_hplmn_get(struct gtp_apn *, uint8_t *);
struct gtp_apn *gtp_apn_alloc(const char *);
struct gtp_pco *gtp_apn_pco(struct gtp_apn *);
int gtp_apn_destroy(void);
struct gtp_apn *gtp_apn_get(const char *);
int gtp_apn_cdr_commit(struct gtp_apn *, struct gtp_cdr *);
