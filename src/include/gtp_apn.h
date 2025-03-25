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

#ifndef _GTP_APN_H
#define _GTP_APN_H

/* defines */
#define GTP_APN_MAX_LEN		256
#define GTP_REALM_LEN		128
#define GTP_RESOLV_BUFFER_LEN	20*1024
#define GTP_DISPLAY_BUFFER_LEN	512
#define GTP_DISPLAY_SRV_LEN	256
#define GTP_MATCH_MAX_LEN	256

/* flags */
enum gtp_apn_flags {
	GTP_RESOLV_FL_SERVICE_SELECTION,
	GTP_RESOLV_FL_CACHE_UPDATE,
	GTP_APN_FL_SESSION_UNIQ_PTYPE,
	GTP_APN_FL_REALM_DYNAMIC,
	GTP_APN_FL_TAG_ULI_WITH_SERVING_NODE_IP4,
};

enum gtp_pco_flags {
	GTP_PCO_IPCP_PRIMARY_NS,
	GTP_PCO_IPCP_SECONDARY_NS,
	GTP_PCO_IP_NS,
};

/* Protocol Configuration Option */
typedef struct _gtp_ns {
	struct sockaddr_storage	addr;

	list_head_t		next;
} gtp_ns_t;

typedef struct _gtp_pco {
	list_head_t		ns;
	struct sockaddr_storage	ipcp_primary_ns;
	struct sockaddr_storage	ipcp_secondary_ns;
	uint16_t		link_mtu;
	uint8_t			selected_bearer_control_mode;

	unsigned long		flags;
} gtp_pco_t;

typedef struct _gtp_ip_pool {
	uint32_t		network;
	uint32_t		netmask;
	bool			*lease;
	int			next_lease_idx;
} gtp_ip_pool_t;


/* Rewriting rule */
typedef struct _gtp_rewrite_rule {
	char			match[GTP_MATCH_MAX_LEN];
	size_t			match_len;
	char			rewrite[GTP_MATCH_MAX_LEN];
	size_t			rewrite_len;

	list_head_t		next;
} gtp_rewrite_rule_t;

/* Access-Point-Name */
typedef struct _gtp_apn {
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
	gtp_pco_t		*pco;
	gtp_ip_pool_t		*ip_pool;
	ip_vrf_t		*vrf;

	list_head_t		naptr;
	list_head_t		service_selection;
	list_head_t		imsi_match;
	list_head_t		oi_match;
	pthread_mutex_t		mutex;

	pthread_t		cache_task;
	pthread_cond_t		cache_cond;
	pthread_mutex_t		cache_mutex;
	time_t			last_update;

	list_head_t		next;

	unsigned long		flags;
} gtp_apn_t;


/* Prototypes */
extern uint32_t gtp_ip_pool_get(gtp_apn_t *);
extern int gtp_ip_pool_put(gtp_apn_t *, uint32_t);
extern gtp_apn_t *gtp_apn_get(const char *);
extern int gtp_apn_destroy(void);
extern int gtp_apn_vty_init(void);

#endif
