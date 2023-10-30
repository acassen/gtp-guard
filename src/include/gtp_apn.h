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
enum gtp_resolv_flags {
	GTP_RESOLV_FL_SERVICE_SELECTION,
	GTP_RESOLV_FL_CACHE_UPDATE,
};

/* GTP APN */
typedef struct _gtp_rewrite_rule {
	char			match[GTP_MATCH_MAX_LEN];
	size_t			match_len;
	char			rewrite[GTP_MATCH_MAX_LEN];
	size_t			rewrite_len;

	list_head_t		next;
} gtp_rewrite_rule_t;

typedef struct _gtp_apn {
	char			name[GTP_APN_MAX_LEN];
	u_char			nsbuffer[GTP_RESOLV_BUFFER_LEN];
	char			nsdisp[GTP_DISPLAY_BUFFER_LEN];
	char			realm[GTP_REALM_LEN];
	struct sockaddr_storage	nameserver;
	uint8_t			resolv_max_retry;
	int			resolv_cache_update;
	int			session_lifetime;

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
extern gtp_apn_t *gtp_apn_get(const char *);
extern int gtp_apn_destroy(void);
extern int gtp_apn_vty_init(void);

#endif
