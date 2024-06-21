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

#ifndef _GTP_RESOLV_H
#define _GTP_RESOLV_H

/* defines */
#define GTP_APN_MAX_LEN		256
#define GTP_RESOLV_BUFFER_LEN	20*1024
#define GTP_DISPLAY_BUFFER_LEN	512
#define GTP_DISPLAY_SRV_LEN	256
#define GTP_MATCH_MAX_LEN	256

/* flags */
enum gtp_schedule_flags {
	GTP_SCHEDULE_FL_SKIP,
};

/* GTP Resolv */
typedef struct _gtp_pgw {
	uint16_t		priority;
	uint16_t		weight;
	char			srv_name[GTP_DISPLAY_SRV_LEN];
	struct _gtp_naptr	*naptr;	  /*Back-pointer */
	struct sockaddr_storage	addr;
	uint64_t		cnt;
	time_t			last_resp;

	list_head_t		next;
} gtp_pgw_t;

typedef struct _gtp_naptr {
	uint8_t			server_type;
	uint16_t		order;
	uint16_t		preference;
	char			flags[GTP_APN_MAX_LEN];
	char			service[GTP_APN_MAX_LEN];
	char			regexp[GTP_APN_MAX_LEN];
	char			server[GTP_APN_MAX_LEN];

	list_head_t		pgw;

	list_head_t		next;

	unsigned long		fl;
} gtp_naptr_t;

typedef struct _gtp_service {
	char			str[GTP_APN_MAX_LEN];
	int			prio;

	list_head_t		next;
} gtp_service_t;

typedef struct _gtp_resolv_ctx {
	char			apn_ni[GTP_APN_MAX_LEN];
	char			*realm;
	struct __res_state	ns_rs;
	ns_msg			msg;
	ns_rr			rr;
	int			max_retry;
	u_char			nsbuffer[GTP_RESOLV_BUFFER_LEN];
	char			nsdisp[GTP_DISPLAY_BUFFER_LEN];
} gtp_resolv_ctx_t;


/* Prototypes */
extern int gtp_naptr_destroy(list_head_t *);
extern int gtp_naptr_show(vty_t *vty, gtp_apn_t *);
extern gtp_naptr_t *gtp_naptr_get(gtp_apn_t *, const char *);
extern int gtp_resolv_pgw(gtp_resolv_ctx_t *, list_head_t *);
extern int gtp_resolv_naptr(gtp_resolv_ctx_t *, list_head_t *);
extern gtp_resolv_ctx_t *gtp_resolv_ctx_alloc(gtp_apn_t *, const char *);
extern int gtp_resolv_ctx_destroy(gtp_resolv_ctx_t *);
extern int gtp_resolv_init(void);
extern int gtp_resolv_destroy(void);

#endif
