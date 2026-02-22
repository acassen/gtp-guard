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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <stdint.h>
#include <resolv.h>
#include <sys/socket.h>
#include "vty.h"
#include "gtp_apn.h"

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
struct gtp_pgw {
	uint16_t		priority;
	uint16_t		weight;
	char			srv_name[GTP_DISPLAY_SRV_LEN];
	struct gtp_naptr	*naptr;	  /* Back-pointer */
	struct sockaddr_storage	addr;
	uint64_t		cnt;
	time_t			last_resp;

	struct list_head	next;
};

struct gtp_naptr {
	uint8_t			server_type;
	uint16_t		order;
	uint16_t		preference;
	char			flags[GTP_APN_MAX_LEN];
	char			service[GTP_APN_MAX_LEN];
	char			regexp[GTP_APN_MAX_LEN];
	char			server[GTP_APN_MAX_LEN];

	struct list_head	pgw;

	struct list_head	next;

	unsigned long		fl;
};

struct gtp_service {
	char			str[GTP_APN_MAX_LEN];
	int			prio;

	struct list_head	next;
};

struct gtp_resolv_ctx {
	struct gtp_apn		*apn;	/* Back-pointer */
	char			*realm;
	struct __res_state	ns_rs;
	ns_msg			msg;
	ns_rr			rr;
	int			max_retry;
	u_char			nsbuffer[GTP_RESOLV_BUFFER_LEN];
	char			nsdisp[GTP_DISPLAY_BUFFER_LEN];
};


/* Prototypes */
struct gtp_service *gtp_service_alloc(struct gtp_apn *, const char *, int);
int gtp_service_destroy(struct gtp_apn *);
int gtp_naptr_destroy(struct list_head *);
int gtp_naptr_show(struct vty *vty, struct gtp_apn *);
int gtp_naptr_dump(struct list_head *);
struct gtp_naptr *gtp_naptr_get(struct gtp_apn *, const char *);
int gtp_resolv_pgw(struct gtp_resolv_ctx *, struct list_head *);
int gtp_resolv_naptr(struct gtp_resolv_ctx *, struct list_head *, const char *, ...);
struct gtp_resolv_ctx *gtp_resolv_ctx_alloc(struct gtp_apn *);
int gtp_resolv_ctx_destroy(struct gtp_resolv_ctx *);
int gtp_resolv_init(void);
int gtp_resolv_destroy(void);
