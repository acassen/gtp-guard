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
#include <netinet/in.h>
#include "list_head.h"
#include "vty.h"

/* Hash table */
#define CONN_HASHTAB_BITS  20
#define CONN_HASHTAB_SIZE  (1 << CONN_HASHTAB_BITS)
#define CONN_HASHTAB_MASK  (CONN_HASHTAB_SIZE - 1)

/* Connection flags */
enum conn_flags {
	GTP_CONN_F_IMSI_HASHED = 0,
	GTP_CONN_F_IMEI_HASHED,
	GTP_CONN_F_MSISDN_HASHED,
	GTP_CONN_F_DEBUG,
};

struct gtp_conn {
        uint64_t                imsi;
        uint64_t                imei;
        uint64_t                msisdn;
	struct sockaddr_in	sgw_addr;

	/* FIXME: maybe use a global dlock here */
	struct list_head	gtp_sessions;
	struct list_head	pppoe_sessions;
	int			pppoe_cnt;
	struct list_head	pfcp_sessions;
	int			pfcp_cnt;
	time_t			ts;

	/* hash stuff */
        struct hlist_node       h_imsi;
        struct hlist_node       h_imei;
        struct hlist_node       h_msisdn;

	unsigned long		flags;
	int			refcnt;
};

/* Prototypes */
int gtp_conn_count_read(void);
int gtp_conn_get(struct gtp_conn *c);
int gtp_conn_put(struct gtp_conn *c);
struct gtp_conn *gtp_conn_get_by_imsi(uint64_t imsi);
struct gtp_conn *gtp_conn_get_by_imei(uint64_t imei);
struct gtp_conn *gtp_conn_get_by_msisdn(uint64_t msisdn);
struct gtp_conn *gtp_conn_alloc(uint64_t imsi, uint64_t imei, uint64_t msisdn);
int gtp_conn_hash(struct gtp_conn *c);
int gtp_conn_unhash(struct gtp_conn *c);
int gtp_conn_vty(struct vty *vty, int (*vty_conn) (struct vty *, struct gtp_conn *, void *),
		 uint64_t imsi, void *arg);
int gtp_conn_init(void);
int gtp_conn_destroy(void);
