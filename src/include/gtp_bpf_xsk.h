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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

struct gtp_interface;
struct bpf_object;
struct gtp_xsk_ctx;
struct gtp_bpf_xsk;
struct gtp_bpf_prog;

#define GTP_XSK_DROP	1
#define GTP_XSK_TX	2
#define GTP_XSK_QUEUE	3

struct thread_master;
struct gtp_xsk_desc;

typedef int (*gtp_xsk_init_cb_t)(void *);
typedef void (*gtp_xsk_release_cb_t)(void *);
typedef int (*gtp_xsk_pkt_read_cb_t)(void *priv, struct gtp_xsk_desc *);
typedef void (*gtp_xsk_notif_t)(void *, void *, size_t);

/* a packet descriptor, hold in AF_XDP's umem */
struct gtp_xsk_desc
{
	void			*data;		// pointer to umem
	uint32_t		len;		// packet len
	time_t			alloc_time;	// in seconds
	uint8_t			user_data[];	// of pkt_cb_user_size
};

struct gtp_xsk_cfg
{
	char			name[12];	/* user's name */
	void			*priv;		/* user's priv, for callbacks */

	gtp_xsk_init_cb_t	thread_init;
	gtp_xsk_release_cb_t	thread_release;
	gtp_xsk_pkt_read_cb_t	pkt_read;

	/* packet re-circulation */
	bool			egress_xdp_hook;	/* enable it */
};

/* gtp_xsk.c */
void gtp_xsk_tx(struct gtp_xsk_ctx *xc, int queue_id, struct gtp_xsk_desc *pkt);
struct thread_master *gtp_xsk_thread_master(struct gtp_xsk_ctx *xc);
void gtp_xsk_send_notif(struct gtp_xsk_ctx *xc, gtp_xsk_notif_t cb, void *cb_ud,
			const void *data, size_t size);
struct gtp_xsk_ctx *gtp_xsk_create(struct gtp_bpf_prog *p, struct gtp_xsk_cfg *cfg);
void gtp_xsk_release(struct gtp_xsk_ctx *xc);
