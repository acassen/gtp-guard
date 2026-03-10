/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Protocol). GTP is
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
 * Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
 */

#pragma once

struct gtp_bpf_prog;
struct gtp_bpf_capture_ctx;
struct gtp_capture_file;
struct gtp_capture_entry;

#define GTP_CAPTURE_DEFAULT_CAPLEN		96

#define GTP_CAPTURE_FL_INGRESS			0x0001
#define GTP_CAPTURE_FL_EGRESS			0x0002
#define GTP_CAPTURE_FL_DIRECTION_MASK		0x0003
#define GTP_CAPTURE_FL_USE_TRACEFUNC		0x0004
#define GTP_CAPTURE_FL_NEED_BPF_UPDATE		0x0008

typedef void (*gtp_capture_entry_cb_t)(void *, struct gtp_capture_entry *);

struct gtp_capture_entry
{
	uint16_t			flags;
	uint16_t			cap_len;
	uint16_t			entry_id;

	/* called when capture file is closed */
	gtp_capture_entry_cb_t		opened_cb;
	gtp_capture_entry_cb_t		closed_cb;
	void				*cb_ud;

	/* private use */
	struct gtp_bpf_capture_ctx	*bcc;
	struct gtp_capture_file		*cf;
};

int gtp_capture_start(struct gtp_capture_entry *e, struct gtp_bpf_prog *p,
		      const char *name);
void gtp_capture_stop(struct gtp_capture_entry *e);
int gtp_capture_start_all(struct gtp_capture_entry *e, struct gtp_bpf_prog *p,
			  const char *name);
int gtp_capture_start_iface(struct gtp_capture_entry *e, struct gtp_bpf_prog *p,
			    const char *name, int iface);
int gtp_capture_init(void);
void gtp_capture_release(void);
