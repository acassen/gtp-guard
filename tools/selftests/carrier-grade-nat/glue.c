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
 * Authors:     Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include <stdlib.h>
#include <stdio.h>

#include "gtp_bpf_xsk.h"
#include "cdr_fwd.h"

void
cdr_fwd_send_ticket(struct cdr_fwd_context *ctx,
		    const uint8_t *data, int size)
{
	printf("%s\n", __func__);
}

void
cdr_fwd_entry_release(void)
{
}


struct gtp_xsk_ctx *
gtp_xsk_create(struct gtp_bpf_prog *p, struct gtp_xsk_cfg *cfg)
{
	return NULL;
}

void
gtp_xsk_release(struct gtp_xsk_ctx *xc)
{
}

void
gtp_xsk_send_notif(struct gtp_xsk_ctx *xc, gtp_xsk_notif_t cb, void *cb_ud,
		   const void *data, size_t size)
{
	printf("%s\n", __func__);
}


struct thread_master *
gtp_xsk_thread_master(struct gtp_xsk_ctx *xc)
{
	printf("%s\n", __func__);
	return NULL;
}
