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

#include "pfcp_teid.h"
#include "pfcp_session.h"

struct pfcp_router;
struct gtp_bpf_prog;

struct pfcp_urr_cmd
{
	struct upf_urr_cmd_req	uc;
	struct list_head	clist;
	struct list_head	plist;
};

struct pfcp_bpf_data
{
	struct list_head	pfcp_router_list;

	struct bpf_map		*user_egress;
	struct bpf_map		*user_ingress;

	/* urr */
	struct bpf_map		*upf_urr;
	uint8_t			*urr_alloc;
	int			urr_alloc_cur;
	int			urr_ctl_prog_fd;
	struct pfcp_bpf_data_thread **ctl_task;

	/* upf_events ring_buffer */
	struct ring_buffer	*rbuf;
	struct thread		*rbuf_th;
};

/* Prototypes */
struct upf_urr_cmd_req *pfcp_bpf_urr_alloc_cmd(struct pfcp_session *s);
int pfcp_bpf_urr_ctl(struct pfcp_session *s, struct upf_urr_cmd_req *uc);
int pfcp_bpf_teid_action(struct pfcp_router *r, int action, struct pfcp_teid *t,
			 struct ue_ip_address *ue);
int pfcp_bpf_action(struct pfcp_router *rtr, struct pfcp_fwd_rule *r,
		    struct pfcp_teid *t, struct ue_ip_address *ue);
int pfcp_bpf_teid_vty(struct vty *vty, struct gtp_bpf_prog *p, int dir,
		      struct ue_ip_address *ue, struct pfcp_teid *t);
uint32_t pfcp_bpf_alloc_urr_idx(struct pfcp_session *s);
void pfcp_bpf_release_urr_idx(struct pfcp_session *s, uint32_t urr_idx);
