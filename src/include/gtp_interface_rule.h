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

struct gtp_bpf_interface_rule;
struct gtp_bpf_prog;

struct gtp_if_rule
{
	struct gtp_bpf_interface_rule	*bir;
	struct gtp_interface		*from;
	int				prio;

	int (*key_stringify)(const struct gtp_if_rule *, char *, int, bool);
	void				*key;
	int				key_size;

	int				action;
	int				table_id;
	uint32_t			force_ifindex;
};


/* Prototypes */
int gtp_interface_rule_set(struct gtp_if_rule *, bool add);
void gtp_interface_rule_set_auto_input_rule(struct gtp_interface *iface, bool set);
int gtp_interface_rule_show_attr(struct gtp_bpf_prog *p, void *arg);
int gtp_interface_rule_show_stored(struct gtp_bpf_prog *p, void *arg);
int gtp_interface_rule_show(struct gtp_bpf_prog *p, void *arg);
