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

struct gtp_if_rule
{
	struct gtp_interface *from;
	struct gtp_interface *to;
	void *key;
	int key_size;
	int action;
	int prio;
};

typedef int (*key_stringify_cb_t)(const struct gtp_if_rule *, char *, int, bool);

/* Prototypes */
int gtp_interface_rule_add(struct gtp_if_rule *);
void gtp_interface_rule_del(struct gtp_if_rule *);
void gtp_interface_rule_del_iface(struct gtp_interface *);
int gtp_interface_rule_show_stored(struct gtp_bpf_prog *p, void *arg);
int gtp_interface_rule_show(struct gtp_bpf_prog *p, void *arg);
void gtp_interface_rule_set_custom_key_stringify(struct gtp_bpf_prog *p,
						 key_stringify_cb_t cb);
