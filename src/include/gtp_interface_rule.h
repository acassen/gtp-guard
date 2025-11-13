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
struct gtp_interface_rules_ctx;
struct gtp_bpf_prog;

struct gtp_if_rule
{
	struct gtp_interface	*from;
	struct gtp_interface	*to;
	void			*key;
	int			key_size;
	int			action;
	int			prio;
};

typedef void (*gtp_interface_rules_ctx_exec_cb_t)(void *ud, struct gtp_interface *,
						  bool, struct gtp_interface *);

struct gtp_interface_rules_ops {
	void	(*rule_set)(void *, struct gtp_interface *, bool,
			    struct gtp_interface *, bool);
	int	(*key_stringify)(const struct gtp_if_rule *, char *, int, bool);

	void	*ud;
};


/* Prototypes */
int gtp_interface_rule_set(struct gtp_if_rule *, bool add);
struct gtp_interface_rules_ctx *gtp_interface_rules_ctx_new(const struct gtp_interface_rules_ops *);
void gtp_interface_rules_ctx_release(struct gtp_interface_rules_ctx *);
int gtp_interface_rules_ctx_add(struct gtp_interface_rules_ctx *, struct gtp_interface *,
			       bool ingress);
void gtp_interface_rules_ctx_del(struct gtp_interface_rules_ctx *, struct gtp_interface *,
				 bool ingress);
void gtp_interface_rules_ctx_exec(struct gtp_interface_rules_ctx *, bool,
				  gtp_interface_rules_ctx_exec_cb_t);
int gtp_interface_rules_ctx_list_bound(struct gtp_interface_rules_ctx *, bool,
				       struct gtp_interface **, int);
int gtp_interface_rules_ctx_list(struct gtp_interface_rules_ctx *, bool,
				 struct gtp_interface **, int);
int gtp_interface_rule_show_stored(struct gtp_bpf_prog *p, void *arg);
int gtp_interface_rule_show(struct gtp_bpf_prog *p, void *arg);
