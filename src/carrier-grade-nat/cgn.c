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
 *              Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

/* system includes */
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <libbpf.h>

/* local includes */
#include "libbpf.h"
#include "inet_server.h"
#include "inet_utils.h"
#include "list_head.h"
#include "tools.h"
#include "utils.h"
#include "command.h"
#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "gtp_interface_rule.h"
#include "cdr_fwd.h"
#include "cgn.h"
#include "bpf/lib/cgn-def.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	CGN utilities
 */


/* compact addr/netmask from cgn_addr array.
 * returned u64 contains cgn_addr on lower 32 bits,
 * netmask (24 => addr/24, 256 ips) on upper 64 bits.
 * 'out' must be of c->cgn_addr_n size.
 * return number of written addr/mask */
int
cgn_ctx_compact_cgn_addr(struct cgn_ctx *c, uint64_t *out)
{
	uint32_t a_n, a_mask, a_mask_bits, a_start, a_inc_next;
	int j, k = 0;

	a_start = c->cgn_addr[0];
	a_n = a_inc_next = 1;
	a_mask = a_mask_bits = 0;

	for (j = 1; j < c->cgn_addr_n; j++) {
		if (a_start + a_n == c->cgn_addr[j]) {
			a_n++;
			bool inc = a_inc_next;
			if (inc)
				a_mask = (a_mask << 1) | 1;
			a_inc_next = next_power_of_2(a_n) == a_n;

			if ((a_start & ~a_mask) == (c->cgn_addr[j] & ~a_mask)) {
				if (inc)
					a_mask_bits++;
				continue;
			}
		}

		out[k++] = a_start | ((32ULL - a_mask_bits) << 32);

		a_start = c->cgn_addr[j];
		a_n = a_inc_next = 1;
		a_mask = a_mask_bits = 0;
	}

	out[k++] = a_start | ((32ULL - a_mask_bits) << 32);

	return k;
}


int
cgn_ctx_dump(struct cgn_ctx *c, char *b, size_t s)
{
	int i, j, k = 0, p;
	uint32_t pub;
	uint64_t cgn_addr[c->cgn_addr_n];

	k += scnprintf(b + k, s - k, "  %d address%s; "
		       "%d blocks of %d ports [%d-%d]\n",
		       c->cgn_addr_n, c->cgn_addr_n > 1 ? "es" : "",
		       c->block_count, c->block_size,
		       c->port_start, c->port_end);
	j = cgn_ctx_compact_cgn_addr(c, cgn_addr);
	for (i = 0; i < j; i++) {
		pub = ntohl(cgn_addr[i]);
		k += scnprintf(b + k, s - k, "    - %s/%d\n",
			       inet_ntoa(*(struct in_addr *)&pub),
			       (int)(cgn_addr[i] >> 32));
	}

	k += scnprintf(b + k, s - k,"  flow timeouts:\n");
	k += scnprintf(b + k, s - k,"    icmp : %d\n", c->timeout_icmp);
	k += scnprintf(b + k, s - k,"    udp  : %d\n", c->timeout.udp);
	for (p = 0; p < UINT16_MAX; p++) {
		if (c->timeout_by_port[p].udp) {
			k += scnprintf(b + k, s - k,"     port % 5d: %d\n",
				       p, c->timeout_by_port[p].udp);
		}
	}
	k += scnprintf(b + k, s - k,"    tcp  : estab:%d  synfin:%d\n",
		       c->timeout.tcp_est, c->timeout.tcp_synfin);
	for (p = 0; p < UINT16_MAX; p++) {
		if (c->timeout_by_port[p].tcp_est) {
			k += scnprintf(b + k, s - k,"     port % 5d: "
				       "estab:%d  synfin:%d\n", p,
				       c->timeout_by_port[p].tcp_est,
				       c->timeout_by_port[p].tcp_synfin);
		}
	}

	return k;
}

static void
cgn_ctx_set_rules(struct cgn_ctx *c)
{
	/* everything configured/binded, set traffic rules */
	if (!c->rules_set &&
	    c->priv != NULL && c->bind_priv &&
	    c->pub != NULL && c->bind_pub) {
		struct if_rule_key_base k;
		struct gtp_if_rule ifr = {
			.from = c->priv,
			.to = c->pub,
			.key = &k,
			.key_size = sizeof (k),
			.action = 10,
			.prio = 100,
		};
		gtp_interface_rule_add(&ifr);
		ifr.from = c->pub;
		ifr.to = c->priv;
		ifr.action = 11;
		ifr.prio = 500;
		gtp_interface_rule_add(&ifr);
		c->rules_set = true;
		return;
	}

	/* something not configured/binded anymore, unset traffic rules */
	if (c->rules_set && (!c->bind_priv || !c->bind_pub)) {
		assert(c->priv && c->pub);
		gtp_interface_rule_del_iface(c->priv);
		gtp_interface_rule_del_iface(c->pub);
		c->rules_set = false;
	}
}

static void
cgn_ctx_iface_event_cb(struct gtp_interface *iface,
		       enum gtp_interface_event type,
		       void *ud, void *arg)
{
	struct cgn_ctx *c = ud;

	switch (type) {
	case GTP_INTERFACE_EV_PRG_BIND:
		if (iface == c->priv)
			c->bind_priv = true;
		if (iface == c->pub)
			c->bind_pub = true;
		break;

	case GTP_INTERFACE_EV_PRG_UNBIND:
	case GTP_INTERFACE_EV_DESTROYING:
		if (iface == c->priv)
			c->bind_priv = false;
		if (iface == c->pub)
			c->bind_pub = false;
		break;

	case GTP_INTERFACE_EV_VTY_SHOW:
	case GTP_INTERFACE_EV_VTY_WRITE:
	{
		struct vty *vty = arg;
		if (iface == c->priv)
			vty_out(vty, " carrier-grade-nat %s side network-in\n",
				c->name);
		if (iface == c->pub)
			vty_out(vty, " carrier-grade-nat %s side network-out\n",
				c->name);
		break;
	}
	}

	cgn_ctx_set_rules(c);

	if (type == GTP_INTERFACE_EV_DESTROYING) {
		if (iface == c->priv)
			c->priv = NULL;
		if (iface == c->pub)
			c->pub = NULL;
	}
}

int
cgn_ctx_attach_interface(struct cgn_ctx *c, struct gtp_interface *iface,
			 bool is_priv)
{
	struct gtp_interface **piface = is_priv ? &c->priv : &c->pub;

	if (*piface) {
		errno = EEXIST;
		return -1;
	}
	*piface = iface;
	gtp_interface_register_event(iface, cgn_ctx_iface_event_cb, c);

	return 0;
}

void
cgn_ctx_detach_interface(struct cgn_ctx *c, struct gtp_interface *iface)
{
	cgn_ctx_iface_event_cb(iface, GTP_INTERFACE_EV_DESTROYING, c, NULL);
	gtp_interface_unregister_event(iface, cgn_ctx_iface_event_cb);
}


struct cgn_ctx *
cgn_ctx_get_by_name(const char *name)
{
	struct list_head *l = &daemon_data->cgn;
	struct cgn_ctx *c;

	list_for_each_entry(c, l, next) {
		if (!strcmp(c->name, name))
			return c;
	}

	return NULL;
}

struct cgn_ctx *
cgn_ctx_alloc(const char *name)
{
	struct cgn_ctx *c = NULL;
	struct gtp_bpf_prog *p;

	/* cgn configure a bpf-program. create it if it doesn't exist */
	p = gtp_bpf_prog_get(name);
	if (p == NULL) {
		p = gtp_bpf_prog_alloc(name);
		if (p == NULL)
			return NULL;
	}

	c = calloc(1, sizeof (*c));
	if (c == NULL)
		return NULL;

	c->prg = p;
	c->bpf_data = gtp_bpf_prog_tpl_data_get(p, "cgn");
	if (c->bpf_data)
		*c->bpf_data = c;
	c->port_start = 1500;
	c->port_end = 65535;
	c->block_size = 500;
	c->block_count = (c->port_end - c->port_start) / c->block_size;
	c->port_end = c->port_start + c->block_size * c->block_count;
	c->flow_per_user = 2000;
	c->block_per_user = min(4, CGN_USER_BLOCKS_MAX);
	c->timeout.udp = CGN_PROTO_TIMEOUT_UDP;
	c->timeout.tcp_synfin = CGN_PROTO_TIMEOUT_TCP_SYNFIN;
	c->timeout.tcp_est = CGN_PROTO_TIMEOUT_TCP_EST;
	c->timeout_icmp = CGN_PROTO_TIMEOUT_ICMP;
	snprintf(c->name, GTP_NAME_MAX_LEN, "%s", name);
	list_add_tail(&c->next, &daemon_data->cgn);

	return c;
}

/* release a cgn context instance */
void
cgn_ctx_release(struct cgn_ctx *c)
{
	if (c->priv != NULL)
		cgn_ctx_detach_interface(c, c->priv);
	if (c->pub != NULL)
		cgn_ctx_detach_interface(c, c->pub);
	if (c->bpf_data != NULL)
		*c->bpf_data = NULL;
	if (c->blog_cdr_fwd != NULL)
		--c->blog_cdr_fwd->refcount;
	cgn_blog_release(c);
	free(c->cgn_addr);
	list_del(&c->next);
	free(c);
}


/* initialize cgn module */
int
cgn_init(void)
{
	return 0;
}

/* destroy cgn module */
int
cgn_destroy(void)
{
	struct list_head *l = &daemon_data->cgn;
	struct cgn_ctx *cgn, *cgn_tmp;

	list_for_each_entry_safe(cgn, cgn_tmp, l, next) {
		cgn_ctx_release(cgn);
	}
	cdr_fwd_entry_release();

	return 0;
}
