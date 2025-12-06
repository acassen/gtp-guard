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
#include "gtp_bpf_xsk.h"
#include "gtp_interface.h"
#include "cdr_fwd.h"
#include "cdr_avp.h"
#include "cgn.h"
#include "cgn-priv.h"
#include "bpf/lib/cgn-def.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	CGN log blocks allocation/release
 */

#define CDR_TYPE_ALLOC_IP		0x01
#define CDR_TYPE_RELEASE_IP		0x02

enum cdr_avp_type {
	CDR_REFERENCE_TIME_AVP	= 0x0014, /* u64 */

	CDR_PGW			= 0x1200, /* string */
	CDR_PRIV_IP46		= 0x1201, /* v4: u32, v6: u8 + 8bytes */
	CDR_PUB_IP46		= 0x1202, /* v4: u32, v6: u8 + 8bytes */
	CDR_PUB_PORT_START	= 0x1203, /* u16 */
	CDR_PUB_PORT_END	= 0x1204, /* u16 */
	CDR_DURATION		= 0x1205, /* u32, seconds */
	CDR_PUB_IP6		= 0x1210, /* v4: u32, v6: u8 + 8bytes */
};

void
cgn_ctx_log_send(struct cgn_ctx *c, const struct cgn_v4_block_log *e, size_t size)
{
	uint8_t data[400 + sizeof (struct cdr_header)];
	struct cdr_header *hdr = (struct cdr_header *)(data);
	uint8_t *dst = (uint8_t *)(hdr + 1);
	uint8_t *end = data + sizeof (data);
	time_t now = time(NULL);
	uint16_t port;

	/* printf("GOT log to send: alloc:%d priv=%x cgn=%x port=%d/%d dur=%d\n", */
	/*        e->alloc, e->priv_addr, e->cgn_addr, */
	/*        e->port_start, e->port_size, e->duration); */

	if (c->blog_cdr_fwd == NULL || c->blog_cdr_fwd->ctx == NULL)
		return;

	memset(hdr, 0x00, sizeof (*hdr));
	hdr->version = CDR_VERSION;
	hdr->ne_type = CDR_NE_CGNLOG;
	hdr->cdr_type = e->alloc ? CDR_TYPE_ALLOC_IP : CDR_TYPE_RELEASE_IP;

	now = htobe64(now);
	cdr_avp_append(&dst, end - dst, CDR_REFERENCE_TIME_AVP,
		       sizeof (now), &now);
	++hdr->nb_avp;

	if (e->prefix[0]) {
		cdr_avp_append_str(&dst, end - dst, CDR_PGW, e->prefix);
		++hdr->nb_avp;
	}

	cdr_avp_append(&dst, end - dst, CDR_PRIV_IP46, 4, &e->priv_addr);
	++hdr->nb_avp;

	cdr_avp_append(&dst, end - dst, CDR_PUB_IP46, 4, &e->cgn_addr);
	++hdr->nb_avp;

	if (e->port_size) {
		port = htons(e->port_start + e->port_size - 1);
		cdr_avp_append(&dst, end - dst, CDR_PUB_PORT_END, 2, &port);
		port = htons(e->port_start);
		cdr_avp_append(&dst, end - dst, CDR_PUB_PORT_START, 2, &port);
		hdr->nb_avp += 2;
	}

	uint32_t duration = htonl(e->duration);
	cdr_avp_append(&dst, end - dst, CDR_DURATION, 4, &duration);
	++hdr->nb_avp;

	hdr->size = htobe16(dst - (uint8_t *)(hdr + 1));

	cdr_fwd_send_ticket(c->blog_cdr_fwd->ctx, data,
			    sizeof (*hdr) + be16toh(hdr->size));
}


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

int
cgn_ctx_start(struct cgn_ctx *c)
{
	struct cgn_bpf_ctx *x = c->bpf_data;
	uint32_t i, k;
	uint8_t uu = 1;

	if (x == NULL)
		return -1;

	/* initialize once */
	if (c->initialized)
		return 0;
	c->initialized = true;

	/* init af_xdp library
	 * cgn_flow will be initialized from af_xdp thread */
	struct gtp_xsk_cfg xcfg = {
		.name = "cgn",
		.priv = c,
		.thread_init = cgn_flow_init,
		.thread_release = cgn_flow_release,
		.pkt_read = cgn_flow_read_pkt,
		.egress_xdp_hook = true,
	};
	x->xc = gtp_xsk_create(x->p, &xcfg);
	if (x->xc == NULL) {
		c->initialized = false;
		return -1;
	}

	/* fill ippub pool addr (for traffic selector) */
	for (i = 0; i < c->cgn_addr_n; i++) {
		k = c->cgn_addr[i];
		bpf_map__update_elem(x->v4_pool_addr, &k, sizeof (k),
				     &uu, sizeof (uu), 0);

	}

	return 0;
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
	struct cgn_ctx *c;

	c = calloc(1, sizeof (*c));
	if (c == NULL)
		return NULL;

	snprintf(c->name, sizeof (c->name), "%s", name);
	list_add_tail(&c->next, &daemon_data->cgn);
	c->port_start = 1025;
	c->port_end = 65535;
	c->block_size = CGN_BLOCK_SIZE_DEF;
	c->block_count = (c->port_end - c->port_start) / c->block_size;
	c->port_end = c->port_start + c->block_size * c->block_count;
	c->flow_per_user = CGN_FLOW_PER_USER_DEF;
	c->block_per_user = CGN_BLOCK_PER_USER_DEF;
	c->max_user = CGN_USER_MAX_DEF;
	c->max_flow = CGN_USER_MAX_DEF * CGN_FLOW_PER_USER_DEF / 100;
	c->timeout.udp = CGN_PROTO_TIMEOUT_UDP;
	c->timeout.tcp_synfin = CGN_PROTO_TIMEOUT_TCP_SYNFIN;
	c->timeout.tcp_est = CGN_PROTO_TIMEOUT_TCP_EST;
	c->timeout_icmp = CGN_PROTO_TIMEOUT_ICMP;

	return c;
}

/* release a cgn context instance */
void
cgn_ctx_release(struct cgn_ctx *c)
{
	if (c->bpf_data != NULL) {
		if (c->bpf_data->xc != NULL)
			gtp_xsk_release(c->bpf_data->xc);
		c->bpf_data = NULL;
		c->bpf_ifrules = NULL;
		list_del(&c->bpf_list);
	}
	if (c->blog_cdr_fwd != NULL)
		--c->blog_cdr_fwd->refcount;
	free(c->cgn_addr);
	list_del(&c->next);
	free(c);
}


/* initialize cgn module */
int
cgn_init(void)
{
	/* not called from anywhere */
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
