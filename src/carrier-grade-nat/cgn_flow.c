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
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libbpf.h>

/* local includes */
#include "list_head.h"
#include "utils.h"
#include "jhash.h"
#include "thread.h"
#include "logger.h"
#include "gtp_bpf_xsk.h"
#include "cgn-priv.h"
#include "bpf/lib/cgn-def.h"
#include "bpf/lib/xsk-def.h"


//#define CGN_FLOW_DEBUG		1

#ifdef CGN_FLOW_DEBUG
# define dbg_printf(Fmt, ...) printf(Fmt, ## __VA_ARGS__)
#else
# define dbg_printf(...)
#endif


/* forward decl. */
static void _user_flow_gc(struct cgn_bpf_ctx *x, struct cgn_ctx *c, struct cgn_user *u);


static inline uint64_t
_clock_mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
}

static inline uint8_t
_proto_pack(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return 0;
	case IPPROTO_UDP:
		return 1;
	case IPPROTO_ICMP:
		return 2;
	default:
		return 3;
	}
}


/* hpriv: delete an entry by port + flow_idx */
static void
_hpriv_unset(struct cgn_user *u, uint16_t priv_port, uint16_t flow_idx)
{
	uint32_t m, h, nh, e, w, v;

	m = u->hpriv_size - 1;
	v = (priv_port << 16) | flow_idx;
	for (h = priv_port & m; u->hpriv[h] && u->hpriv[h] != v; )
		h = (h + 1) & m;

	/* entry not found */
	if (!u->hpriv[h])
		return;

	--u->hpriv_n;

	/* rehash next entries until an empty slot is found */
	for (w = 0, e = h, h = (h + 1) & m; u->hpriv[h]; h = (h + 1) & m) {
		if (h == 0)
			w = 1;
		nh = (u->hpriv[h] >> 16) & m;
		if ((w == 0 && (nh <= e || nh > h)) ||
		    (w == 1 && (nh <= e && nh > h))) {
			u->hpriv[e] = u->hpriv[h];
			e = h;
			w = 0;
		}
	}

	u->hpriv[e] = 0;
}


/* allocate a new ipv4 flow */
static struct cgn_v4_flow *
_flow_alloc(struct cgn_ctx *c, struct cgn_user *u)
{
	struct cgn_v4_flow *f;
	uint32_t k;

	if (unlikely(u->flow_n >= c->flow_per_user ||
		     c->flow_n >= c->max_flow))
		return NULL;

	f = &u->flow[u->flow_next];
	for (k = 0; k < u->flow_size; k++) {
		if (!f->proto) {
			if (++u->flow_next == u->flow_size)
				u->flow_next = 0;
			++u->flow_n;
			++c->flow_n;
			return f;
		}

		++f;
		if (++u->flow_next == u->flow_size) {
			u->flow_next = 0;
			f = u->flow;
		}
	}

	return NULL;
}

static inline void
_flow_release(struct cgn_ctx *c, struct cgn_user *u, struct cgn_v4_flow *f)
{
	f->proto = 0;
	--u->flow_n;
	--c->flow_n;
}

static int
_flow_port_is_free(struct cgn_bpf_ctx *x, struct cgn_v4_flow_pub_key *pub_k)
{
	struct cgn_v4_flow_pub pub_f;
	int ret;

	ret = bpf_map__lookup_elem(x->v4_pub_flows, pub_k, sizeof (*pub_k),
				   &pub_f, sizeof (pub_f), 0);
	if (ret) {
		if (errno == ENOENT)
			return 1;
		log_message(LOG_INFO, "lookup map{v4_pub_flows}: %m");
		return -1;
	}
	return 0;
}

/* allocate and return a new cgn port, not already used for the ipv4 quintuplet */
static int
_flow_port_alloc(struct cgn_bpf_ctx *x, struct cgn_ctx *c,
		 struct cgn_v4_block *bl, struct cgn_v4_flow *f)
{
	uint8_t proto = _proto_pack(f->proto);
	uint32_t i;
	uint16_t p;
	int r;

	dbg_printf("would alloc port from block, proto:%d next:%d in [%d-%d]\n",
	       proto, bl->port_next[proto], bl->port_start, bl->port_end);
	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = htonl(bl->ipbl->cgn_addr),
		.pub_addr = f->pub_addr,
		.pub_port = f->pub_port,
		.proto = f->proto,
	};
	for (i = 0; i < c->block_size; i++) {
		p = bl->port_next[proto];
		if (++bl->port_next[proto] >= bl->port_end)
			bl->port_next[proto] = bl->port_start;

		/* check in bpf map that it is free */
		pub_k.cgn_port = htons(p);
		r = _flow_port_is_free(x, &pub_k);
		if (r == 1) {
			++bl->refcnt;
			++bl->port_uniq[proto];
			f->cgn_port = pub_k.cgn_port;
			return 0;
		}
		if (r < 0)
			return -1;
	}

	bl->port_next[proto] = bl->port_start;
	return -1;
}

/* return in seconds */
static inline int64_t
_flow_timeout(struct cgn_ctx *c, uint8_t proto, uint16_t port, uint8_t state)
{
	switch (proto) {
	case IPPROTO_UDP:
		return c->timeout_by_port[port].udp ?: c->timeout.udp;
	case IPPROTO_TCP:
		if (state == 1)
			return c->timeout_by_port[port].tcp_est ?:
				c->timeout.tcp_est;
		return c->timeout_by_port[port].tcp_synfin ?:
			c->timeout.tcp_synfin;
	case IPPROTO_ICMP:
		return c->timeout_icmp;
	default:
		return CGN_FLOW_DEFAULT_TIMEOUT;
	}
}

/* return in ns */
static inline int64_t
_flow_timeout_remain(struct cgn_bpf_ctx *x, struct cgn_ctx *c,
		     const struct cgn_user *u, const struct cgn_v4_flow *f)
{
	struct cgn_v4_flow_priv priv_f;
	int64_t timeout;
	int ret;

	struct cgn_v4_flow_priv_key priv_k = {
		.priv_addr = htonl(u->addr),
		.pub_addr = f->pub_addr,
		.priv_port = f->priv_port,
		.pub_port = f->pub_port,
		.proto = f->proto,
	};

	ret = bpf_map__lookup_elem(x->v4_priv_flows, &priv_k, sizeof (priv_k),
				   &priv_f, sizeof (priv_f), 0);
	if (ret) {
		log_message(LOG_INFO, "map lookup{v4_priv_flows}: %m");
		return 0;
	}

	timeout = _flow_timeout(c, f->proto, ntohs(f->pub_port),
				priv_f.proto_state) * NSEC_PER_SEC;

	return ((int64_t)priv_f.last_use - (int64_t)c->now_ns) + timeout;
}

static void
_block_log(struct cgn_ctx *c, struct cgn_user *u, struct cgn_v4_block *bl, bool alloc)
{
	struct cgn_v4_block_log e;
	struct gtp_xsk_ctx *xc;

	if (c->bpf_data == NULL || (xc = c->bpf_data->xc) == NULL)
		return;

	e.alloc = alloc;
	strcpy(e.prefix, "to-be-set");
	e.cgn_addr = u->cgn_addr;
	e.priv_addr = u->addr;
	e.duration = c->now_ns - bl->alloc_time;
	e.port_start = bl->port_start;
	e.port_size = bl->port_end - bl->port_start;

	/* send to master thread */
	gtp_xsk_send_notif(xc, (gtp_xsk_notif_t)cgn_ctx_log_send, c, &e, sizeof (e));
}

/* allocate a new fresh block for user 'u' */
static struct cgn_v4_block *
_block_alloc(struct cgn_ctx *c, struct cgn_user *u)
{
	struct cgn_v4_ipblock *ipbl;
	struct cgn_v4_block *bl;
	unsigned i, ip_usage;

	if (unlikely(c->cgn_addr_n == 0 || u->bl_n == c->block_per_user)) {
		dbg_printf("user allocated all its blocks %d/%d!\n",
			   u->bl_n, c->block_per_user);
		return NULL;
	}

	/* force allocation on the same public address */
	if (u->bl_n) {
		ipbl = u->bl[0]->ipbl;
		if (likely(ipbl->used < c->block_count))
			goto takeme;

		dbg_printf("cannot alloc new block, ip=%x is full!\n",
			   ipbl->cgn_addr);
		return NULL;
	}

	/* get the least used address */
	for (i = 0; i < c->block_count; i++) {
		if (!list_empty(&c->addr_slots[i])) {
			ipbl = list_first_entry(&c->addr_slots[i],
						struct cgn_v4_ipblock,
						addr_list);
			goto takeme;
		}
	}

	dbg_printf("no more available block\n");
	return NULL;

 takeme:
	ip_usage = ipbl->used * 100 / c->block_count;
	if ((ip_usage < 70 && u->bl_n >= c->block_per_user) ||
	    (ip_usage >= 70 && u->bl_n >= c->block_per_user / 2)) {
		dbg_printf("user reached max block allocation (ip_usage=%d)\n",
			   ip_usage);
		return NULL;
	}

	/* get next available block in address block */
	for (i = 0; i < c->block_count; i++) {
		bl = &ipbl->bl[ipbl->next];
		ipbl->next = (ipbl->next + 1) % c->block_count;
		if (!bl->alloc_time)
			break;
	}

	u->bl[u->bl_n++] = bl;

	--c->addr_stats[ipbl->used];
	++ipbl->used;
	++c->addr_stats[ipbl->used];
	list_move(&ipbl->addr_list, &c->addr_slots[ipbl->used]);

	bl->alloc_time = c->now_ns;
	for (i = 0; i < ARRAY_SIZE(bl->port_next); i++)
		bl->port_next[i] = bl->port_start;

	u->cgn_addr = ipbl->cgn_addr;

	_block_log(c, u, bl, 1);

	return bl;
}

static void
_block_release(struct cgn_ctx *c, struct cgn_user *u, struct cgn_v4_block *bl)
{
	struct cgn_v4_ipblock *ipbl = bl->ipbl;

	dbg_printf("%s: %x:%d\n", __func__, ipbl->cgn_addr, bl->port_start);

	bl->alloc_time = 0;

	_block_log(c, u, bl, 0);

	--c->addr_stats[ipbl->used];
	--ipbl->used;
	++c->addr_stats[ipbl->used];
	list_move(&ipbl->addr_list, &c->addr_slots[ipbl->used]);
}


/*
 * return allocated flow, NULL if not available
 * (user limit or global resources exhausted)
 */
static struct cgn_v4_flow *
_flow_create(struct cgn_bpf_ctx *x, struct cgn_ctx *c, struct cgn_user *u,
	     const struct cgn_v4_flow_priv_key *pk)
{
	struct cgn_v4_block *bl;
	struct cgn_v4_flow *f, *f_reuse = NULL;
	bool reloop = false;
	uint32_t m, h;
	uint64_t gc_at;

	if (unlikely(!pk->proto || !pk->priv_port))
		return NULL;

	/* set on hpriv next empty slot */
	m = u->hpriv_size - 1;
	for (h = pk->priv_port & m; u->hpriv[h]; h = (h + 1) & m) {
		if (pk->priv_port == u->hpriv[h] >> 16 &&
		    (f = &u->flow[u->hpriv[h] & 0xffff]) &&
		    f->proto == pk->proto) {
			/* same quintuplet */
			if (f->pub_addr == pk->pub_addr &&
			    f->pub_port == pk->pub_port) {
				dbg_printf("matching priv flow port=%d/%d, "
					   "use it, do not realloc\n",
					   pk->priv_port, f->priv_port);
				return f;
			}
			/* partial match */
			f_reuse = f;
		}
	}

	f = _flow_alloc(c, u);
	if (unlikely(f == NULL)) {
		dbg_printf("cannot alloc more flow\n");
		return NULL;
	}
	f->flags = 0;
	f->priv_port = pk->priv_port;
	f->pub_port = pk->pub_port;
	f->pub_addr = pk->pub_addr;

	u->hpriv[h] = (pk->priv_port << 16) | (f - u->flow);
	++u->hpriv_n;

	/* bring gc_next closer */
	gc_at = _flow_timeout(c, pk->proto, ntohs(f->pub_port), 0) *
		NSEC_PER_SEC + c->now_ns;
	if (!u->flow_gc_next || gc_at < u->flow_gc_next)
		u->flow_gc_next = gc_at;

	/* partial match of {priv_addr,priv_port,proto}, reuse cgn_port */
	if (f_reuse != NULL) {
		/* be sure that quintuplet on pub side does not exist */
		struct cgn_v4_flow_pub_key pub_k = {
			.cgn_addr = htonl(u->cgn_addr),
			.pub_addr = f->pub_addr,
			.cgn_port = f_reuse->cgn_port,
			.pub_port = f->pub_port,
			.proto = pk->proto,
		};
		if (_flow_port_is_free(x, &pub_k) == 1) {
			f->proto = pk->proto;
			f->flags |= CGN_FLOW_FL_SHARED_PORT;
			f->cgn_port = f_reuse->cgn_port;
			f->bl_idx = f_reuse->bl_idx;
			++u->bl[f->bl_idx]->refcnt;
			dbg_printf("cgn port reused: %d priv:%d\n",
				   ntohs(f->cgn_port), ntohs(pk->priv_port));
			return f;
		}
	}

	/* allocate a new cgn_port */
	while (1) {
		if (unlikely(u->bl_next >= u->bl_n)) {
			if (u->bl_n > 1 && !reloop) {
				/* try again once in all allocated blocks */
				u->bl_next = 0;
				bl = u->bl[0];
				reloop = true;
			} else if ((bl = _block_alloc(c, u)) == NULL) {
				_flow_release(c, u, f);
				return NULL;
			}
		} else {
			bl = u->bl[u->bl_next];
		}
		dbg_printf("allocate new cgn port, use block idx: %d/%d\n",
			   u->bl_next, u->bl_n);

		f->proto = pk->proto;
		if (!_flow_port_alloc(x, c, bl, f)) {
			f->bl_idx = u->bl_next;
			dbg_printf("cgn port allocated: %d priv:%d\n",
				   ntohs(f->cgn_port), ntohs(pk->priv_port));

			return f;

		}
		f->proto = 0;

		dbg_printf("cannot allocate new cgn port priv_port:%d, force gc\n",
			   ntohs(pk->priv_port));
		_user_flow_gc(x, c, u);
		++u->bl_next;
	}
	return NULL;
}

static struct cgn_user *
_user_get(struct cgn_ctx *c, uint32_t priv_addr, bool alloc)
{
	struct cgn_user *u;
	uint32_t h = jhash_1word(priv_addr, 0) & (c->huser_size - 1);
	size_t hpriv_size, size, flow_size;
	void *ptr;

	hlist_for_each_entry(u, &c->huser[h], hlist) {
		if (u->addr == priv_addr)
			return u;
	}
	if (!alloc || c->user_n >= c->max_user)
		return NULL;

	/* alloc 20% more flows to reduce fragmentation */
	flow_size = c->flow_per_user * 6 / 5;

	hpriv_size = next_power_of_2(flow_size);
	size = sizeof (*u)
		+ (c->block_per_user * sizeof (struct cgn_v4_block *))
		+ (flow_size * sizeof (struct cgn_v4_flow))
		+ (hpriv_size * sizeof (uint32_t *));

	u = calloc(1, size);
	if (u == NULL)
		return NULL;
	u->addr = priv_addr;
	list_add(&u->list, &c->user_list);
	hlist_add_head(&u->hlist, &c->huser[h]);
	u->bl_n = 0;
	u->bl_next = 0;
	u->flow_size = flow_size;
	u->flow_n = 0;
	u->flow_next = 0;
	u->flow_gc_next = 0;
	u->hpriv_size = hpriv_size;

	ptr = u + 1;
	u->bl = (struct cgn_v4_block **)(ptr);
	ptr += c->block_per_user * sizeof (struct cgn_v4_block *);
	u->flow = ptr;
	ptr += u->flow_size * sizeof (struct cgn_v4_flow);
	u->hpriv = ptr;
	/* memset(u->hpriv, 0x00, hpriv_size * sizeof (uint32_t *)); */

	++c->user_n;

	return u;
}

static void
_user_del(struct cgn_ctx *c, struct cgn_user *u)
{
	hlist_del(&u->hlist);
	list_del(&u->list);
	free(u);
	--c->user_n;
}

/* do a garbage collection on all flows of user 'u' */
static void
_user_flow_gc(struct cgn_bpf_ctx *x, struct cgn_ctx *c, struct cgn_user *u)
{
	unsigned k, t = u->flow_n;
	struct cgn_v4_block *bl;
	struct cgn_v4_flow *f;
	uint16_t flow_idx;
	int64_t to;
	int ret;

	if (u->flow_gc_next > c->now_ns) {
		dbg_printf("%s: skip, not flow_gc_next\n", __func__);
		return;
	}
	u->flow_gc_next = 0;

	for (f = u->flow, k = 0; k < t && f < u->flow + u->flow_size; ++f) {
		if (!f->proto)
			continue;

		to = _flow_timeout_remain(x, c, u, f);
		if (to > 0) {
			to += c->now_ns;
			if (!u->flow_gc_next || to < u->flow_gc_next)
				u->flow_gc_next = to;
			continue;
		}

		/* delete flow entry */
		flow_idx = f - u->flow;
		bl = u->bl[f->bl_idx];

		dbg_printf("flow_free bl:{ref:%d} u:{bl_idx:%d/%d} addr=%x "
			   "priv:%d pub:%d\n", bl->refcnt, f->bl_idx, u->bl_n,
			   u->cgn_addr, ntohs(f->priv_port), ntohs(f->cgn_port));

		struct cgn_v4_flow_pub_key pub_k = {
			.cgn_addr = htonl(u->cgn_addr),
			.pub_addr = f->pub_addr,
			.cgn_port = f->cgn_port,
			.pub_port = f->pub_port,
			.proto = f->proto,
		};
		ret = bpf_map__delete_elem(x->v4_pub_flows, &pub_k, sizeof (pub_k), 0);
		if (ret)
			log_message(LOG_INFO, "map delete{v4_pub_flows}: %m");

		struct cgn_v4_flow_priv_key priv_k = {
			.priv_addr = htonl(u->addr),
			.pub_addr = f->pub_addr,
			.priv_port = f->priv_port,
			.pub_port = f->pub_port,
			.proto = f->proto,
		};
		ret = bpf_map__delete_elem(x->v4_priv_flows, &priv_k, sizeof (priv_k), 0);
		if (ret)
			log_message(LOG_INFO, "map delete{v4_priv_flows}: %m");

		_hpriv_unset(u, f->priv_port, flow_idx);
		--bl->refcnt;
		if (!(f->flags & CGN_FLOW_FL_SHARED_PORT))
			--bl->port_uniq[_proto_pack(f->proto)];
		_flow_release(c, u, f);
		if (!k++ && u->flow_next > flow_idx)
			u->flow_next = flow_idx;
	}
}

static void
_user_block_gc(struct cgn_ctx *c, struct cgn_user *u)
{
	struct cgn_v4_block *bl;
	struct cgn_v4_flow *f;
	int i, j;

	for (i = 0; i < u->bl_n; i++) {
		bl = u->bl[i];
		if (bl->refcnt)
			continue;
		_block_release(c, u, bl);
		if (i + 1 != u->bl_n) {
			u->bl[i] = u->bl[--u->bl_n];
			for (j = 0; j < u->flow_size; j++) {
				f = &u->flow[j];
				if (f->proto && f->bl_idx == u->bl_n)
					f->bl_idx = i;
			}
			--i;
		} else {
			--u->bl_n;
		}
	}
}

int
cgn_flow_gc(struct cgn_ctx *c)
{
	struct cgn_user *u = c->user_gc_cur;
	struct cgn_user *u_tmp;
	int k = 0;

	if (list_empty(&c->user_list) || c->bpf_data == NULL)
		return 0;
	if (u == NULL)
		u = list_first_entry(&c->user_list, struct cgn_user, list);

	list_for_each_entry_safe_from(u, u_tmp, &c->user_list, list) {
		if (k++ > 100) {
			c->user_gc_cur = u;
			return 1;
		}

		/* free timeouted flows */
		_user_flow_gc(c->bpf_data, c, u);

		/* free unused blocks */
		_user_block_gc(c, u);

		/* free user */
		if (!u->bl_n)
			_user_del(c, u);
	}
	c->user_gc_cur = NULL;
	return 0;
}

static void
_flow_gc(struct thread *th)
{
	struct cgn_ctx *c = THREAD_ARG(th);

	c->now_ns = _clock_mono_ns();
	c->user_gc_th = thread_add_timer(th->master, _flow_gc, c, TIMER_HZ);
	cgn_flow_gc(c);
}


static void
_flow_add_to_map(struct cgn_bpf_ctx *x, struct cgn_ctx *c,
		 const struct cgn_v4_flow_priv_key *priv_k,
		 uint32_t cgn_addr, uint16_t cgn_port)
{
	int ret;

	/* add pub entry */
	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = cgn_addr,
		.pub_addr = priv_k->pub_addr,
		.cgn_port = cgn_port,
		.pub_port = priv_k->pub_port,
		.proto = priv_k->proto,
	};
	struct cgn_v4_flow_pub pub_d = {
		.priv_addr = priv_k->priv_addr,
		.priv_port = priv_k->priv_port,
	};
	ret = bpf_map__update_elem(x->v4_pub_flows, &pub_k, sizeof (pub_k),
				   &pub_d, sizeof (pub_d), BPF_NOEXIST);
	if (ret) {
		log_message(LOG_INFO, "map insert{v4_pub_flows}: %m %d", ret);
		dbg_printf("flow key is cgn=%x:%d pub=%x:%d proto=%d\n",
			   ntohl(pub_k.cgn_addr), ntohs(pub_k.cgn_port),
			   ntohl(pub_k.pub_addr), ntohs(pub_k.pub_port),
			   pub_k.proto);

		return;
	}

	/* add priv entry */
	struct cgn_v4_flow_priv priv_d = {
		.cgn_addr = cgn_addr,
		.cgn_port = cgn_port,
		.last_use = c->now_ns,
	};
	ret = bpf_map__update_elem(x->v4_priv_flows, priv_k, sizeof (*priv_k),
				   &priv_d, sizeof (priv_d), BPF_NOEXIST);
	if (ret) {
		log_message(LOG_INFO, "map insert{v4_priv_flows}: %m");
		dbg_printf("flow key is priv=%x:%d pub=%x:%d proto=%d\n",
			   ntohl(priv_k->priv_addr), ntohs(priv_k->priv_port),
			   ntohl(priv_k->pub_addr), ntohs(priv_k->pub_port),
			   priv_k->proto);
		return;
	}
}

/* called in xsk thread context */
int
cgn_flow_read_pkt(void *priv, struct gtp_xsk_desc *pkt)
{
	struct cgn_ctx *c = priv;
	struct cgn_bpf_ctx *x = c->bpf_data;
	struct cgn_v4_flow_priv_key *pk;
	struct gtp_xsk_metadata *md;
	struct cgn_v4_flow *f;
	struct cgn_user *u;

	/* pk and md are set in metadata in ebpf prog */
	pk = (struct cgn_v4_flow_priv_key *)(pkt->data) - 1;
	md = (struct gtp_xsk_metadata *)(pk) - 1;

	dbg_printf("read pkt %x:%d %x:%d %d\n",
		       ntohl(pk->priv_addr), ntohs(pk->priv_port),
		       ntohl(pk->pub_addr), ntohs(pk->pub_port), pk->proto);

	u = _user_get(c, ntohl(pk->priv_addr), true);
	if (u == NULL)
		return GTP_XSK_DROP;

	f = _flow_create(x, c, u, pk);
	if (f == NULL)
		return GTP_XSK_DROP;

	if (!(f->flags & CGN_FLOW_FL_IN_MAP)) {
		_flow_add_to_map(x, c, pk, htonl(u->cgn_addr), f->cgn_port);
		f->flags |= CGN_FLOW_FL_IN_MAP;
	}

	/* set metadata as part of packet, so veth on rx side can see them */
	int md_len = pkt->data - (void *)md;
	pkt->len += md_len;
	pkt->data -= md_len;

	return GTP_XSK_TX;
}


static const char *
proto_to_str(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_ICMPV6:
		return "icmp6";
	default:
		return "???";
	}
}

static int
_flow_print(struct cgn_ctx *c, const struct cgn_user *u, const struct cgn_v4_flow *f,
	    char *buf, size_t s)
{
	char spriv[100], scgn[100], spub[100];
	int64_t timeout;
	uint32_t a;
	int k = 0;

	timeout = _flow_timeout_remain(c->bpf_data, c, u, f);
	k += scnprintf(buf + k, s - k, "   %4s  %4ld  ",
		       proto_to_str(f->proto), timeout / NSEC_PER_SEC);

	a = htonl(u->addr);
	inet_ntop(AF_INET, &a, spriv, sizeof (spriv));
	a = htonl(u->cgn_addr);
	inet_ntop(AF_INET, &a, scgn, sizeof (scgn));
	a = f->pub_addr;
	inet_ntop(AF_INET, &a, spub, sizeof (spub));
	k += scnprintf(buf + k, s - k, "%s:%-5d  %s:%-5d  %s:%d\n",
		       spriv, ntohs(f->priv_port), scgn, ntohs(f->cgn_port),
		       spub, ntohs(f->pub_port));

	return k;
}

void
cgn_flow_dump_user_full(struct cgn_ctx *c, uint32_t addr, char *buf, size_t s)
{
	struct cgn_v4_ipblock *ipbl;
	struct cgn_user *u;
	char spriv[100], scgn[100];
	uint32_t a;
	int i, k = 0;

	buf[0] = 0;
	if (!c->initialized || c->bpf_data == NULL)
		return;

	u = _user_get(c, addr, false);
	if (u == NULL)
		return;

	a = htonl(addr);
	inet_ntop(AF_INET, &a, spriv, sizeof (spriv));
	k += scnprintf(buf + k, s - k, "user:\n private addr       : "
		       "%s\n", spriv);

	if (u->bl_n > 0) {
		ipbl = u->bl[0]->ipbl;
		a = htonl(ipbl->cgn_addr);
		inet_ntop(AF_INET, &a, scgn, sizeof (scgn));
		k += scnprintf(buf + k, s - k, " pub address        : %s\n",
			       scgn);
	}

	k += scnprintf(buf + k, s - k, " allocated flows    : %d / %d\n",
		       u->flow_n, c->flow_per_user);
	k += scnprintf(buf + k, s - k, " allocated blocks   : %d / %d\n",
		       u->bl_n, c->block_per_user);

	for (i = 0; i < u->bl_n; i++) {
		struct cgn_v4_block *bl = u->bl[i];
		k += scnprintf(buf + k, s - k,
			       "  bl[%d]             : [%d-%d] refcnt: %d\n"
			       "                       ports tcp=%d udp=%d "
			       "icmp=%d other=%d\n",
			       i, bl->port_start, bl->port_end, bl->refcnt,
			       bl->port_uniq[0], bl->port_uniq[1], bl->port_uniq[2],
			       bl->port_uniq[3]);
	}

	k += scnprintf(buf + k, s - k, "user flows:\n");
	k += scnprintf(buf + k, s - k, "   prot  tim     "
		       "priv                    cgn      "
		       "        ext_pub\n");

	for (i = 0; i < u->flow_size; i++) {
		if (u->flow[i].proto)
			k += _flow_print(c, u, &u->flow[i], buf + k, s - k);
	}
}


void
cgn_flow_dump_block_alloc(struct cgn_ctx *c, char *b, size_t s)
{
	const size_t ipbl_size =
		sizeof (struct cgn_v4_ipblock) +
		c->block_count * sizeof (struct cgn_v4_block);
	struct cgn_v4_ipblock *ipbl;
	struct cgn_user *u;
	uint32_t fl_used, bl_fl_used, bl_total, bl_used;
	uint64_t fl_total;
	uint32_t k = 0, i, j;

	b[0] = 0;
	if (!c->initialized)
		return;

	bl_total = c->cgn_addr_n * c->block_count;
	for (bl_used = 0, i = 0; i < c->block_count + 1; i++)
		bl_used += c->addr_stats[i] * i;
	for (bl_fl_used = 0, i = 0; i < c->cgn_addr_n; i++) {
		ipbl = (void *)c->ipbl + i * ipbl_size;
		for (j = 0; j < c->block_count; j++)
			if (ipbl->bl[j].alloc_time)
				bl_fl_used += ipbl->bl[j].refcnt;
	}

	k += scnprintf(b + k, s - k, "ipaddr count       : "
		       "%d\n", c->cgn_addr_n);
	k += scnprintf(b + k, s - k, "blocks used        : "
		       "%d / %d (%.2f%%)\n", bl_used, bl_total,
		       (double)bl_used / (bl_total ?: 1));
	k += scnprintf(b + k, s - k, "block distribution :\n");
	for (i = 1; i < c->block_count + 1; i++) {
		if (c->addr_stats[i])
			k += scnprintf(b + k, s - k, "  % 5d blocks; % 3d ipaddr with "
				       "%d / %d blocks on each\n", c->addr_stats[i] * i,
				       c->addr_stats[i], i, c->block_count);
	}

	k += scnprintf(b + k, s - k, "users              : "
		       "%d / %d (%.2f%%)\n", c->user_n, c->max_user,
		       (double)c->user_n / (c->max_user ?: 1));

	fl_used = fl_total = 0;
	list_for_each_entry(u, &c->user_list, list) {
		fl_used += u->flow_n;
		fl_total += c->flow_per_user;
	}

	k += scnprintf(b + k, s - k, "  flow used        : "
		       "%d / %ld (%.2f%%)",
		       fl_used, fl_total, (double)fl_used / (fl_total ?: 1));
	/* if different, may indicate a bug */
	if (bl_fl_used != fl_used)
		k += scnprintf(b + k, s - k, " (flows from blocks: %d)", bl_fl_used);
	k += scnprintf(b + k, s - k, "\n");
}


int
cgn_flow_init(void *priv)
{
	struct cgn_ctx *c = priv;
	struct cgn_v4_ipblock *ipbl;
	struct cgn_v4_block *bl;
	struct thread_master *m;
	const size_t ipbl_size =
		sizeof (struct cgn_v4_ipblock) +
		c->block_count * sizeof (struct cgn_v4_block);
	void *ptr;
	int i, j;

	c->now_ns = _clock_mono_ns();

	INIT_LIST_HEAD(&c->user_list);
	c->huser_size = next_power_of_2(c->max_user);
	c->huser = calloc(c->huser_size, sizeof (struct hlist_head));
	if (c->huser == NULL)
		return -1;
	c->user_n = 0;

	c->ipbl = calloc(c->cgn_addr_n, ipbl_size);
	c->addr_slots = calloc(c->block_count + 1, sizeof (struct list_head));
	c->addr_stats = calloc(c->block_count + 1, sizeof (uint32_t *));
	if (c->ipbl == NULL || c->addr_slots == NULL || c->addr_stats == NULL) {
		free(c->huser);
		return -1;
	}

	for (i = 0; i < c->block_count + 1; i++)
		INIT_LIST_HEAD(&c->addr_slots[i]);
	c->addr_stats[0] = c->cgn_addr_n;
	for (i = 0, ptr = c->ipbl; i < c->cgn_addr_n; i++, ptr += ipbl_size) {
		ipbl = ptr;
		list_add_tail(&ipbl->addr_list, &c->addr_slots[0]);
		ipbl->cgn_addr = c->cgn_addr[i];
		for (j = 0; j < c->block_count; j++) {
			bl = &ipbl->bl[j];
			bl->ipbl = ipbl;
			bl->port_start = c->port_start + j * c->block_size;
			bl->port_end = bl->port_start + c->block_size;
		}
	}

	m = gtp_xsk_thread_master(c->bpf_data->xc);
	if (m != NULL)
		c->user_gc_th = thread_add_timer(m, _flow_gc, c, TIMER_HZ);

	return 0;
}

void
cgn_flow_release(void *priv)
{
	struct cgn_ctx *c = priv;
	struct cgn_user *u, *u_tmp;

	list_for_each_entry_safe(u, u_tmp, &c->user_list, list)
		free(u);
	thread_del(c->user_gc_th);
	free(c->ipbl);
	free(c->addr_slots);
	free(c->addr_stats);
	free(c->huser);
}
