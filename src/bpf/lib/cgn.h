/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <time.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "flow.h"
#include "cgn-def.h"


/* cfg set from userspace */
const volatile __u32 ipbl_n = 1;	/* # of ips in pool */
const volatile __u32 bl_n = 2;		/* # of blocks per ip */
const volatile __u32 port_count = 3;	/* # ports per block */
const volatile __u32 bl_flow_max = 4;	/* # of allocatable flow per block  */
const volatile __u8 bl_user_max = CGN_USER_BLOCKS_MAX;

/* locals */
int hit_bug;


/*
 * user
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct cgn_user_key);
	__type(value, struct cgn_user);
	__uint(max_entries, 120000);
} users SEC(".maps");


static __always_inline struct cgn_user *
_cgn_user_lookup(__u32 addr)
{
	return bpf_map_lookup_elem(&users, &addr);
}

static __always_inline struct cgn_user *
_cgn_user_alloc(__u32 addr)
{
	struct cgn_user u = {
		.created = bpf_ktime_get_ns(),
		.addr = addr,
	};
	int ret;

	ret = bpf_map_update_elem(&users, &addr, &u, BPF_NOEXIST);
	if (ret < 0) {
		if (ret == -EEXIST)
			return _cgn_user_lookup(addr);
		bpf_printk("cannot allocate user 0x%08x: %d", addr, ret);
		return NULL;
	}

	return _cgn_user_lookup(addr);
}

static __always_inline void
_cgn_user_release(struct cgn_user *u)
{
	/* bpf_printk("release user %x", u->addr); */
	bpf_map_delete_elem(&users, &u->addr);
}


/*
 * ipv4 block
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cgn_v4_block_lock);
	__uint(max_entries, 1);
} v4_block_lock SEC(".maps");

/* ipv4 allocatable blocks
 * value size and max entries set on startup */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cgn_v4_ipblock);
} v4_blocks SEC(".maps");

/* store free blocks, as index in 'blocks' map */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32[]);
} v4_free_blocks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
} v4_pool_addr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 15000);
	__type(value, struct cgn_v4_block_log);
} v4_block_log_queue SEC(".maps");

static __always_inline void
_block_log(__u32 priv_addr, __u32 cgn_addr, const struct cgn_v4_block *bl, int alloc)
{
	__u32 duration = bpf_ktime_get_ns() - bl->alloc_time / NSEC_PER_SEC;

	struct cgn_v4_block_log s = {
		.prefix = "cmg-to-be-set",
		.cgn_addr = cgn_addr,
		.priv_addr = priv_addr,
		.duration = duration,
		.port_start = bl->cgn_port_start,
		.port_size = port_count,
		.flag = alloc ? CGN_BLOG_FL_ALLOC : 0,
	};
	bpf_map_push_elem(&v4_block_log_queue, &s, 0);
}

static __always_inline int
_block_lookup(__u32 ipbl_idx, __u32 bl_idx,
	      struct cgn_v4_ipblock **out_ipbl,
	      struct cgn_v4_block **out_bl)
{
	struct cgn_v4_ipblock *ipbl;

	ipbl = bpf_map_lookup_elem(&v4_blocks, &ipbl_idx);
	if (ipbl == NULL)
		return -1;
	*out_ipbl = ipbl;

	if (bl_idx >= bl_n)
		return -1;
	*out_bl = &ipbl->b[bl_idx];

	return 0;
}

static __always_inline int
_block_alloc_sub(struct cgn_user *u, struct cgn_v4_ipblock *ipbl,
		 struct cgn_v4_block **out_bl)
{
	struct cgn_v4_block *bl;
	__u32 ipbl_idx;
	__u32 real_bl_idx, bl_idx, i;

	/* get a block from this ipblock */
	bl_idx = ipbl->next;
	bpf_for(i, 0, bl_n) {
		if (bl_idx >= bl_n)
			break;
		bl = &ipbl->b[bl_idx];
		if (!bl->refcnt) {
			ipbl->next = bl_idx;
			ipbl_idx = ipbl->ipbl_idx;

			/* assign to user */
			__u8 block_n = u->block_n;
			if (block_n >= bl_user_max)
				break;
			u->ipblock_idx = ipbl_idx;
			u->block_idx[block_n] = bl_idx;
			++u->block_n;

			bl->alloc_time = bpf_ktime_get_ns();
			*out_bl = bl;
			return 0;
		}
		++bl_idx;
		bl_idx %= bl_n;
	}

	bpf_printk("_block_alloc_sub bug!");
	hit_bug = 1;
	return -2;
}


static __always_inline int
_block_alloc_first(struct cgn_user *u, __u32 *frd_from, __u32 *frd_to,
		   struct cgn_v4_ipblock **out_ipbl, struct cgn_v4_block **out_bl)
{
	struct cgn_v4_ipblock *ipbl;
	__u32 ipblock_idx;
	__u32 *fdata;
	__u32 idx, i;

	idx = 0;
	struct bpf_spin_lock *lock = bpf_map_lookup_elem(&v4_block_lock, &idx);
	if (lock == NULL)
		goto bug;

	bpf_spin_lock(lock);

	/* under lock, re-check if this array is not empty  */
	if (frd_from[0] == frd_from[1]) {
		bpf_spin_unlock(lock);
		return 2;
	}

	/* move from v4_free_block[i]... (inc begin index) */
	if (frd_from[0] > ipbl_n)
		goto bug_unlock;
	ipblock_idx = frd_from[frd_from[0] + 2];
	if (++frd_from[0] == ipbl_n + 1)
		frd_from[0] = 0;

	/* ... to v4_free_block[i + 1] (inc end index) */
	if (frd_to[1] > ipbl_n)
		goto bug_unlock;
	frd_to[frd_to[1] + 2] = ipblock_idx;
	if (++frd_to[1] == ipbl_n + 1)
		frd_to[1] = 0;

	bpf_spin_unlock(lock);

	/* get a block from this ipblock */
	ipbl = bpf_map_lookup_elem(&v4_blocks, &ipblock_idx);
	if (ipbl == NULL)
		goto bug;

	++ipbl->used;
	*out_ipbl = ipbl;
	return _block_alloc_sub(u, ipbl, out_bl);

 bug_unlock:
	bpf_spin_unlock(lock);
 bug:
	bpf_printk("_block_alloc_sub bug!");
	hit_bug = 1;
	return -2;
}


static __always_inline int
_block_alloc_more(struct cgn_user *u, struct cgn_v4_ipblock *ipbl,
		  struct cgn_v4_block **out_bl)
{
	__u32 i, idx, block_n;
	__u32 *frd_from, *frd_to;
	__u32 ipbl_idx_to_move = ~0, ipbl_fr_idx, ipbl_old_fr_idx;
	__u32 l_ipbl_n;

	/* take lock to update v4_free_block */
	idx = 0;
	struct bpf_spin_lock *lock = bpf_map_lookup_elem(&v4_block_lock, &idx);
	if (lock == NULL)
		goto bug;

	idx = ipbl->used;
	frd_from = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	++idx;
	frd_to = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	if (frd_from == NULL || frd_to == NULL)
		goto bug;

	l_ipbl_n = ipbl_n;

	bpf_spin_lock(lock);

	/* check for racy condition */
	if (idx - 1 != ipbl->used) {
		bpf_spin_unlock(lock);
		bpf_printk("alloc_more race");
		return 1;
	}

	/* move us from v4_free_block[i] ... */
	if (ipbl->fr_idx != frd_from[0]) {
		if (frd_from[0] > l_ipbl_n || ipbl->fr_idx > l_ipbl_n)
			goto bug_unlock;
		ipbl_idx_to_move = frd_from[frd_from[0] + 2];
		frd_from[ipbl->fr_idx + 2] = ipbl_idx_to_move;
		ipbl_old_fr_idx = frd_from[0];
		ipbl_fr_idx = ipbl->fr_idx;
	}
	if (++frd_from[0] == l_ipbl_n + 1)
		frd_from[0] = 0;

	/* ... to v4_free_block[i + 1] */
	++ipbl->used;
	ipbl->fr_idx = frd_to[1];
	if (frd_to[1] > l_ipbl_n)
		goto bug_unlock;
	frd_to[frd_to[1] + 2] = ipbl->ipbl_idx;
	if (++frd_to[1] == l_ipbl_n + 1)
		frd_to[1] = 0;

	bpf_spin_unlock(lock);

	if (ipbl_idx_to_move != ~0) {
		struct cgn_v4_ipblock *ipbl_to_move;
		ipbl_to_move = bpf_map_lookup_elem(&v4_blocks, &ipbl_idx_to_move);
		if (ipbl_to_move == NULL)
			goto bug;

		bpf_spin_lock(lock);
		/* block was used (++used or --used) since we take a ref on it
		 * if it happens, then a refcount on ipblock should be added */
		if (ipbl_to_move->fr_idx != ipbl_old_fr_idx)
			goto bug_unlock;
		ipbl_to_move->fr_idx = ipbl_fr_idx;
		bpf_spin_unlock(lock);
	}

	/* get a block from this ipblock */
	return _block_alloc_sub(u, ipbl, out_bl);

 bug_unlock:
	bpf_spin_unlock(lock);
 bug:
	bpf_printk("_block_alloc_more bug!");
	hit_bug = 1;
	return -2;
}


static __no_inline int
_block_alloc(struct cgn_user *u, struct cgn_v4_ipblock **out_ipbl,
	     struct cgn_v4_block **out_bl)
{
	__u32 *frd_from, *frd_to;
	__u32 idx, i;
	int ret = -1;

	if (__sync_fetch_and_add(&u->allocating, 1) >= 1) {
		ret = 1;
		goto exit;
	}

	/* too greedy */
	if (u->block_n >= bl_user_max)
		goto exit;

	/* fetch from the same ipblock */
	if (u->block_n > 0) {
		*out_ipbl = bpf_map_lookup_elem(&v4_blocks, &u->ipblock_idx);
		if (*out_ipbl == NULL)
			goto bug;

		ret = _block_alloc_more(u, *out_ipbl, out_bl);
		goto exit;
	}

	/* first user block allocation, get the least used ipblock */
	idx = 0;
	frd_from = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	if (frd_from == NULL)
		goto bug;

	bpf_for(i, 0, bl_n) {
		idx = i + 1;
		frd_to = bpf_map_lookup_elem(&v4_free_blocks, &idx);
		if (frd_to == NULL)
			goto bug;
		if (frd_from[0] != frd_from[1]) {
			ret = _block_alloc_first(u, frd_from, frd_to,
						 out_ipbl, out_bl);
			if (ret <= 0)
				goto exit;
		}

		frd_from = frd_to;
	}

	/* nothing left... */
	ret = -1;
	goto exit;

 bug:
	bpf_printk("_block_alloc bug!");
	hit_bug = 1;
	ret = -2;

 exit:
	__sync_fetch_and_sub(&u->allocating, 1);
	return ret;
}


static __always_inline int
_block_release(struct cgn_user *u, struct cgn_v4_ipblock *ipbl,
	       struct cgn_v4_block *bl)
{
	__u32 idx, idx_to_move = ~0;
	__u32 i, block_n;
	__u32 *frd_from, *frd_to;
	__u32 ipbl_fr_idx, ipbl_old_fr_idx;
	__u32 l_ipbl_n;
	int ret;

	if (__sync_fetch_and_add(&u->allocating, 1) >= 1) {
		ret = 1;
		goto exit;
	}

	/* take lock to update v4_free_block */
	idx = 0;
	struct bpf_spin_lock *lock = bpf_map_lookup_elem(&v4_block_lock, &idx);
	if (lock == NULL)
		goto bug;

	idx = ipbl->used;
	frd_from = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	--idx;
	frd_to = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	if (frd_from == NULL || frd_to == NULL)
		goto bug;

	l_ipbl_n = ipbl_n;

	bpf_spin_lock(lock);

	/* check for racy condition */
	if (idx + 1 != ipbl->used) {
		bpf_spin_unlock(lock);
		ret = 1;
		goto exit;
	}

	/* move us from v4_free_block[i] ... */
	if (ipbl->fr_idx != frd_from[0]) {
		if (frd_from[0] > l_ipbl_n || ipbl->fr_idx > l_ipbl_n)
			goto bug_unlock;
		idx_to_move = frd_from[frd_from[0] + 2];
		frd_from[ipbl->fr_idx + 2] = idx_to_move;
		ipbl_fr_idx = ipbl->fr_idx;
		ipbl_old_fr_idx = frd_from[0];
	}
	if (++frd_from[0] == l_ipbl_n + 1)
		frd_from[0] = 0;

	/* ... to v4_free_block[i - 1] */
	--ipbl->used;
	ipbl->fr_idx = frd_to[1];
	if (frd_to[1] > l_ipbl_n)
		goto bug_unlock;
	frd_to[frd_to[1] + 2] = bl->ipbl_idx;
	if (++frd_to[1] == l_ipbl_n + 1)
		frd_to[1] = 0;

	bpf_spin_unlock(lock);

	if (idx_to_move != ~0) {
		struct cgn_v4_ipblock *ipbl_to_move;
		ipbl_to_move = bpf_map_lookup_elem(&v4_blocks, &idx_to_move);
		if (ipbl_to_move == NULL)
			goto bug;
		bpf_spin_lock(lock);
		if (ipbl_to_move->fr_idx != ipbl_old_fr_idx)
			goto bug_unlock;
		ipbl_to_move->fr_idx = ipbl_fr_idx;
		bpf_spin_unlock(lock);
	}

	_block_log(u->addr, ipbl->cgn_addr, bl, 0);

	/* release in user's allocated block */
	block_n = u->block_n;
	if (block_n < 1 || block_n > bl_user_max)
		goto bug;
	bpf_for(i, 0, block_n - 1) {
		if (u->ipblock_idx == ipbl->ipbl_idx &&
		    u->block_idx[i] == bl->bl_idx)
			break;
	}
	for ( ; i < block_n - 1; i++)
		u->block_idx[i] = u->block_idx[i + 1];

	--u->block_n;
	if (!u->block_n)
		_cgn_user_release(u);

	__sync_fetch_and_sub(&u->allocating, 1);
	return 0;

 bug_unlock:
	bpf_spin_unlock(lock);
 bug:
	bpf_printk("_block_release bug");
	hit_bug = 1;
	ret = -2;
 exit:
	__sync_fetch_and_sub(&u->allocating, 1);
	return ret;
}

static __always_inline __u16
_block_get_next_port(struct cgn_v4_block *bl)
{
	if (__sync_fetch_and_add(&bl->refcnt, 1) >= bl_flow_max) {
		__sync_fetch_and_sub(&bl->refcnt, 1);
		return 0;
	}
	__u16 port = __sync_fetch_and_add(&bl->cgn_port_next, 1);
	return bl->cgn_port_start + (port % port_count);
}


/*
 * ipv4 flows
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cgn_v4_flow_priv_hairpin_key);
	__type(value, struct cgn_v4_flow_priv_hairpin);
	__uint(max_entries, 3000000);
} v4_priv_flows_hp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cgn_v4_flow_priv_key);
	__type(value, struct cgn_v4_flow_priv);
	__uint(max_entries, 3000000);
} v4_priv_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cgn_v4_flow_pub_key);
	__type(value, struct cgn_v4_flow_pub);
	__uint(max_entries, 3000000);
} v4_pub_flows SEC(".maps");



static __always_inline void
_flow_release(struct cgn_v4_flow_priv_key *priv_k, struct cgn_v4_flow_priv *f)
{
	struct cgn_v4_ipblock *ipbl;
	struct cgn_v4_block *bl;
	struct cgn_user *u;
	__u32 idx;

	idx = f->ipbl_idx;
	ipbl = bpf_map_lookup_elem(&v4_blocks, &idx);
	if (ipbl == NULL)
		goto bug;

	idx = f->bl_idx;
	if (idx >= bl_n)
		goto bug;
	bl = &ipbl->b[idx];
	if (__sync_fetch_and_sub(&bl->refcnt, 1) == 1) {
		u = bpf_map_lookup_elem(&users, &priv_k->priv_addr);
		if (u == NULL)
			goto bug;
		if (_block_release(u, ipbl, bl) == 1) {
			if (bpf_timer_start(&f->timer, 10000, 0)) {
				bpf_printk("_flow_release: cannot restart "
					   "timer in racy situation");
			}
			return;
		}
	}

	bpf_map_delete_elem(&v4_priv_flows, priv_k);

	struct cgn_v4_flow_priv_hairpin_key phk = {
		.priv_addr = priv_k->priv_addr,
		.priv_port = priv_k->priv_port,
		.proto = priv_k->proto,
	};
	bpf_map_delete_elem(&v4_priv_flows_hp, &phk);

	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = f->cgn_addr,
		.pub_addr = priv_k->pub_addr,
		.cgn_port = f->cgn_port,
		.pub_port = priv_k->pub_port,
		.proto = priv_k->proto,
	};
	bpf_map_delete_elem(&v4_pub_flows, &pub_k);

	return;

 bug:
	bpf_printk("_flow_release bug, ipbl:%p idx:%d/%d u:%p",
		   ipbl, idx, bl_n, u);
	hit_bug = 1;
}

static int
_flow_timer_cb(void *_map, struct cgn_v4_flow_priv_key *key,
	       struct cgn_v4_flow_priv *f)
{
	/* bpf_printk("flow_timer_cb"); */
	_flow_release(key, f);
	return 0;
}

static inline __attribute__((always_inline)) int
_flow_add_entry(const struct cgn_packet *pp, struct cgn_v4_block *bl,
		__u16 cgn_port, struct cgn_v4_flow_priv **out_f)
{
	int ret = -1;

	/* bpf_printk("%d: user 0x%x get port: %d newrefc: %d ", */
	/* 	   bpf_get_smp_processor_id(), bpf_ntohl(u->addr.ip4), */
	/* 	   cgn_port, bl->refcnt); */

	/* add pub entry */
	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = pp->cgn_addr,
		.pub_addr = pp->dst_addr,
		.cgn_port = cgn_port,
		.pub_port = pp->dst_port,
		.proto = pp->proto,
	};
	struct cgn_v4_flow_pub pf = {
		.priv_addr = pp->src_addr,
		.cgn_addr = pp->cgn_addr,
		.priv_port = pp->src_port,
		.cgn_port = cgn_port,
	};
	ret = bpf_map_update_elem(&v4_pub_flows, &pub_k, &pf, BPF_NOEXIST);
	if (ret == -EEXIST) {
		/* may happen if cgn_port is already used with the
		 * same ip_pub:port_pub target. try with one cgn_port in each
		 * block (do not try with every cgn_port) */
		ret = 1;
		goto exit;

	} else if (ret) {
		bpf_printk("cannot insert in v4_pub_flows: %d", ret);
		goto exit;
	}

	/* add priv entry */
	struct cgn_v4_flow_priv_key priv_k = {
		.priv_addr = pp->src_addr,
		.pub_addr = pp->dst_addr,
		.priv_port = pp->src_port,
		.pub_port = pp->dst_port,
		.proto = pp->proto,
	};
	struct cgn_v4_flow_priv ppf = {
		.cgn_addr = pp->cgn_addr,
		.cgn_port = cgn_port,
		.bl_idx = bl->bl_idx,
		.ipbl_idx = bl->ipbl_idx,
	};
	ret = bpf_map_update_elem(&v4_priv_flows, &priv_k, &ppf, BPF_NOEXIST);
	if (ret) {
		/* this one should not happen */
		bpf_printk("cannot insert in v4_priv_flows: %d", ret);
		goto err_priv;
	}

	/* add priv hairpin entry. if it exists, update it */
	struct cgn_v4_flow_priv_hairpin_key phk = {
		.priv_addr = priv_k.priv_addr,
		.priv_port = priv_k.priv_port,
		.proto = priv_k.proto,
	};
	struct cgn_v4_flow_priv_hairpin ph = {
		.cgn_port = cgn_port,
	};
	bpf_map_update_elem(&v4_priv_flows_hp, &phk, &ph, 0);

	/* need to retrieve it from map to initialize bpf timer */
	struct cgn_v4_flow_priv *f = bpf_map_lookup_elem(&v4_priv_flows, &priv_k);
	if (f == NULL) {
		bpf_printk("flow_add_entry: unable to retrieve just "
			   "inserted v4_priv_flows");
		goto err;
	}

	ret = bpf_timer_init(&f->timer, &v4_priv_flows, CLOCK_MONOTONIC);
	if (ret) {
		bpf_printk("flow_add_entry: cannot init timer: %d", ret);
		goto err;
	}
	ret = bpf_timer_set_callback(&f->timer, _flow_timer_cb);
	if (ret) {
		bpf_printk("flow_add_entry: cannot set timer cb: %d", ret);
		goto err;
	}

	*out_f = f;
	return 0;

 err:
	bpf_map_delete_elem(&v4_priv_flows, &priv_k);
 err_priv:
	bpf_map_delete_elem(&v4_pub_flows, &pub_k);
 exit:
	__sync_fetch_and_sub(&bl->refcnt, 1);
	return ret;
}

static __always_inline struct cgn_v4_flow_priv *
_flow_alloc(struct cgn_user *u, struct cgn_packet *pp)
{
	struct cgn_v4_ipblock *ipbl = NULL;
	struct cgn_v4_block *bl;
	struct cgn_v4_flow_priv *f = NULL;
	__u8 block_n = u->block_n;
	__u16 cgn_port;
	int i;

	if (block_n > 0) {
		if (block_n >= bl_user_max)
			block_n = bl_user_max;

		/* first, try with lastest block we allocated from */
		if (_block_lookup(u->ipblock_idx, u->block_idx[block_n - 1],
				  &ipbl, &bl) < 0)
			return NULL;
		pp->cgn_addr = ipbl->cgn_addr;
		cgn_port = _block_get_next_port(bl);
		if (cgn_port && _flow_add_entry(pp, bl, cgn_port, &f) <= 0)
			return f;

		/* if no space left, check in other allocated blocks */
		for (i = 0; i < block_n - 1; i++) {
			if (_block_lookup(u->ipblock_idx, u->block_idx[i],
					  &ipbl, &bl) < 0)
				return NULL;
			cgn_port = _block_get_next_port(bl);
			if (cgn_port &&
			    _flow_add_entry(pp, bl, cgn_port, &f) <= 0) {
				/* got port. move this block to the last
				 * place, so next alloc will use it first */
				for ( ; f != NULL && i < block_n - 1; i++) {
					__u16 tmp = u->block_idx[i];
					u->block_idx[i] = u->block_idx[i + 1];
					u->block_idx[i + 1] = tmp;
				}
				return f;
			}
		}
	}

	/* last chance, allocate a new block */
	int ret = _block_alloc(u, &ipbl, &bl);
	if (ret < 0) {
		bpf_printk("cannot alloc block");
		return NULL;
	}
	if (ret > 0) {
		bpf_printk("racy block alloc, abort");
		pp->racy = 1;
		return NULL;
	}
	pp->cgn_addr = ipbl->cgn_addr;
	_block_log(u->addr, ipbl->cgn_addr, bl, 1);

	cgn_port = _block_get_next_port(bl);
	if (cgn_port)
		_flow_add_entry(pp, bl, cgn_port, &f);

	return f;
}

static inline struct cgn_v4_flow_priv *
_flow_alloc_with_cgn_port(struct cgn_user *u, struct cgn_packet *pp, __u16 cgn_port)
{
	struct cgn_v4_ipblock *ipbl;
	struct cgn_v4_block *bl;
	struct cgn_v4_flow_priv *f = NULL;
	__u8 block_n = u->block_n;
	int i;

	if (block_n >= bl_user_max)
		block_n = bl_user_max;
	for (i = block_n - 1; i >= 0; i--) {
		if (_block_lookup(u->ipblock_idx, u->block_idx[i],
				  &ipbl, &bl) < 0)
			return NULL;
		if (cgn_port >= bl->cgn_port_start &&
		    cgn_port < bl->cgn_port_start + port_count) {
			if (__sync_fetch_and_add(&bl->refcnt, 1) >= bl_flow_max) {
				__sync_fetch_and_sub(&bl->refcnt, 1);
				return 0;
			}
			pp->cgn_addr = ipbl->cgn_addr;
			_flow_add_entry(pp, bl, cgn_port, &f);
			return f;
		}
	}

	return NULL;

}


static inline struct cgn_v4_flow_pub *
_flow_v4_lookup_pub(const struct cgn_packet *pp)
{
	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = pp->dst_addr,
		.pub_addr = pp->src_addr,
		.cgn_port = pp->dst_port,
		.pub_port = pp->src_port,
		.proto = pp->proto,
	};

	return bpf_map_lookup_elem(&v4_pub_flows, &pub_k);
}

static inline struct cgn_v4_flow_priv *
_flow_v4_lookup_priv(const struct cgn_packet *pp)
{
	struct cgn_v4_flow_priv_key priv_k = {
		.priv_addr = pp->src_addr,
		.pub_addr = pp->dst_addr,
		.priv_port = pp->src_port,
		.pub_port = pp->dst_port,
		.proto = pp->proto,
	};

	return bpf_map_lookup_elem(&v4_priv_flows, &priv_k);
}

static inline struct cgn_v4_flow_priv_hairpin *
_flow_v4_lookup_priv_hairpin(const struct cgn_packet *pp)
{
	struct cgn_v4_flow_priv_key priv_k = {
		.priv_addr = pp->src_addr,
		.priv_port = pp->src_port,
		.proto = pp->proto,
	};

	return bpf_map_lookup_elem(&v4_priv_flows_hp, &priv_k);
}


/*
 * packet from private: may create user/flow,
 * and update src addr/port.
 *
 * return:
 *    0: ok
 *    1: internal
 *   10: no associated flow
 *   11: user alloc error
 *   12: flow alloc error
 *   13: packet from pub
 */
static __always_inline int
cgn_flow_handle_priv(struct cgn_packet *cp)
{
	struct cgn_v4_flow_priv_hairpin *hf;
	struct cgn_v4_flow_priv *f;
	struct cgn_user *u;
	void *p;
	int ret;

	f = _flow_v4_lookup_priv(cp);
	if (f == NULL) {
		if (cp->icmp_err_off)
			return 10;

		/* this packet is for egress (to our ip pool pub) */
		if (cp->from_priv == 2) {
			p = bpf_map_lookup_elem(&v4_pool_addr, &cp->dst_addr);
			if (p != NULL)
				return 13;
		}

		/* get/allocate user before allocating flow */
		u = _cgn_user_lookup(cp->src_addr);
		if (u == NULL) {
			if (cp->icmp_err_off)
				return 10;
			u = _cgn_user_alloc(cp->src_addr);
			if (u == NULL)
				return 11;
		}

		/* check if the same {priv_addr:priv_port:proto} was already used
		 * by our user. allow STUN. this feature is called 'hairpin' here */
		hf = _flow_v4_lookup_priv_hairpin(cp);
		if (hf != NULL) {
			f = _flow_alloc_with_cgn_port(u, cp, hf->cgn_port);
			if (f == NULL)
				f = _flow_alloc(u, cp);
		} else {
			f = _flow_alloc(u, cp);
		}
		if (f == NULL)
			return 12;

	} else if (cp->proto == IPPROTO_TCP) {
		if (flow_update_priv_tcp_state(cp->tcp_flags, &f->proto_state)) {
			struct cgn_v4_flow_pub_key pub_k = {
				.cgn_addr = f->cgn_addr,
				.pub_addr = cp->dst_addr,
				.cgn_port = f->cgn_port,
				.pub_port = cp->dst_port,
				.proto = cp->proto,
			};
			struct cgn_v4_flow_pub *pub_f;
			pub_f = bpf_map_lookup_elem(&v4_pub_flows, &pub_k);
			if (pub_f != NULL) {
				pub_f->proto_state = f->proto_state;
			}
		}
	}

	cp->src_addr = f->cgn_addr;
	cp->src_port = f->cgn_port;

	/* start or refresh flow timeout, every ~1 second */
	__u64 now = bpf_ktime_get_ns();
	if ((f->updated >> 30ULL) != (now >> 30ULL)) {
		__u64 to = flow_timeout_ns(cp->proto, cp->dst_port, f->proto_state);
		ret = bpf_timer_start(&f->timer, to, 0);

		if (ret) {
			bpf_printk("cannot (re)start timer??? (val=%ld)", to);
			struct cgn_v4_flow_priv_key priv_k = {
				.priv_addr = cp->src_addr,
				.pub_addr = cp->dst_addr,
				.priv_port = cp->src_port,
				.pub_port = cp->dst_port,
				.proto = cp->proto,
			};
			_flow_release(&priv_k, f);
			return 1;
		}
		f->updated = now;
	}
	return 0;
}

/*
 * packet from public: check if a flow exists;
 *  if there is, update dst addr/port,
 *  if not, drop packet.
 *
 * return:
 *     0: ok
 *    10: no associated flow
 */
static __always_inline int
cgn_flow_handle_pub(struct cgn_packet *cp)
{
	struct cgn_v4_flow_pub *f;

	f = _flow_v4_lookup_pub(cp);
	if (f == NULL)
		return 10;

	if (cp->proto == IPPROTO_TCP) {
		if (flow_update_pub_tcp_state(cp->tcp_flags, &f->proto_state)) {
			struct cgn_v4_flow_priv_key priv_k = {
				.priv_addr = f->priv_addr,
				.pub_addr = cp->src_addr,
				.priv_port = f->priv_port,
				.pub_port = cp->src_port,
				.proto = cp->proto,
			};
			struct cgn_v4_flow_priv *priv_f;
			priv_f = bpf_map_lookup_elem(&v4_priv_flows, &priv_k);
			if (priv_f != NULL)
				priv_f->proto_state = f->proto_state;
		}
	}

	cp->dst_addr = f->priv_addr;
	cp->dst_port = f->priv_port;

	return 0;
}



/*
 * ipv4 packet manipulation
 */

/* lighten stack... */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct cgn_packet);
	__uint(max_entries, 1);
} cgn_on_stack SEC(".maps");



static __always_inline int
cgn_pkt_rewrite_src(struct xdp_md *ctx, struct cgn_packet *cp, struct iphdr *ip4h, void *payload,
		    __u32 addr, __u16 port)
{
	void *data_end = (void *)(long)ctx->data_end;
	__u32 sum;

	addr = bpf_htonl(addr);
	port = bpf_htons(port);

	/* update l4 checksum */
	switch (cp->proto) {
	case IPPROTO_UDP:
	{
		struct udphdr *udp = payload;
		if ((void *)(udp + 1) > data_end)
			return 1;
		if (udp->check) {
			sum = csum_diff32(0, ip4h->saddr, addr);
			sum = csum_diff16(sum, udp->source, port);
			__u16 nsum = csum_replace(udp->check, sum);
			if (nsum == 0)
				nsum = 0xffff;
			udp->check = nsum;
		}
		udp->source = port;
		break;
	}

	case IPPROTO_TCP:
	{
		struct tcphdr *tcp = payload;
		if ((void *)(tcp + 1) > data_end)
			return 1;
		sum = csum_diff32(0, ip4h->saddr, addr);
		sum = csum_diff16(sum, tcp->source, port);
		tcp->check = csum_replace(tcp->check, sum);
		tcp->source = port;
		break;
	}

	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp = payload;
		if ((void *)(icmp + 1) > data_end)
			return 1;
		sum = csum_diff16(0, icmp->un.echo.id, port);
		icmp->checksum = csum_replace(icmp->checksum, sum);
		icmp->un.echo.id = port;
		break;
	}
	}

	/* decrement ttl and update l3 checksum */
	sum = csum_diff32(0, ip4h->saddr, addr);
	ip4h->saddr = addr;
	__u16 icmp_err_off = cp->icmp_err_off;
	if (!icmp_err_off) {
		--sum;
		--ip4h->ttl;
		ip4h->check = csum_replace(ip4h->check, sum);
	} else if (icmp_err_off < 400) {
		__u16 old_ip4h_csum = ip4h->check;
		ip4h->check = csum_replace(ip4h->check, sum);
		if (cp->proto != IPPROTO_ICMP) {
			void *data = (void *)(long)ctx->data;
			struct icmphdr *icmp = (struct icmphdr *)(data + icmp_err_off);
			if ((void *)(icmp + 1) > data_end)
				return 1;
			sum = csum_diff16(0, old_ip4h_csum, ip4h->check);
			icmp->checksum = csum_replace(icmp->checksum, sum);
		}
	}

	return 0;
}


static __always_inline int
cgn_pkt_rewrite_dst(struct xdp_md *ctx, struct cgn_packet *cp, struct iphdr *ip4h, void *payload,
		    __u32 addr, __u16 port)
{
	void *data_end = (void *)(long)ctx->data_end;
	__u32 sum;

	addr = bpf_htonl(addr);
	port = bpf_htons(port);

	/* update l4 checksum */
	switch (cp->proto) {
	case IPPROTO_UDP:
	{
		struct udphdr *udp = payload;
		if ((void *)(udp + 1) > data_end)
			return 1;
		if (udp->check) {
			sum = csum_diff32(0, ip4h->daddr, addr);
			sum = csum_diff16(sum, udp->dest, port);
			__u16 nsum = csum_replace(udp->check, sum);
			if (nsum == 0)
				nsum = 0xffff;
			udp->check = nsum;
		}
		udp->dest = port;
		break;
	}

	case IPPROTO_TCP:
	{
		struct tcphdr *tcp = payload;
		if ((void *)(tcp + 1) > data_end)
			return 1;
		sum = csum_diff32(0, ip4h->daddr, addr);
		sum = csum_diff16(sum, tcp->dest, port);
		tcp->check = csum_replace(tcp->check, sum);
		tcp->dest = port;
		break;
	}

	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp = payload;
		if ((void *)(icmp + 1) > data_end)
			return 1;
		sum = csum_diff16(0, icmp->un.echo.id, port);
		icmp->checksum = csum_replace(icmp->checksum, sum);
		icmp->un.echo.id = port;
		break;
	}
	}

	/* decrement ttl and update l3 checksum */
	sum = csum_diff32(0, ip4h->daddr, addr);
	ip4h->daddr = addr;
	__u16 icmp_err_off = cp->icmp_err_off;
	if (!icmp_err_off) {
		--sum;
		--ip4h->ttl;
		ip4h->check = csum_replace(ip4h->check, sum);
	} else if (icmp_err_off < 400) {
		__u16 old_ip4h_csum = ip4h->check;
		ip4h->check = csum_replace(ip4h->check, sum);
		if (cp->proto != IPPROTO_ICMP) {
			void *data = (void *)(long)ctx->data;
			struct icmphdr *icmp = data + icmp_err_off;
			if ((void *)(icmp + 1) > data_end)
				return 1;
			sum = csum_diff16(0, old_ip4h_csum, ip4h->check);
			icmp->checksum = csum_replace(icmp->checksum, sum);
		}
	}

	return 0;
}

/*
 * process icmp error's inner ip header
 */
static __always_inline int
_handle_pkt_icmp_error(struct cgn_packet *cp, struct iphdr *outer_ip4h,
		       struct icmphdr *outer_icmp, struct iphdr *ip4h)
{
	void *data = (void *)(long)cp->ctx->data;
	void *data_end = (void *)(long)cp->ctx->data_end;
	__u32 sum, addr;
	int ret;

	if ((void *)(ip4h + 1) > data_end || ip4h->version != 4)
		return 2;

	/* parse packet with swapped src/dst, in order to be able
	 * to lookup flow */
	cp->proto = ip4h->protocol;
	cp->src_addr = bpf_ntohl(ip4h->daddr);
	cp->dst_addr = bpf_ntohl(ip4h->saddr);
	cp->icmp_err_off = (void *)outer_icmp - data;

	struct udphdr *udp = (void *)(ip4h) + ip4h->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return 2;

	switch (ip4h->protocol) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		cp->dst_port = bpf_ntohs(udp->source);
		cp->src_port = bpf_ntohs(udp->dest);
		break;
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp = (struct icmphdr *)udp;
		switch (icmp->type) {
		case ICMP_ECHO:
			cp->dst_port = bpf_ntohs(icmp->un.echo.id);
			cp->src_port = 0;
			break;
		case ICMP_ECHOREPLY:
			cp->dst_port = 0;
			cp->src_port = bpf_ntohs(icmp->un.echo.id);
			break;
		default:
			return 3;
		}
		break;
	}
	default:
		return 3;
	}

	/* lookup and process flow, then rewrite inner l3/l4 and outer l3 */
	if (cp->from_priv == 0 || cp->from_priv == 2) {
		ret = cgn_flow_handle_pub(cp);
		if (!ret) {
			ret = cgn_pkt_rewrite_src(cp->ctx, cp, ip4h, udp,
						  cp->dst_addr, cp->dst_port);
			if (ret)
				return ret;

			addr = bpf_htonl(cp->dst_addr);
			sum = csum_diff32(0, outer_ip4h->daddr, addr);
			outer_ip4h->daddr = addr;
			goto end;
		}
		if (cp->from_priv == 0)
			return ret;
	}

	ret = cgn_flow_handle_priv(cp);
	if (ret)
		return ret;
	ret = cgn_pkt_rewrite_dst(cp->ctx, cp, ip4h, udp, cp->src_addr, cp->src_port);
	if (ret)
		return ret;

	addr = bpf_htonl(cp->src_addr);
	sum = csum_diff32(0, outer_ip4h->saddr, addr);
	outer_ip4h->saddr = addr;

 end:
	--sum;
	--outer_ip4h->ttl;
	outer_ip4h->check = csum_replace(outer_ip4h->check, sum);
	return 0;
}

/*
 * main cgn entry function.
 * parameters:
 *  - ip4h: must already be checked (ihl, version, ttl > 0), and cannot be a fragment
 *  - from_priv: 0: egress, 1: ingress, 2: guess
 *
 * returns:
 *    0: ok. packet modified
 *    1: internal
 *    2: invalid packet
 *    3: unsupported protocol/operation
 *   10: no associated flow
 *   11: user alloc error
 *   12: flow alloc error
 */
static __attribute__((noinline)) int
cgn_pkt_handle(struct if_rule_data *d, __u8 from_priv)
{
	struct xdp_md *ctx = d->ctx;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4h = data + d->pl_off;
	struct cgn_packet *cp;
	void *payload;
	int ret;

	struct cgn_packet cp_static = {
		.ctx = ctx,
	};
	cp = &cp_static;

	if (d->pl_off > 256 || (void *)(ip4h + 1) > data_end)
		return 2;

	cp->proto = ip4h->protocol;
	cp->from_priv = from_priv;
	cp->src_addr = bpf_ntohl(ip4h->saddr);
	cp->dst_addr = bpf_ntohl(ip4h->daddr);
	payload = (void *)ip4h + ip4h->ihl * 4;

	CGN_DBG("priv:%d parse proto: %d dst: %pI4 ihl %d/%d", from_priv,
		cp->proto, &ip4h->daddr, ip4h->ihl, ip4h->version);

	switch (cp->proto) {
	case IPPROTO_UDP:
	{
		struct udphdr *udp = payload;
		if ((void *)(udp + 1) > data_end)
			return 2;
		cp->src_port = bpf_ntohs(udp->source);
		cp->dst_port = bpf_ntohs(udp->dest);
		break;
	}
	case IPPROTO_TCP:
	{
		struct tcphdr *tcp = payload;
		if ((void *)(tcp + 1) > data_end)
			return 2;
		cp->src_port = bpf_ntohs(tcp->source);
		cp->dst_port = bpf_ntohs(tcp->dest);
		cp->tcp_flags = ((union tcp_word_hdr *)(tcp))->words[3];
		break;
	}
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp = payload;
		if ((void *)(icmp + 1) > data_end)
			return 2;
		switch (icmp->type) {
		case ICMP_ECHO:
			cp->src_port = bpf_ntohs(icmp->un.echo.id);
			cp->dst_port = 0;
			break;
		case ICMP_ECHOREPLY:
			cp->src_port = 0;
			cp->dst_port = bpf_ntohs(icmp->un.echo.id);
			break;
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
			ret = _handle_pkt_icmp_error(cp, ip4h, icmp,
						     (struct iphdr *)(icmp + 1));
			d->dst_addr.ip4 = ip4h->daddr;
			return ret;
		default:
			return 3;
		}
		break;
	default:
		return 3;
	}
	}

	if (from_priv == 0 || from_priv == 2) {
		ret = cgn_flow_handle_pub(cp);
		if (!ret) {
			d->dst_addr.ip4 = bpf_htonl(cp->dst_addr);
			return cgn_pkt_rewrite_dst(ctx, cp, ip4h, payload,
						   cp->dst_addr, cp->dst_port);
		}
		if (cp->from_priv == 0)
			return ret;
	}

	ret = cgn_flow_handle_priv(cp);
	if (!ret) {
		d->dst_addr.ip4 = bpf_htonl(cp->dst_addr);
		return cgn_pkt_rewrite_src(ctx, cp, ip4h, payload,
					   cp->src_addr, cp->src_port);
	}

	return ret;
}
