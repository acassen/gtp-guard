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

#include "xsk.h"
#include "cgn-def.h"



/*
 * maps
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1);
} v4_pool_addr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cgn_v4_flow_priv_key);
	__type(value, struct cgn_v4_flow_priv);
	__uint(max_entries, 1);
} v4_priv_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cgn_v4_flow_pub_key);
	__type(value, struct cgn_v4_flow_pub);
	__uint(max_entries, 1);
} v4_pub_flows SEC(".maps");


/*
 * update tcp flow state. make it easy:
 *   0: init
 *   1: established, got syn+ack from pub
 *   2: fin or rst received from any side
 *
 * this flow will have bigger timeout in state 1 than in 0 or 2.
 */
static __always_inline void
flow_update_priv_tcp_state(struct cgn_packet *cp, struct cgn_v4_flow_priv *f)
{
	if (cp->tcp_flags & (TCP_FLAG_RST | TCP_FLAG_FIN))
		f->proto_state = 2;
	else
		return;

	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = f->cgn_addr,
		.pub_addr = cp->dst_addr,
		.cgn_port = f->cgn_port,
		.pub_port = cp->dst_port,
		.proto = cp->proto,
	};
	struct cgn_v4_flow_pub *pub_f;
	pub_f = bpf_map_lookup_elem(&v4_pub_flows, &pub_k);
	if (pub_f != NULL)
		pub_f->proto_state = f->proto_state;
}

static __always_inline void
flow_update_pub_tcp_state(struct cgn_packet *cp, struct cgn_v4_flow_pub *f)
{
	if (cp->tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) && f->proto_state == 0)
		/* got syn+ack, go to established */
		f->proto_state = 1;

	else if (cp->tcp_flags & (TCP_FLAG_RST | TCP_FLAG_FIN))
		f->proto_state = 2;

	else
		return;

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


/*
 * packet from private: may create user/flow,
 * and update src addr/port.
 *
 * return:
 *    0: ok
 *    1: internal
 *    2: redirected to xsk
 *   10: no associated flow
 *   11: user alloc error
 *   12: flow alloc error
 *   13: packet from pub
 */
static __always_inline int
cgn_flow_handle_priv(struct xdp_md *ctx, struct if_rule_data *d, struct cgn_packet *cp)
{
	struct cgn_v4_flow_priv *f;
	void *p;
	int ret;

	struct cgn_v4_flow_priv_key priv_k = {
		.priv_addr = cp->src_addr,
		.pub_addr = cp->dst_addr,
		.priv_port = cp->src_port,
		.pub_port = cp->dst_port,
		.proto = cp->proto,
	};

	f = bpf_map_lookup_elem(&v4_priv_flows, &priv_k);
	if (f == NULL) {
		if (cp->icmp_err_off)
			return 10;

		/* this packet is for egress (to our ip pool pub) */
		if (cp->from_priv == 2) {
			p = bpf_map_lookup_elem(&v4_pool_addr, &cp->dst_addr);
			if (p != NULL)
				return 13;
		}

		/* redirect to userspace, so it will create flow */
		if (xsk_to_userspace(ctx, d, &priv_k, sizeof (priv_k)) < 0)
			return 1;
		return 2;
	}

	f->last_use = bpf_ktime_get_ns();

	if (cp->proto == IPPROTO_TCP)
		flow_update_priv_tcp_state(cp, f);

	cp->src_addr = f->cgn_addr;
	cp->src_port = f->cgn_port;

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
	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = cp->dst_addr,
		.pub_addr = cp->src_addr,
		.cgn_port = cp->dst_port,
		.pub_port = cp->src_port,
		.proto = cp->proto,
	};

	f = bpf_map_lookup_elem(&v4_pub_flows, &pub_k);
	if (f == NULL)
		return 10;

	if (cp->proto == IPPROTO_TCP)
		flow_update_pub_tcp_state(cp, f);

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
cgn_pkt_rewrite_src(struct xdp_md *ctx, struct cgn_packet *cp, struct iphdr *ip4h,
		    void *payload, __u32 addr, __u16 port)
{
	void *data_end = (void *)(long)ctx->data_end;
	__u32 sum;

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
_handle_pkt_icmp_error(struct xdp_md *ctx, struct if_rule_data *d, struct cgn_packet *cp,
		       struct iphdr *outer_ip4h, struct icmphdr *outer_icmp,
		       struct iphdr *ip4h)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 sum, addr;
	int ret;

	if ((void *)(ip4h + 1) > data_end || ip4h->version != 4)
		return 2;

	/* parse packet with swapped src/dst, in order to be able
	 * to lookup flow */
	cp->proto = ip4h->protocol;
	cp->src_addr = ip4h->daddr;
	cp->dst_addr = ip4h->saddr;
	cp->icmp_err_off = (void *)outer_icmp - data;

	struct udphdr *udp = (void *)(ip4h) + ip4h->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return 2;

	switch (ip4h->protocol) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		cp->dst_port = udp->source;
		cp->src_port = udp->dest;
		break;
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp = (struct icmphdr *)udp;
		switch (icmp->type) {
		case ICMP_ECHO:
			cp->dst_port = icmp->un.echo.id;
			cp->src_port = 0;
			break;
		case ICMP_ECHOREPLY:
			cp->dst_port = 0;
			cp->src_port = icmp->un.echo.id;
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
			ret = cgn_pkt_rewrite_src(ctx, cp, ip4h, udp,
						  cp->dst_addr, cp->dst_port);
			if (ret)
				return ret;

			sum = csum_diff32(0, outer_ip4h->daddr, cp->dst_addr);
			outer_ip4h->daddr = cp->dst_addr;
			goto end;
		}
		if (cp->from_priv == 0)
			return ret;
	}

	ret = cgn_flow_handle_priv(ctx, d, cp);
	if (ret)
		return ret;
	ret = cgn_pkt_rewrite_dst(ctx, cp, ip4h, udp, cp->src_addr, cp->src_port);
	if (ret)
		return ret;

	sum = csum_diff32(0, outer_ip4h->saddr, cp->src_addr);
	outer_ip4h->saddr = cp->src_addr;

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
cgn_pkt_handle(struct xdp_md *ctx, struct if_rule_data *d, __u8 from_priv)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *data_meta = (void *)(long)ctx->data_meta;
	struct cgn_packet *cp;
	struct iphdr *ip4h;
	void *payload;
	int ret;

	ret = 0;
	cp = bpf_map_lookup_elem(&cgn_on_stack, &ret);
	if (cp == NULL)
		return 1;

	ip4h = data + d->pl_off;
	if (d->pl_off > 256 || (void *)(ip4h + 1) > data_end)
		return 2;

	cp->proto = ip4h->protocol;
	cp->from_priv = from_priv;
	cp->src_addr = ip4h->saddr;
	cp->dst_addr = ip4h->daddr;
	cp->icmp_err_off = 0;
	payload = (void *)ip4h + ip4h->ihl * 4;

#ifdef CGN_DEBUG
	bpf_printk("priv:%d parse proto: %d dst: %pI4 ihl %d/%d", from_priv,
		   cp->proto, &ip4h->daddr, ip4h->ihl, ip4h->version);
#endif

	switch (cp->proto) {
	case IPPROTO_UDP:
	{
		struct udphdr *udp = payload;
		if ((void *)(udp + 1) > data_end)
			return 2;
		cp->src_port = udp->source;
		cp->dst_port = udp->dest;
		break;
	}
	case IPPROTO_TCP:
	{
		struct tcphdr *tcp = payload;
		if ((void *)(tcp + 1) > data_end)
			return 2;
		cp->src_port = tcp->source;
		cp->dst_port = tcp->dest;
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
			cp->src_port = icmp->un.echo.id;
			cp->dst_port = 0;
			break;
		case ICMP_ECHOREPLY:
			cp->src_port = 0;
			cp->dst_port = icmp->un.echo.id;
			break;
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
			ret = _handle_pkt_icmp_error(ctx, d, cp, ip4h, icmp,
						     (struct iphdr *)(icmp + 1));
			if (ret == 0)
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
			d->dst_addr.ip4 = cp->dst_addr;
			return cgn_pkt_rewrite_dst(ctx, cp, ip4h, payload,
						   cp->dst_addr, cp->dst_port);
		}
		if (cp->from_priv == 0)
			return ret;
	}

	ret = cgn_flow_handle_priv(ctx, d, cp);
	if (!ret) {
		d->dst_addr.ip4 = cp->dst_addr;
		return cgn_pkt_rewrite_src(ctx, cp, ip4h, payload,
					   cp->src_addr, cp->src_port);
	}

	return ret;
}
