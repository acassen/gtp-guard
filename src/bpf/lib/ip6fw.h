/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <time.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "flow.h"


/* all address/port in cpu order */
struct ip6fw_packet
{
	struct ipv6hdr *ip6h;
	__u16		src_port;
	__u16		dst_port;
	__u32		tcp_flags;
	__u8		proto;
};


/*
 * ipv6 flows
 */

#include "ip.h"

struct ip6fw_flow_key {
	union v6addr		priv_addr;
	union v6addr		pub_addr;
	__u16			priv_port;
	__u16			pub_port;
	__u8			proto;
} __attribute__((packed));

struct ip6fw_flow {
	struct bpf_timer	timer;		/* flow expiration */
	__u64			created;
	__u8			proto_state;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ip6fw_flow_key);
	__type(value, struct ip6fw_flow);
	__uint(max_entries, 1000000);
} v6_flows SEC(".maps");


static int
_flow_timer_cb(void *_map, struct ip6fw_flow_key *key,
	       struct ip6fw_flow *f)
{
	bpf_map_delete_elem(&v6_flows, key);
	return 0;
}

static struct ip6fw_flow *
_flow_alloc(const struct ip6fw_flow_key *k)
{
	struct ip6fw_flow *f;
	int ret;

	struct ip6fw_flow nf = {
		.created = bpf_ktime_get_ns(),
	};
	ret = bpf_map_update_elem(&v6_flows, k, &nf, 0);
	if (ret < 0) {
		bpf_printk("cannot add v6 flow");
		return NULL;
	}
	f = bpf_map_lookup_elem(&v6_flows, k);
	if (f == NULL) {
		bpf_printk("cannot get added v6 flow");
		return NULL;
	}

	ret = bpf_timer_init(&f->timer, &v6_flows, CLOCK_MONOTONIC);
	if (ret)
		goto err;
	ret = bpf_timer_set_callback(&f->timer, _flow_timer_cb);
	if (ret)
		goto err;

	return f;

 err:
	bpf_printk("error setting up v6 flow");
	bpf_map_delete_elem(&v6_flows, k);
	return NULL;
}

static int
ip6fw_flow_handle_priv(struct ip6fw_packet *pp)
{
	struct ip6fw_flow_key k = {
		.priv_port = pp->src_port,
		.pub_port = pp->dst_port,
		.proto = pp->proto,
	};
	struct ip6fw_flow *f;

	__builtin_memcpy(k.priv_addr.addr, pp->ip6h->saddr.s6_addr, 16);
	__builtin_memcpy(k.pub_addr.addr, pp->ip6h->daddr.s6_addr, 16);

	/* create flow if it doesn't exist */
	f = bpf_map_lookup_elem(&v6_flows, &k);
	bpf_printk("lookup priv with proto %d port priv %d pub %d  f = %p",
		   pp->proto, pp->src_port, pp->dst_port, f);
 	if (f == NULL) {
		f = _flow_alloc(&k);
		if (f == NULL)
			return 12;
	}

	if (pp->proto == IPPROTO_TCP)
		flow_update_priv_tcp_state(pp->tcp_flags, &f->proto_state);

	/* start or refresh flow timeout */
	__u64 to = flow_timeout_ns(pp->proto, pp->dst_port, f->proto_state);
	int ret = bpf_timer_start(&f->timer, to, 0);
	if (ret) {
		bpf_printk("cannot (re)start timer??? (val=%ld)", to);
		bpf_map_delete_elem(&v6_flows, &k);
		return 12;
	}

	return 0;
}

static int
ip6fw_flow_handle_pub(struct ip6fw_packet *pp)
{
	struct ip6fw_flow_key k = {
		.priv_port = pp->dst_port,
		.pub_port = pp->src_port,
		.proto = pp->proto,
	};
	struct ip6fw_flow *f;

	__builtin_memcpy(k.priv_addr.addr, pp->ip6h->daddr.s6_addr, 16);
	__builtin_memcpy(k.pub_addr.addr, pp->ip6h->saddr.s6_addr, 16);

	/* reject if flow doesn't exist */
	f = bpf_map_lookup_elem(&v6_flows, &k);
	bpf_printk("pub check with proto %d port priv %d pub %d  f = %p",
		   pp->proto, pp->dst_port, pp->src_port, f);
	if (f == NULL)
		return 10;

	if (pp->proto == IPPROTO_TCP)
		flow_update_pub_tcp_state(pp->tcp_flags, &f->proto_state);

	return 0;
}



#define IPV6_MAX_HEADERS	4


struct ipv6_frag_hdr
{
	__u8 nexthdr;
	__u8 hdrlen;
	__u16 frag_off;
	__u32 id;
} __attribute__((packed));


static void *
ipv6_skip_exthdr(struct xdp_md *ctx, struct ipv6hdr *ip6h, __u8 *out_nh)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = ip6h + 1;
	struct ipv6_opt_hdr *opthdr;
	struct ipv6_frag_hdr *fraghdr;
	__u8 nh = ip6h->nexthdr;
	int i;

	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		switch (nh) {
		case IPPROTO_NONE:
			return NULL;

		case IPPROTO_FRAGMENT:
			if (data + sizeof (*fraghdr) > data_end)
				return NULL;
			fraghdr = data;
			data = fraghdr + 1;
			nh = fraghdr->hdrlen;
			break;

		case IPPROTO_ROUTING:
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			if (data + sizeof (*opthdr) > data_end)
				return NULL;
			opthdr = data;
			data += 8 + opthdr->hdrlen * 8;
			nh = opthdr->nexthdr;
			break;

		default:
			*out_nh = nh;
			return data;
		}
	}

	return NULL;
}


static int
_ip6fw_handle_icmp_err(struct xdp_md *ctx, struct ipv6hdr *outer_ip6h,
		       struct ipv6hdr *ip6h, __u8 from_priv)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *payload;
	struct udphdr *udp;
	struct icmp6hdr *icmp6;
	struct ip6fw_packet pp = {
		.ip6h = outer_ip6h
	};

	if ((void *)(ip6h + 1) > data_end)
		return 1;

	payload = ipv6_skip_exthdr(ctx, ip6h, &pp.proto);
	if (payload == NULL)
		return 1;

	switch (pp.proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		udp = payload;
		if ((void *)(udp + 1) > data_end)
			return 1;
		pp.dst_port = bpf_ntohs(udp->source);
		pp.src_port = bpf_ntohs(udp->dest);
		break;

	case IPPROTO_ICMPV6:
		icmp6 = payload;
		if ((void *)(icmp6 + 1) > data_end)
			return 1;

		switch (icmp6->icmp6_type) {
		case ICMPV6_ECHO_REQUEST:
			pp.dst_port = bpf_ntohs(icmp6->icmp6_identifier);
			pp.src_port = 0;
			break;
		case ICMPV6_ECHO_REPLY:
			pp.dst_port = 0;
			pp.src_port = bpf_ntohs(icmp6->icmp6_identifier);
			break;
		default:
			return 2;
		}
		break;

	default:
		return 2;
	}

	if (from_priv)
		return ip6fw_flow_handle_priv(&pp);
	else
		return ip6fw_flow_handle_pub(&pp);
}


/*
 * main ip6fw entry function.
 * parameters:
 *  - ip6h: must already be checked
 *  - from_priv: 1 if packet is coming from 'private' side, else 0
 *
 * returns:
 *    0: ok. packet modified
 *    1: invalid packet
 *    2: unsupported protocol/operation
 *   10: no associated flow
 *   12: flow alloc error
 */
static int
ip6fw_pkt_handle(struct xdp_md *ctx, struct ipv6hdr *ip6h, __u8 from_priv)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *payload;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmp6hdr *icmp6;
	struct ip6fw_packet pp = {
		.ip6h = ip6h
	};

	payload = ipv6_skip_exthdr(ctx, ip6h, &pp.proto);
	if (payload == NULL)
		return 1;

	switch (pp.proto) {
	case IPPROTO_UDP:
		udp = payload;
		if ((void *)(udp + 1) > data_end)
			return 1;
		pp.src_port = bpf_ntohs(udp->source);
		pp.dst_port = bpf_ntohs(udp->dest);
		break;

	case IPPROTO_TCP:
		tcp = payload;
		if ((void *)(tcp + 1) > data_end)
			return 1;
		pp.src_port = bpf_ntohs(tcp->source);
		pp.dst_port = bpf_ntohs(tcp->dest);
		pp.tcp_flags = ((union tcp_word_hdr *)(tcp))->words[3];
		break;

	case IPPROTO_ICMPV6:
		icmp6 = payload;
		if ((void *)(icmp6 + 1) > data_end)
			return 1;

		switch (icmp6->icmp6_type) {
		case ICMPV6_ECHO_REQUEST:
			if (!from_priv)
				return 2;
			pp.src_port = bpf_ntohs(icmp6->icmp6_identifier);
			pp.dst_port = 0;
			break;

		case ICMPV6_ECHO_REPLY:
			pp.src_port = 0;
			pp.dst_port = bpf_ntohs(icmp6->icmp6_identifier);
			break;

		case ICMPV6_DEST_UNREACH:
		case ICMPV6_PKT_TOOBIG:
		case ICMPV6_TIME_EXCEED:
		case ICMPV6_PARAMPROB:
			/* always allow from priv. reply not expected, don't keep flow */
			if (from_priv)
				return 0;

			/* check if original flow exists before forwarding */
			return _ip6fw_handle_icmp_err(ctx, ip6h, (struct ipv6hdr *)(icmp6 + 1),
						      from_priv);

		default:
			return 2;
		}
		break;

	default:
		return 2;
	}

	if (from_priv)
		return ip6fw_flow_handle_priv(&pp);
	else
		return ip6fw_flow_handle_pub(&pp);

	return 0;
}
