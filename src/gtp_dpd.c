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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#include "gtp.h"
#include "gtp_dpd.h"
#include "gtp_bpf.h"
#include "gtp_mirror.h"
#include "inet_utils.h"
#include "logger.h"
#include "utils.h"

/* Extern data */
extern struct thread_master *master;

/*
 *	Egress Handling
 */

/* Packet related */
static int
gtp_dpd_build_gtpu(struct gtp_iptnl *t, uint8_t *buffer)
{
	struct gtp_hdr *gtph = (struct gtp_hdr *) buffer;
	off_t offset = GTPV1U_HEADER_LEN;
	struct gtpu_ie *ie;
	struct gtpu_ie_private *priv;
	uint8_t *payload = buffer + GTPV1U_HEADER_LEN + sizeof(struct gtpu_ie);

	gtph->version = 2;
	gtph->piggybacked = 0;
	gtph->teid_presence = 0;
	gtph->spare = 0;
	gtph->type = GTPU_ECHO_REQ_TYPE;
	gtph->length = htons(t->payload_len);
	gtph->sqn_only = htonl(0x8badf00d);

	if (!t->payload_len)
		return sizeof(struct gtp_hdr);

	ie = (struct gtpu_ie *) (buffer + offset);
	ie->type = 0xff;
	ie->length = htons(t->payload_len-sizeof(struct gtpu_ie)-1);

	offset += sizeof(struct gtpu_ie);
	priv = (struct gtpu_ie_private *) (buffer + offset);
	priv->type = 0;
	priv->id = htons(0);
	offset += sizeof(struct gtpu_ie_private);

	payload = buffer + offset;
	memset(payload, '!', t->payload_len-sizeof(struct gtpu_ie)-sizeof(struct gtpu_ie_private));

	return sizeof(struct gtp_hdr) + t->payload_len;
}

static int
gtp_dpd_build_udp(struct gtp_iptnl *t, uint8_t *buffer)
{
	struct udphdr *udph = (struct udphdr *) buffer;

	udph->source = htons(GTP_U_PORT);
	udph->dest = htons(GTP_U_PORT);
	udph->len = htons(sizeof(struct udphdr) + GTPV1U_HEADER_LEN + t->payload_len);
	udph->check = 0;

	return sizeof(struct udphdr);
}

static int
gtp_dpd_build_ip(struct gtp_iptnl *t, uint8_t *buffer)
{
	struct iphdr *iph = (struct iphdr *) buffer;

	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->version = 4;
	/* set tos to internet network control */
	iph->tos = 0xc0;
	iph->tot_len = (uint16_t)(sizeof(struct iphdr) + sizeof(struct udphdr) + GTPV1U_HEADER_LEN + t->payload_len);
	iph->tot_len = htons(iph->tot_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = t->dpd_saddr;
	iph->daddr = htonl(DEFAULT_DST_ADDR);
	iph->check = 0;
	iph->check = in_csum((uint16_t *) iph, sizeof(struct iphdr), 0);

	return sizeof(struct iphdr);
}

static int
gtp_dpd_build_ip_encap(struct gtp_iptnl *t, uint8_t *buffer)
{
	struct iphdr *iph = (struct iphdr *) buffer;

	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->version = 4;
	/* set tos to internet network control */
	iph->tos = 0xc0;
	iph->tot_len = (uint16_t)(2*sizeof(struct iphdr) + sizeof(struct udphdr) + GTPV1U_HEADER_LEN + t->payload_len);
	iph->tot_len = htons(iph->tot_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_IPIP;
	iph->saddr = t->local_addr;
	iph->daddr = t->remote_addr;
	iph->check = 0;

	return sizeof(struct iphdr);
}

static int
gtp_dpd_build_pkt(struct gtp_iptnl *t)
{
	uint8_t *bufptr = t->send_buffer;
	size_t offset = 0;

	offset += gtp_dpd_build_ip_encap(t, bufptr);
	offset += gtp_dpd_build_ip(t, bufptr + offset);
	offset += gtp_dpd_build_udp(t, bufptr + offset);
	offset += gtp_dpd_build_gtpu(t, bufptr + offset);
	t->send_buffer_size = offset;

	return 0;
}

/* Socket related */
static ssize_t
gtp_dpd_send_pkt(struct gtp_iptnl *t)
{
	struct sockaddr_in dst;
	struct msghdr msg;
	struct iovec iov;

	/* Build the message data */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = t->send_buffer;
	iov.iov_len = t->send_buffer_size;

	/* Build destination */
	memset(&dst, 0, sizeof(struct sockaddr_in));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = t->remote_addr;
	msg.msg_name = &dst;
	msg.msg_namelen = sizeof(struct sockaddr_in);

	return sendmsg(t->fd_out, &msg, 0);
}


static void
gtp_dpd_timer_thread(struct thread *thread)
{
	struct gtp_proxy *p = THREAD_ARG(thread);
	struct gtp_iptnl *t = &p->iptnl;
	ssize_t ret;

	ret = gtp_dpd_send_pkt(t);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error sending DPD heartbeat (%m)"
				    , __FUNCTION__);
	}

	/* Timer fired ? */
	if ((t->flags & IPTNL_FL_DEAD) && (t->expire > timer_long(time_now))) {
		log_message(LOG_INFO, "%s(): Peer back to life"
				      " (s:%u.%u.%u.%u l:%u.%u.%u.%u r:%u.%u.%u.%u)"
				    , __FUNCTION__
				    , NIPQUAD(t->dpd_saddr)
				    , NIPQUAD(t->local_addr)
				    , NIPQUAD(t->remote_addr));
		t->flags &= ~IPTNL_FL_DEAD;
		p->ipip_dead = false;
		gtp_proxy_rules_set(p);
		gtp_mirror_brd_action(RULE_ADD, t->ifindex);
		goto end;
	}

	if (!(t->flags & IPTNL_FL_DEAD) && (t->expire < timer_long(time_now))) {
		log_message(LOG_INFO, "%s(): Dead Peer Detected (bypassing)"
				      " (s:%u.%u.%u.%u l:%u.%u.%u.%u r:%u.%u.%u.%u)"
				    , __FUNCTION__
				    , NIPQUAD(t->dpd_saddr)
				    , NIPQUAD(t->local_addr)
				    , NIPQUAD(t->remote_addr));
		t->flags |= IPTNL_FL_DEAD;
		p->ipip_dead = true;
		gtp_proxy_rules_set(p);
		gtp_mirror_brd_action(RULE_DEL, t->ifindex);
	}

  end:
	thread_add_timer(master, gtp_dpd_timer_thread, p, TIMER_HZ);
}

static int
gtp_dpd_egress_socket_init(void)
{
	int fd, err;

	fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_IPIP);
	if (fd < 0)
		return -1;

	err = inet_setsockopt_hdrincl(fd);
	err = (err) ? : inet_setsockopt_priority(fd, AF_INET);
	err = (err) ? : inet_setsockopt_no_receive(fd);
	if (err)
		close(fd);

	return (err) ? -1 : fd;
}


/*
 *	Ingress handling
 */
static int
gtp_dpd_ingress_sanitize(struct gtp_iptnl *t)
{
	struct iphdr *iph = (struct iphdr *) t->recv_buffer;
	struct udphdr *udph;
	struct gtp_hdr *gtph;

	/* IP Header sanitize */
	if (iph->protocol != IPPROTO_UDP	||
	    iph->saddr != t->dpd_saddr		||
	    iph->daddr != htonl(DEFAULT_DST_ADDR))
		return -1;

	/* UDP header sanitize */
	udph = (struct udphdr *) (t->recv_buffer + sizeof(struct iphdr));
	if (udph->source != htons(GTP_U_PORT) || udph->source != udph->dest)
		return -1;

	/* GTP-U header sanitize */
	gtph = (struct gtp_hdr *) (t->recv_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
	if (gtph->type != GTPU_ECHO_REQ_TYPE || gtph->sqn_only != htonl(0x8badf00d))
		return -1;

	return 0;
}

static void
gtp_dpd_read_thread(struct thread *t)
{
	struct gtp_proxy *p = THREAD_ARG(t);
	struct gtp_iptnl *tnl = &p->iptnl;
	ssize_t len;
	int ret;

	/* Handle read timeout */
	if (t->type == THREAD_READ_TIMEOUT)
		goto end;

	len = read(tnl->fd_in, (unsigned char *) tnl->recv_buffer, GTP_BUFFER_SIZE);
	if (len < 0) {
		log_message(LOG_INFO, "%s(): Error receiving DPD heartbeat (%m)"
				    , __FUNCTION__);
		goto end;
	}
	tnl->recv_buffer_size = len;

	/* Sanitize */
	ret = gtp_dpd_ingress_sanitize(tnl);
	if (ret < 0)
		goto end;

	/* Update expire */
	tnl->expire = timer_long(time_now) + tnl->credit;

end:
	tnl->r_thread = thread_add_read(master, gtp_dpd_read_thread, p, tnl->fd_in, TIMER_HZ, 0);
}

/*
 *	BPF Layer3 & Layer4 filtering
 *
 * ASM code:
 *	(000) ldb      [0]
 *	(001) and      #0xf0
 *	(002) jeq      #0x40            jt 3	jf 17
 *	(003) ld       [12]
 *	(004) jeq      #0x8badf00d      jt 5	jf 17
 *	(005) ld       [16]
 *	(006) jeq      #0x8badf00d      jt 7	jf 17
 *	(007) ldb      [9]
 *	(008) jeq      #0x11            jt 9	jf 17
 *	(009) ldh      [6]
 *	(010) jset     #0x1fff          jt 17	jf 11
 *	(011) ldxb     4*([0]&0xf)
 *	(012) ldh      [x + 0]
 *	(013) jeq      #0x868           jt 14	jf 17
 *	(014) ldh      [x + 2]
 *	(015) jeq      #0x868           jt 16	jf 17
 *	(016) ret      #262144
 *	(017) ret      #0
 */
static int
gtp_dpd_ingress_socket_init(struct gtp_iptnl *t)
{
	int fd, err;
	struct sock_filter bpfcode[18] = {
		{ 0x30, 0, 0, 0x00000000  },
		{ 0x54, 0, 0, 0x000000f0  },
		{ 0x15, 0, 14, 0x00000040 },
		{ 0x20, 0, 0, 0x0000000c  },
		{ 0x15, 0, 12, 0x8badf00d },
		{ 0x20, 0, 0, 0x00000010  },
		{ 0x15, 0, 10, 0x8badf00d },
		{ 0x30, 0, 0, 0x00000009  },
		{ 0x15, 0, 8, 0x00000011  },
		{ 0x28, 0, 0, 0x00000006  },
		{ 0x45, 6, 0, 0x00001fff  },
		{ 0xb1, 0, 0, 0x00000000  },
		{ 0x48, 0, 0, 0x00000000  },
		{ 0x15, 0, 3, 0x00000868  },
		{ 0x48, 0, 0, 0x00000002  },
		{ 0x15, 0, 1, 0x00000868  },
		{ 0x6, 0, 0, 0x00040000   },
		{ 0x6, 0, 0, 0x00000000   }
	};
	struct sock_fprog bpf = {
		.len = ARRAY_SIZE(bpfcode),
		.filter = bpfcode
	};
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = t->ifindex,
		.sll_hatype = 0,
		.sll_pkttype = PACKET_HOST,
		.sll_halen = 0,
	};

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ALL));
	if (fd < 0)
		return -1;

	err = bind(fd, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll));
	if (err) {
		log_message(LOG_INFO, "%s(): failed binding to ifindex:%d. (%m)"
				    , __FUNCTION__
				    , t->ifindex);
		close(fd);
		return -1;
	}

	/* Prepare filter */
	bpfcode[4].k = ntohl(t->dpd_saddr);
	bpfcode[6].k = DEFAULT_DST_ADDR;

	/* Attach filter */
	err = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (err) {
		log_message(LOG_INFO, "%s(): failed to attach filter. (%m)"
				    , __FUNCTION__);
		close(fd);
		return -1;
	}

	return fd;
}

/*
 *      Dead-Peer-Detection channel
 */
int
gtp_dpd_init(struct gtp_proxy *p)
{
	struct gtp_iptnl *t = &p->iptnl;

	/* Ingress Channel */
	t->fd_in = gtp_dpd_ingress_socket_init(t);
	if (t->fd_in < 0) {
		log_message(LOG_INFO, "%s(): Error creating ingress DPD socket (%m)"
				    , __FUNCTION__);
		return -1;
	}

	/* Egress Channel */
	t->fd_out = gtp_dpd_egress_socket_init();
	if (t->fd_out < 0) {
		log_message(LOG_INFO, "%s(): Error creating egress DPD socket (%m)"
				    , __FUNCTION__);
		close(t->fd_in);
		return -1;
	}

	gtp_dpd_build_pkt(t);

	/* Scheduling submition */
	t->r_thread = thread_add_read(master, gtp_dpd_read_thread, p, t->fd_in, TIMER_HZ, 0);
	thread_add_event(master, gtp_dpd_timer_thread, p, 0);
	return 0;
}

int
gtp_dpd_destroy(struct gtp_proxy *p)
{
	struct gtp_iptnl *t = &p->iptnl;

	if (!(t->flags & IPTNL_FL_DPD))
		return -1;

	close(t->fd_in);
	close(t->fd_out);
	return 0;
}
