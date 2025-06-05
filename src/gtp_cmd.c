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

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Some GTP command tools
 */
static void gtp_cmd_write_thread(thread_ref_t);
static int gtp_cmd_update_udp_hlen(char *, size_t);
static int gtp_cmd_update_ip_hlen(char *, size_t);

static int
gtp_cmd_build_gtp_v1(gtp_cmd_args_t *args)
{
	char *buffer = args->buffer + args->buffer_offset;
	gtp1_hdr_t *gtph = (gtp1_hdr_t *) buffer;
	gtp1_ie_recovery_t *recovery;
	off_t hlen = sizeof(gtp1_hdr_t);
	size_t tot_len;

	gtph->version = 1;
	gtph->protocoltype = 1;
	gtph->seq = 1;
	gtph->type = GTP_ECHO_REQUEST_TYPE;
	gtph->length = htons(sizeof(gtp1_ie_recovery_t) + 4);
	gtph->sqn = htons(args->sqn++);
	tot_len = sizeof(gtp1_hdr_t) + ntohs(gtph->length);

	/* Recovery is not mandatory as per 3GPP howver on the field
	 * it seems some GTPv1 peer really need it
	 */
	recovery = (gtp1_ie_recovery_t *) (buffer + hlen);
	recovery->type = GTP1_IE_RECOVERY_TYPE;
	recovery->recovery = daemon_data->restart_counter;

	/* In extended RAW mode update IP + UDP header len */
	if (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED) {
		gtp_cmd_update_ip_hlen(args->buffer, tot_len);
		gtp_cmd_update_udp_hlen(args->buffer, tot_len);
	}

	args->buffer_len += tot_len;
	return 0;
}

static int
gtp_cmd_build_gtp_v2(gtp_cmd_args_t *args)
{
	char *buffer = args->buffer + args->buffer_offset;
	gtp_hdr_t *gtph = (gtp_hdr_t *) buffer;
	gtp_ie_recovery_t *recovery;
	off_t hlen = sizeof(gtp_hdr_t) - 4;
	size_t tot_len;

	gtph->version = 2;
	gtph->type = GTP_ECHO_REQUEST_TYPE;
	gtph->length = htons(sizeof(gtp_ie_recovery_t) + 4);
	tot_len = hlen + ntohs(gtph->length) - 4;

	recovery = (gtp_ie_recovery_t *) (buffer + hlen);
	recovery->h.type = GTP_IE_RECOVERY_TYPE;
	recovery->h.length = htons(1);
	recovery->recovery = daemon_data->restart_counter;

	/* In extended RAW mode update IP + UDP header len */
	if (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED) {
		gtp_cmd_update_ip_hlen(args->buffer, tot_len);
		gtp_cmd_update_udp_hlen(args->buffer, tot_len);
	}

	args->buffer_len += tot_len;
	return 0;
}

static int
gtp_cmd_update_udp_hlen(char *buffer, size_t len)
{
	struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct iphdr));

	udph->len = htons(ntohs(udph->len) + len);
	return 0;
}

static int
gtp_cmd_build_udp(gtp_cmd_args_t *args, char *buffer)
{
	struct udphdr *udph = (struct udphdr *) buffer;

	udph->source = ((struct sockaddr_in *) &args->src_addr)->sin_port;
	udph->dest = ((struct sockaddr_in *) &args->dst_addr)->sin_port;
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0;

	args->buffer_len += sizeof(struct udphdr);
	return sizeof(struct udphdr);
}

static int
gtp_cmd_update_ip_hlen(char *buffer, size_t len)
{
	struct iphdr *iph = (struct iphdr *) buffer;

	iph->tot_len = htons(ntohs(iph->tot_len) + len);
	return 0;
}

static int
gtp_cmd_build_ip(gtp_cmd_args_t *args, char *buffer)
{
	struct iphdr *iph = (struct iphdr *) buffer;

	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->version = 4;
	/* set tos to internet network control */
	iph->tos = 0xc0;
	iph->tot_len = (uint16_t)(sizeof(struct iphdr) + sizeof(struct udphdr));
	iph->tot_len = htons(iph->tot_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = ((struct sockaddr_in *) &args->src_addr)->sin_addr.s_addr;
	iph->daddr = ((struct sockaddr_in *) &args->dst_addr)->sin_addr.s_addr;
	iph->check = 0;
	iph->check = in_csum((uint16_t *) iph, sizeof(struct iphdr), 0);

	args->buffer_len += sizeof(struct iphdr);
	return sizeof(struct iphdr);
}

static size_t
gtp_cmd_build_pkt(gtp_cmd_args_t *args)
{
	char *bufptr = args->buffer;
	size_t offset = 0;

	offset += gtp_cmd_build_ip(args, bufptr);
	offset += gtp_cmd_build_udp(args, bufptr + offset);

	return offset;
}

static int
gtp_cmd_sendmsg(gtp_cmd_args_t *args)
{
	struct sockaddr_storage *addr = &args->dst_addr;
	struct msghdr msg;
	struct iovec iov;
	int fd;

	/* Build the message data */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = args->buffer;
	iov.iov_len = args->buffer_len;

	/* Build destination */
	msg.msg_name = addr;
	msg.msg_namelen = sizeof(*addr);

	fd = (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED) ? args->fd_out : args->fd_in;
	return sendmsg(fd, &msg, 0);
}

static int
gtp_cmd_args_destroy(gtp_cmd_args_t *args)
{
	vty_t *vty = args->vty;

	vty_prompt_restore(vty);
	close(args->fd_in);
	if (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED)
		close(args->fd_out);
	FREE(args);
	return 0;
}

static void
gtp_cmd_read_thread(thread_ref_t thread)
{
	gtp_cmd_args_t *args = THREAD_ARG(thread);
	struct sockaddr_storage addr_from;
	socklen_t addrlen = sizeof(addr_from);
	vty_t *vty = args->vty;
	gtp_hdr_t *gtph;
	off_t offset = 0;
	int ret, fd;

	thread_del_read(args->t_read);
	args->t_read = NULL;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		vty_send_out(vty, ".");
		log_message(LOG_INFO, "%s(): Timeout receiving GTPv%d Echo-Response from remote-peer [%s]:%d"
				    , __FUNCTION__
				    , args->version
				    , inet_sockaddrtos(&args->dst_addr)
				    , ntohs(inet_sockaddrport(&args->dst_addr)));
		goto end;
	}

	ret = recvfrom(args->fd_in, args->buffer, GTP_CMD_BUFFER_SIZE, 0
				  , (struct sockaddr *) &addr_from, &addrlen);
	if (ret < 0) {
		vty_out(vty, "%% Error receiving msg from [%s]:%d (%m)%s"
			   , inet_sockaddrtos(&addr_from)
			   , ntohs(inet_sockaddrport(&addr_from))
			   , VTY_NEWLINE);
		goto end;
	}

	if (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED) {
		addr_from = args->dst_addr;
		offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	}

	gtph = (gtp_hdr_t *) (args->buffer + offset);
	vty_send_out(vty, "%s", (gtph->type == GTP_ECHO_RESPONSE_TYPE) ? "!" : "?");

	log_message(LOG_INFO, "%s(): Receiving GTPv%d Echo-Response from remote-peer [%s]:%d"
			    , __FUNCTION__
			    , args->version
			    , inet_sockaddrtos(&addr_from)
			    , ntohs(inet_sockaddrport(&addr_from)));

  end:
	if (!--args->count) {
		vty_send_out(vty, "\r\n");
		gtp_cmd_args_destroy(args);
		return;
	}

	/* Register next write thread */
	fd = (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED) ? args->fd_out : args->fd_in;
	args->t_write = thread_add_write(master, gtp_cmd_write_thread, args, fd, 3 * TIMER_HZ, 0);
}

static void
gtp_cmd_write_thread(thread_ref_t thread)
{
	gtp_cmd_args_t *args = THREAD_ARG(thread);
	struct sockaddr_storage *addr = &args->dst_addr;
	vty_t *vty = args->vty;
	int ret = 0;

	thread_del_write(args->t_write);
	args->t_write = NULL;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		vty_send_out(vty, ".");
		gtp_cmd_args_destroy(args);
		return;
	}

	/* Prepare request message */
	memset(args->buffer, 0, GTP_CMD_BUFFER_SIZE);
	args->buffer_len = args->buffer_offset = 0;

	/* Build IP + UDP headers for extended flavor */
	if (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED)
		args->buffer_offset = gtp_cmd_build_pkt(args);

	/* GTP */
	ret = (args->version == 1) ? gtp_cmd_build_gtp_v1(args) : gtp_cmd_build_gtp_v2(args);

	/* Warm the road */
	ret = gtp_cmd_sendmsg(args);
	if (ret < 0) {
		vty_send_out(vty, "%% Error sending msg to [%s]:%d (%m)%s"
				, inet_sockaddrtos(addr)
				, ntohs(inet_sockaddrport(addr))
				, VTY_NEWLINE);
		vty_prompt_restore(vty);
		close(args->fd_in);
		FREE(args);
		return;
	}

	log_message(LOG_INFO, "%s(): Sending GTPv%d Echo-Request to remote-peer [%s]:%d"
			    , __FUNCTION__
			    , args->version
			    , inet_sockaddrtos(addr)
			    , ntohs(inet_sockaddrport(addr)));

	/* Register async read thread */
	args->t_read = thread_add_read(master, gtp_cmd_read_thread, args, args->fd_in, 3 * TIMER_HZ, 0);
}

static int
gtp_cmd_cbpf_egress_init(void)
{
	int fd;

	fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_RAW);
	if (fd < 0)
		return -1;
	inet_setsockopt_hdrincl(fd);
	inet_setsockopt_priority(&fd, AF_INET);
	inet_setsockopt_no_receive(&fd);
	return fd;
}

/*
 *	cBPF Layer3 + Layer4 + GTP
 *
 * ASM code:
 *	(000) ldh      [12]
 *	(001) jeq      #0x800           jt 2	jf 20
 *	(002) ld       [26]
 *	(003) jeq      #0x1010101       jt 4	jf 20	; ip_dst
 *	(004) ld       [30]
 *	(005) jeq      #0x2020202       jt 6	jf 20	; ip_src
 *	(006) ldb      [23]
 *	(007) jeq      #0x11            jt 8	jf 20
 *	(008) ldh      [20]
 *	(009) jset     #0x1fff          jt 20	jf 10
 *	(010) ldxb     4*([14]&0xf)
 *	(011) ldh      [x + 16]
 *	(012) jeq      #0x84b           jt 13	jf 20	; UDP port_dst
 *	(013) ldb      [x + 22]
 *	(014) and      #0xf0
 *	(015) rsh      #5
 *	(016) jeq      #0x2             jt 17	jf 20	; GTP Version
 *	(017) ldb      [x + 23]
 *	(018) jeq      #0x2             jt 19	jf 20	; GTP Echo-Response
 *	(019) ret      #0xffffffff
 *	(020) ret      #0
 */
static int
gtp_cmd_echo_request_cbpf_ingress_init(gtp_cmd_args_t *args)
{
	vty_t *vty = args->vty;
	int fd, ret;
	struct sock_filter bpfcode[21] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 18, 0x00000800 },
		{ 0x20, 0, 0, 0x0000001e },
		{ 0x15, 0, 16, 0x01010101 },
		{ 0x20, 0, 0, 0x0000001a },
		{ 0x15, 0, 14, 0x02020202 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 12, 0x00000011 },
		{ 0x28, 0, 0, 0x00000014 },
		{ 0x45, 10, 0, 0x00001fff },
		{ 0xb1, 0, 0, 0x0000000e },
		{ 0x48, 0, 0, 0x00000010 },
		{ 0x15, 0, 7, 0x0000084b },
		{ 0x50, 0, 0, 0x00000016 },
		{ 0x54, 0, 0, 0x000000f0 },
		{ 0x74, 0, 0, 0x00000005 },
		{ 0x15, 0, 3, 0x00000001 },
		{ 0x50, 0, 0, 0x00000017 },
		{ 0x15, 0, 1, 0x00000002 },
		{ 0x6, 0, 0, (uint)-1 },
		{ 0x6, 0, 0, 0 }
	};
	struct sock_fprog bpf = {
		.len = ARRAY_SIZE(bpfcode),
		.filter = bpfcode
	};
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = args->ifindex,
		.sll_hatype = 0,
		.sll_pkttype = PACKET_HOST,
		.sll_halen = 0,
	};

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ALL));
	if (fd < 0)
		return -1;

	ret = bind(fd, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll));
	if (ret < 0) {
		vty_out(vty, "%% failed binding to ifindex:%d (%m)%s"
			   , args->ifindex, VTY_NEWLINE);
		close(fd);
		return -1;
	}

	/* Prepare filter */
	bpfcode[3].k = ntohl(((struct sockaddr_in *) &args->src_addr)->sin_addr.s_addr);
	bpfcode[5].k = ntohl(((struct sockaddr_in *) &args->dst_addr)->sin_addr.s_addr);
	bpfcode[12].k = ntohs(((struct sockaddr_in *) &args->src_addr)->sin_port);
	bpfcode[16].k = args->version;

	/* Attach filter */
	ret = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0) {
		vty_out(vty, "%% failed to attach filter to ifindex:%d (%m)%s"
			   , args->ifindex, VTY_NEWLINE);
		close(fd);
		return -1;
	}

	return fd;
}

static int
gtp_cmd_echo_request_cbpf_init(gtp_cmd_args_t *args)
{
	vty_t *vty = args->vty;

	/* Ingress Channel*/
	args->fd_in = gtp_cmd_echo_request_cbpf_ingress_init(args);
	if (args->fd_in < 0) {
		vty_out(vty, "%% error creating ingress channel (%m)%s", VTY_NEWLINE);
		return -1;
	}

	/* Egress Channel*/
	args->fd_out = gtp_cmd_cbpf_egress_init();
	if (args->fd_out < 0) {
		vty_out(vty, "%% error creating egress channel (%m)%s", VTY_NEWLINE);
		return -1;
	}

	return 0;
}

int
gtp_cmd_echo_request(gtp_cmd_args_t *args)
{
	vty_t *vty = args->vty;

	/* Unnumbered init */
	if (args->type == GTP_CMD_ECHO_REQUEST) {
		args->fd_in = socket(args->dst_addr.ss_family, SOCK_DGRAM, 0);
		if (args->fd_in < 0) {
			vty_out(vty, "%% error creating UDP socket (%m)%s", VTY_NEWLINE);
			FREE(args);
			return -1;
		}
	} else if (args->type == GTP_CMD_ECHO_REQUEST_EXTENDED) {
		if (gtp_cmd_echo_request_cbpf_init(args) < 0) {
			FREE(args);
			return -1;
		}
	}

	vty_prompt_hold(vty);

	/* VTY is into the I/O scheduler context, we need to submit our
	 * msg into I/O scheduler too.
	 */
	args->t_write = thread_add_write(master, gtp_cmd_write_thread, args, args->fd_in, 3 * TIMER_HZ, 0);
	return 0;
}
