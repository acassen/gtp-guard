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
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "vty.h"
#include "logger.h"
#include "list_head.h"
#include "json_writer.h"
#include "scheduler.h"
#include "jhash.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_cmd.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Some GTP command tools
 */
static void gtp_cmd_write_thread(thread_ref_t);

static int
gtp_cmd_build_gtp_v1(gtp_cmd_args_t *args)
{
	gtp1_hdr_t *gtph = (gtp1_hdr_t *) args->buffer;
	gtp1_ie_recovery_t *recovery;
	off_t hlen = sizeof(gtp1_hdr_t);

	gtph->version = 1;
	gtph->protocoltype = 1;
	gtph->seq = 1;
	gtph->type = GTP_ECHO_REQUEST_TYPE;
	gtph->length = htons(sizeof(gtp1_ie_recovery_t) + 4);
	gtph->sqn = htons(args->sqn++);

	/* Recovery is not mandatory as per 3GPP howver on the field
	 * it seems some GTPv1 peer really need it
	 */
	recovery = (gtp1_ie_recovery_t *) (args->buffer + hlen);
	recovery->type = GTP1_IE_RECOVERY_TYPE;
	recovery->recovery = daemon_data->restart_counter;

	args->buffer_len = sizeof(gtp1_hdr_t) + ntohs(gtph->length);
	return 0;
}

static int
gtp_cmd_build_gtp_v2(gtp_cmd_args_t *args)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) args->buffer;
	gtp_ie_recovery_t *recovery;
	off_t hlen = sizeof(gtp_hdr_t) - 4;

	gtph->version = 2;
	gtph->type = GTP_ECHO_REQUEST_TYPE;
	gtph->length = htons(sizeof(gtp_ie_recovery_t) + 4);

	recovery = (gtp_ie_recovery_t *) (args->buffer + hlen);
	recovery->h.type = GTP_IE_RECOVERY_TYPE;
	recovery->h.length = htons(1);
	recovery->recovery = daemon_data->restart_counter;

	args->buffer_len = hlen + ntohs(gtph->length) - 4;
	return 0;
}

static int
gtp_cmd_sendmsg(gtp_cmd_args_t *args)
{
	struct sockaddr_storage *addr = &args->addr;
	struct msghdr msg;
	struct iovec iov;

	/* Build the message data */
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = args->buffer;
	iov.iov_len = args->buffer_len;

	/* Build destination */
	msg.msg_name = addr;
	msg.msg_namelen = sizeof(*addr);

	return sendmsg(args->fd, &msg, 0);
}

static void
gtp_cmd_read_thread(thread_ref_t thread)
{
	gtp_cmd_args_t *args = THREAD_ARG(thread);
	gtp_hdr_t *gtph = (gtp_hdr_t *) args->buffer;
	struct sockaddr_storage addr_from;
	socklen_t addrlen = sizeof(addr_from);
	vty_t *vty = args->vty;
	int ret;

	thread_del_read(args->t_read);
	args->t_read = NULL;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		vty_send_out(vty, ".");
		log_message(LOG_INFO, "%s(): Timeout receiving GTPv%d Echo-Response from remote-peer [%s]:%d"
				    , __FUNCTION__
				    , args->version
				    , inet_sockaddrtos(&args->addr)
				    , ntohs(inet_sockaddrport(&args->addr)));
		goto end;
	}

	ret = recvfrom(args->fd, args->buffer, 64, 0, (struct sockaddr *) &addr_from, &addrlen);
	if (ret < 0) {
		vty_out(vty, "%% Error receiving msg from [%s]:%d (%m)%s"
			   , inet_sockaddrtos(&addr_from)
			   , ntohs(inet_sockaddrport(&addr_from))
			   , VTY_NEWLINE);
		goto end;
	}

	vty_send_out(vty, "%s", (gtph->type == GTP_ECHO_RESPONSE_TYPE) ? "!" : "?");

	log_message(LOG_INFO, "%s(): Receiving GTPv%d Echo-Response from remote-peer [%s]:%d"
			    , __FUNCTION__
			    , args->version
			    , inet_sockaddrtos(&addr_from)
			    , ntohs(inet_sockaddrport(&addr_from)));

  end:
	if (!--args->count) {
		vty_send_out(vty, "\r\n");
		vty_prompt_restore(vty);
		close(args->fd);
		FREE(args);
		return;
	}

	/* Register next write thread */
	args->t_write = thread_add_write(master, gtp_cmd_write_thread, args, args->fd, 3 * TIMER_HZ, 0);
}

static void
gtp_cmd_write_thread(thread_ref_t thread)
{
	gtp_cmd_args_t *args = THREAD_ARG(thread);
	struct sockaddr_storage *addr = &args->addr;
	vty_t *vty = args->vty;
	int ret = 0;

	thread_del_write(args->t_write);

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		vty_send_out(vty, ".");
		vty->status = VTY_NORMAL;
		close(args->fd);
		FREE(args);
		return;
	}

	/* Prepare request message */
	memset(args->buffer, 0, 64);
	if (args->version == 1)
		gtp_cmd_build_gtp_v1(args);
	else if (args->version == 2)
		gtp_cmd_build_gtp_v2(args);

	/* Warm the road */
	ret = gtp_cmd_sendmsg(args);
	if (ret < 0) {
		vty_send_out(vty, "%% Error sending msg to [%s]:%d (%m)%s"
				, inet_sockaddrtos(addr)
				, ntohs(inet_sockaddrport(addr))
				, VTY_NEWLINE);
		vty_prompt_restore(vty);
		close(args->fd);
		FREE(args);
		return;
	}

	log_message(LOG_INFO, "%s(): Sending GTPv%d Echo-Request to remote-peer [%s]:%d"
			    , __FUNCTION__
			    , args->version
			    , inet_sockaddrtos(addr)
			    , ntohs(inet_sockaddrport(addr)));

	/* Register async read thread */
	args->t_read = thread_add_read(master, gtp_cmd_read_thread, args, args->fd, 3 * TIMER_HZ, 0);
}

int
gtp_cmd_echo_request(gtp_cmd_args_t *args)
{
	vty_t *vty = args->vty;

	args->fd = socket(args->addr.ss_family, SOCK_DGRAM, 0);
	if (args->fd < 0) {
		vty_out(vty, "%% error creating UDP socket (%m)%s", VTY_NEWLINE);
		FREE(args);
		return -1;
	}

	vty_prompt_hold(vty);

	/* VTY is into the I/O scheduler context, we need to submit our
	 * msg into I/O scheduler too.
	 */
	args->t_write = thread_add_write(master, gtp_cmd_write_thread, args, args->fd, 3 * TIMER_HZ, 0);
	return 0;
}