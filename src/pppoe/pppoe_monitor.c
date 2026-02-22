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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#include "pppoe.h"
#include "bitops.h"
#include "logger.h"
#include "utils.h"

/*
 *	Monitoring thread
 */
static void
pppoe_vrrp_timer_thread(struct thread *thread)
{
	struct pppoe *pppoe = THREAD_ARG(thread);

	/* Timer fired ? */
	if (__test_bit(PPPOE_FL_FAULT_BIT, &pppoe->flags) && (pppoe->expire > timer_long(time_now))) {
		log_message(LOG_INFO, "%s(): PPPoE Instance %s back-in-business..."
				    , __FUNCTION__
				    , pppoe->name);
		__clear_bit(PPPOE_FL_FAULT_BIT, &pppoe->flags);
		goto end;
	}

	if (!__test_bit(PPPOE_FL_FAULT_BIT, &pppoe->flags) && (pppoe->expire < timer_long(time_now))) {
		log_message(LOG_INFO, "%s(): PPPoE Instance %s is out-of-order..."
				    , __FUNCTION__
				    , pppoe->name);
		__set_bit(PPPOE_FL_FAULT_BIT, &pppoe->flags);
	}

  end:
	thread_add_timer(master, pppoe_vrrp_timer_thread, pppoe, TIMER_HZ);
}

static void
pppoe_vrrp_read_thread(struct thread *thread)
{
	struct pppoe *pppoe = THREAD_ARG(thread);
	ssize_t len;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		goto end;

	len = read(pppoe->monitor_fd, pppoe->monitor_buffer, GTP_BUFFER_SIZE);
	if (len < 0) {
		log_message(LOG_INFO, "%s(): Error reading for vrrp monitor socket (%m)"
				    , __FUNCTION__);
		goto end;
	}

	/* update metrics */
	pppoe->vrrp_pkt_rx++;

	/* Update expiration */
	pppoe->expire = timer_long(time_now) + pppoe->credit;

  end:
	thread_add_read(master, pppoe_vrrp_read_thread
			      , pppoe, pppoe->monitor_fd, TIMER_HZ, 0);
}


/*
 *	BPF VRRP Filtering
 *
 * ASM Code :
 *	(000) ldh      [12]
 *	(001) jeq      #0x800           jt 2	jf 5
 *	(002) ldb      [23]
 *	(003) jeq      #0x70            jt 4	jf 5
 *	(004) ret      #262144
 *	(005) ret      #0
 */
static int
pppoe_monitor_vrrp_socket_init(struct pppoe *pppoe)
{
	int fd, err;
	struct sock_filter bpfcode[6] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 3, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 1, 0x00000070 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 }
	};
	struct sock_fprog bpf = {
		.len = ARRAY_SIZE(bpfcode),
		.filter = bpfcode
	};
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = pppoe->ifindex,
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
				    , pppoe->ifindex);
		close(fd);
		return -1;
	}

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
 *	PPPoE Monitoring
 */
int
pppoe_monitor_vrrp_init(struct pppoe *pppoe)
{
	pppoe->monitor_fd = pppoe_monitor_vrrp_socket_init(pppoe);
	if (pppoe->monitor_fd < 0) {
		log_message(LOG_INFO, "%s(): Error creating VRRP minitoring socket (%m)"
				    , __FUNCTION__);
		return -1;
	}

	log_message(LOG_INFO, "%s(): Activating VRRP monitoring for PPPoE instance:%s"
			    , __FUNCTION__
			    , pppoe->ifname);

	/* Scheduling submition */
	thread_add_read(master, pppoe_vrrp_read_thread
			      , pppoe, pppoe->monitor_fd, TIMER_HZ, 0);
	thread_add_timer(master, pppoe_vrrp_timer_thread, pppoe, pppoe->credit);
	return 0;
}

int
pppoe_monitor_vrrp_destroy(struct pppoe *pppoe)
{
	if (__test_bit(PPPOE_FL_VRRP_MONITOR_BIT, &pppoe->flags))
		close(pppoe->monitor_fd);
	return 0;
}
