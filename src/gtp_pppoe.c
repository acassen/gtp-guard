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
#include <net/if.h>
#include <linux/if_packet.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */
pthread_mutex_t gtp_pppoe_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 *	PPPoE utilities
 */
static gtp_pppoe_t *
gtp_pppoe_get(const char *ifname)
{
	gtp_pppoe_t *pppoe;

	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_for_each_entry(pppoe, &daemon_data->pppoe, next) {
		if (!strncmp(ifname, pppoe->ifname, strlen(ifname))) {
			pppoe->refcnt++;
			pthread_mutex_unlock(&gtp_pppoe_mutex);
			return pppoe;
		}
	}
	pthread_mutex_unlock(&gtp_pppoe_mutex);
	return NULL;
}

int
gtp_pppoe_put(gtp_pppoe_t *pppoe)
{
	pppoe->refcnt--;
	return 0;
}

static int
gtp_pppoe_add(gtp_pppoe_t *pppoe)
{
	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_add_tail(&pppoe->next, &daemon_data->pppoe);
	pthread_mutex_unlock(&gtp_pppoe_mutex);
	return 0;
}


/*
 *	Pkt queue related
 */
gtp_pppoe_pkt_t *
gtp_pppoe_pkt_get(list_head_t *q)
{
	gtp_pppoe_pkt_t *pkt;

	if (list_empty(q)) {
		PMALLOC(pkt);
		INIT_LIST_HEAD(&pkt->next);
		pkt->pbuff = pkt_buffer_alloc(GTP_BUFFER_SIZE);
		return pkt;
	}

	pkt = list_first_entry(q, gtp_pppoe_pkt_t, next);
	pkt_buffer_reset(pkt->pbuff);
	list_del_init(&pkt->next);
	return pkt;
}

int
gtp_pppoe_pkt_put(list_head_t *q, gtp_pppoe_pkt_t *pkt)
{
	if (!pkt)
		return -1;

	list_add_tail(&pkt->next, q);
	return 0;
}


/*
 *	PPPoE Workers
 */
static void *
gtp_pppoe_worker_task(void *arg)
{
	gtp_pppoe_worker_t *worker = arg;
	gtp_pppoe_t *pppoe = worker->pppoe;







	return NULL;
}

static int
gtp_pppoe_worker_init(gtp_pppoe_t *pppoe, int id)
{
	pppoe->worker[id].pppoe = pppoe;
	pppoe->worker[id].id = id;
	INIT_LIST_HEAD(&pppoe->worker[id].q);
	pthread_mutex_init(&pppoe->worker[id].q_mutex, NULL);
	pthread_mutex_init(&pppoe->worker[id].mutex, NULL);
	pthread_cond_init(&pppoe->worker[id].cond, NULL);

	pthread_create(&pppoe->worker[id].task, NULL, gtp_pppoe_worker_task, &pppoe->worker[id]);
	return 0;
}

static int
gtp_pppoe_worker_destroy(gtp_pppoe_t *pppoe)
{
	int i;

	for (i = 0; i < pppoe->thread_cnt; i++) {
		pthread_cancel(pppoe->worker[i].task);
		pthread_join(pppoe->worker[i].task, NULL);
	}

	FREE(pppoe->worker);
	return 0;
}

/*
 *	PPPoE socket related
 */
static ssize_t
gtp_pppoe_pkt_recv(int fd, pkt_buffer_t *pbuff)
{
	ssize_t nbytes;

	nbytes = recv(fd, pbuff->head, pkt_buffer_size(pbuff), 0);
	if (nbytes < 0)
		return -1;

	pkt_buffer_set_end_pointer(pbuff, nbytes);
	return nbytes;
}

static void
gtp_pppoe_discovery_read(thread_ref_t thread)
{
	gtp_pppoe_t *pppoe;
	gtp_pppoe_pkt_t *pkt = NULL;
	ssize_t nbytes;
	int fd;

	/* Fetch thread elements */
	pppoe = THREAD_ARG(thread);
	fd = THREAD_FD(thread);

	/* wait until next packet */
	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_read;

	pthread_mutex_lock(&pppoe->unuse_q_mutex);
	pkt = gtp_pppoe_pkt_get(&pppoe->unuse_q);
	pthread_mutex_unlock(&pppoe->unuse_q_mutex);

	nbytes = gtp_pppoe_pkt_recv(fd, pkt->pbuff);
	if (nbytes < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto next_read;

		log_message(LOG_INFO, "%s(): Error recv on pppoe socket for interface %s (%m)"
				    , __FUNCTION__
				    , pppoe->ifname);
		goto next_read;
	}



	printf("-----[ Incoming PPPoE packet ]-----\n");
	dump_buffer("", (char *) pkt->pbuff->head, pkt_buffer_len(pkt->pbuff));



  next_read:
	pthread_mutex_lock(&pppoe->unuse_q_mutex);
	gtp_pppoe_pkt_put(&pppoe->unuse_q, pkt);
	pthread_mutex_unlock(&pppoe->unuse_q_mutex);

	pppoe->r_thread = thread_add_read(thread->master, gtp_pppoe_discovery_read, pppoe,
					  fd, GTP_PPPOE_RECV_TIMER, 0);
}

static void *
gtp_pppoe_pkt_task(void *arg)
{
	gtp_pppoe_t *pppoe = arg;
	char pname[128];

	/* Create Process name */
	snprintf(pname, 127, "pppoe-%s", pppoe->ifname);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

	log_message(LOG_INFO, "%s(): Starting PPPoE on interface %s", __FUNCTION__, pppoe->ifname);

	/* I/O MUX init */
	pppoe->master = thread_make_master(true);

	/* Add socket event reader */
	pppoe->r_thread = thread_add_read(pppoe->master, gtp_pppoe_discovery_read, pppoe,
					  pppoe->fd_disc, GTP_PPPOE_RECV_TIMER, 0);

	/* Inifinite loop */
	launch_thread_scheduler(pppoe->master);

	/* Release Master stuff */
	log_message(LOG_INFO, "%s(): Stopping PPPoE on interface %s", __FUNCTION__, pppoe->ifname);
	return NULL;
}

static int
gtp_pppoe_pkt_init(gtp_pppoe_t *pppoe)
{
	struct sockaddr_ll sll;
	int fd, ret;

	/* PPPoE Discovery channel init */
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(ETH_PPPOE_DISCOVERY);
	sll.sll_ifindex = if_nametoindex(pppoe->ifname);

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_PPPOE_DISCOVERY));
	fd = if_setsockopt_broadcast(fd);
	fd = if_setsockopt_promisc(fd, sll.sll_ifindex, true);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): #%d : Error creating pppoe channel on interface %s (%m)"
				    , __FUNCTION__
				    , pppoe->ifname);
		return -1;
	}

	ret = bind(fd, (struct sockaddr *) &sll, sizeof(sll));
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): #%d : Error binding pppoe channel on interface %s (%m)"
				    , __FUNCTION__
				    , pppoe->ifname);
		close(fd);
		return -1;
	}

	pppoe->fd_disc = fd;

	pthread_create(&pppoe->task, NULL, gtp_pppoe_pkt_task, pppoe);
	return 0;
}


/*
 *	PPPoE service init
 */
int
gtp_pppoe_start(gtp_pppoe_t *pppoe)
{
	int ret, i;

	if (__test_bit(GTP_FL_RUNNING_BIT, &pppoe->flags))
		return -1;

	/* ingress socket init */
	ret = gtp_pppoe_pkt_init(pppoe);
	if (ret < 0)
		return -1;

	/* worker init */
	pppoe->worker = MALLOC(sizeof(gtp_pppoe_worker_t) * pppoe->thread_cnt);
	for (i = 0; i < pppoe->thread_cnt; i++)
		gtp_pppoe_worker_init(pppoe, i);

	__set_bit(GTP_FL_RUNNING_BIT, &pppoe->flags);
	return 0;
}

gtp_pppoe_t *
gtp_pppoe_init(const char *ifname)
{
	gtp_pppoe_t *pppoe = NULL;

	pppoe = gtp_pppoe_get(ifname);
	if (pppoe)
		return pppoe;

	PMALLOC(pppoe);
	INIT_LIST_HEAD(&pppoe->unuse_q);
	strlcpy(pppoe->ifname, ifname, GTP_NAME_MAX_LEN);
	pthread_mutex_init(&pppoe->unuse_q_mutex, NULL);
	gtp_pppoe_add(pppoe);

	return pppoe;
}

static int
__gtp_pppoe_release(gtp_pppoe_t *pppoe)
{
	pthread_cancel(pppoe->task);
	pthread_join(pppoe->task, NULL);
	close(pppoe->fd_disc);
	gtp_pppoe_worker_destroy(pppoe);
	list_head_del(&pppoe->next);
	FREE(pppoe);
	return 0;
}

int
gtp_pppoe_release(gtp_pppoe_t *pppoe)
{
	pthread_mutex_lock(&gtp_pppoe_mutex);
	__gtp_pppoe_release(pppoe);
	pthread_mutex_unlock(&gtp_pppoe_mutex);
	return 0;
}

int
gtp_pppoe_destroy(void)
{
	gtp_pppoe_t *pppoe, *_pppoe;

	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_for_each_entry_safe(pppoe, _pppoe, &daemon_data->pppoe, next)
		__gtp_pppoe_release(pppoe);
	pthread_mutex_unlock(&gtp_pppoe_mutex);

	return 0;
}