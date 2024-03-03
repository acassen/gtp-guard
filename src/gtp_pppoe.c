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
gtp_pppoe_get(const unsigned int ifindex)
{
	gtp_pppoe_t *pppoe;

	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_for_each_entry(pppoe, &daemon_data->pppoe, next) {
		if (pppoe->ifindex == ifindex) {
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
 *	PPPoE Workers
 */
static int
gtp_pppoe_ingress(pkt_t *pkt, void *arg)
{
	struct ether_header *eh = (struct ether_header *) pkt->pbuff->head;
	gtp_pppoe_t *pppoe = arg;

	switch (ntohs(eh->ether_type)) {
	case ETH_P_PPP_DISC:
		pppoe_dispatch_disc_pkt(pppoe, pkt);
		break;
	case ETH_P_PPP_SES:
		pppoe_dispatch_session_pkt(pppoe, pkt);
		break;
	default:
		break;
	}

	pkt_queue_put(&pppoe->pkt_q, pkt);
	return 0;
}

static void *
gtp_pppoe_worker_task(void *arg)
{
	gtp_pppoe_worker_t *w = arg;
	gtp_pppoe_t *pppoe = w->pppoe;
	pkt_queue_t *q = &w->pkt_q;
	struct timeval tval;
	struct timespec timeout;
	char pname[128];

	/* Our identity */
	snprintf(pname, 127, "pppoe-%s-w-%d", pppoe->ifname, w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

  shoot_again:
	/* Schedule interruptible timeout */
	pthread_mutex_lock(&w->mutex);
	gettimeofday(&tval, NULL);
	timeout.tv_sec = tval.tv_sec + 60;
	timeout.tv_nsec = tval.tv_usec * 1000;
	pthread_cond_timedwait(&w->cond, &w->mutex, &timeout);
	pthread_mutex_unlock(&w->mutex);

	if (__test_bit(PPPOE_FL_STOPPING_BIT, &pppoe->flags))
		goto end;

	/* Queue processing */
	pkt_queue_run(q, gtp_pppoe_ingress, pppoe);

	goto shoot_again;

  end:
	return NULL;
}

static int
gtp_pppoe_worker_init(gtp_pppoe_t *pppoe, int id)
{
	pppoe->worker[id].pppoe = pppoe;
	pppoe->worker[id].id = id;
	pkt_queue_init(&pppoe->worker[id].pkt_q);
	pthread_mutex_init(&pppoe->worker[id].mutex, NULL);
	pthread_cond_init(&pppoe->worker[id].cond, NULL);

	pthread_create(&pppoe->worker[id].task, NULL, gtp_pppoe_worker_task, &pppoe->worker[id]);
	return 0;
}

static int
gtp_pppoe_worker_signal(gtp_pppoe_worker_t *w)
{
	pthread_mutex_lock(&w->mutex);
	pthread_cond_signal(&w->cond);
	pthread_mutex_unlock(&w->mutex);
	return 0;
}

static int
gtp_pppoe_worker_destroy(gtp_pppoe_t *pppoe)
{
	int i;

	for (i = 0; i < pppoe->thread_cnt; i++) {
		gtp_pppoe_worker_signal(&pppoe->worker[i]);
		pthread_join(pppoe->worker[i].task, NULL);
		pkt_queue_destroy(&pppoe->worker[i].pkt_q);
	}

	FREE(pppoe->worker);
	return 0;
}


/*
 *	PPPoE socket related
 */
static uint32_t
gtp_pppoe_rps_hash(struct ether_header *eth, uint32_t mask)
{
	uint8_t tmp[ETH_ALEN];
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		/* Good diversity enough only if host != broadcast, but this
		 * case is mostly for server side and we are client here...*/
		tmp[i] = eth->ether_shost[i] ^ eth->ether_dhost[i];
	return jhash_oaat(tmp, ETH_ALEN) & mask;
}

static void
gtp_pppoe_rps(gtp_pppoe_t *pppoe, pkt_t *pkt)
{
	struct ether_header *eth = (struct ether_header *) pkt->pbuff->head;
	uint32_t hkey = gtp_pppoe_rps_hash(eth, pppoe->thread_cnt - 1);

	pkt_queue_put(&pppoe->worker[hkey].pkt_q, pkt);
	gtp_pppoe_worker_signal(&pppoe->worker[hkey]);
}

static void
gtp_pppoe_read(thread_ref_t thread)
{
	gtp_pppoe_t *pppoe;
	thread_ref_t t;
	pkt_t *pkt = NULL;
	ssize_t nbytes;
	int fd;

	/* Fetch thread elements */
	pppoe = THREAD_ARG(thread);
	fd = THREAD_FD(thread);

	/* Terminate event */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		thread_add_terminate_event(thread->master);

	/* wait until next packet */
	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_read;

	pkt = pkt_queue_get(&pppoe->pkt_q);

	nbytes = pkt_recv(fd, pkt);
	if (nbytes < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto next_pkt;

		log_message(LOG_INFO, "%s(): Error recv on pppoe socket for interface %s (%m)"
				    , __FUNCTION__
				    , pppoe->ifname);
		goto next_pkt;
	}

	/* Receivce Packet Steering based upon ethernet header */
	gtp_pppoe_rps(pppoe, pkt);
	goto next_read;

  next_pkt:
	pkt_queue_put(&pppoe->pkt_q, pkt);
  next_read:
	t = thread_add_read(thread->master, gtp_pppoe_read, pppoe,
			    fd, GTP_PPPOE_RECV_TIMER, 0);
	if (fd == pppoe->fd_disc)
		pppoe->r_disc_thread = t;
	else
		pppoe->r_ses_thread = t;
}

static void *
gtp_pppoe_pkt_task(void *arg)
{
	gtp_pppoe_t *pppoe = arg;
	char pname[128];

	/* Create Process name */
	snprintf(pname, 127, "pppoe-%s", pppoe->ifname);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

	log_message(LOG_INFO, "%s(): Starting PPPoE on interface %s"
			    , __FUNCTION__, pppoe->ifname);

	/* I/O MUX init */
	pppoe->master = thread_make_master(true);

	/* Add socket event reader */
	pppoe->r_disc_thread = thread_add_read(pppoe->master, gtp_pppoe_read, pppoe,
					       pppoe->fd_disc, GTP_PPPOE_RECV_TIMER, 0);

	pppoe->r_ses_thread = thread_add_read(pppoe->master, gtp_pppoe_read, pppoe,
					      pppoe->fd_session, GTP_PPPOE_RECV_TIMER, 0);

	/* Inifinite loop */
	launch_thread_scheduler(pppoe->master);

	/* Release Master stuff */
	log_message(LOG_INFO, "%s(): Stopping PPPoE on interface %s", __FUNCTION__, pppoe->ifname);
	return NULL;
}

static int
gtp_pppoe_socket_init(gtp_pppoe_t *pppoe, uint16_t proto)
{
	struct sockaddr_ll sll;
	int fd, ret;

	/* PPPoE Discovery channel init */
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(proto);
	sll.sll_ifindex = if_nametoindex(pppoe->ifname);

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(proto));
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

	return fd;
}

static int
gtp_pppoe_pkt_init(gtp_pppoe_t *pppoe)
{
	pppoe->fd_disc = gtp_pppoe_socket_init(pppoe, ETH_P_PPP_DISC);
	if (pppoe->fd_disc < 0)
		return -1;

	pppoe->fd_session = gtp_pppoe_socket_init(pppoe, ETH_P_PPP_SES);
	if (pppoe->fd_session < 0)
		return -1;

	pthread_create(&pppoe->task, NULL, gtp_pppoe_pkt_task, pppoe);
	return 0;
}

/*
 *	PPPoE Timer related
 */
static int
gtp_pppoe_timer_init(gtp_pppoe_t *pppoe)
{
	char pname[128];

	snprintf(pname, 127, "pppoe-timer-%s", pppoe->ifname);
	timer_thread_init(&pppoe->session_timer, pname, pppoe_timeout);
	return 0;
}

static int
gtp_pppoe_timer_destroy(gtp_pppoe_t *pppoe)
{
	timer_thread_destroy(&pppoe->session_timer);
	return 0;
}

/*
 *	PPPoE service init
 */
int
gtp_pppoe_start(gtp_pppoe_t *pppoe)
{
	int ret, i;

	if (__test_bit(PPPOE_FL_RUNNING_BIT, &pppoe->flags))
		return -1;

	/* worker init */
	pppoe->worker = MALLOC(sizeof(gtp_pppoe_worker_t) * pppoe->thread_cnt);
	for (i = 0; i < pppoe->thread_cnt; i++)
		gtp_pppoe_worker_init(pppoe, i);

	/* ingress socket init */
	ret = gtp_pppoe_pkt_init(pppoe);
	if (ret < 0)
		return -1;

	__set_bit(PPPOE_FL_RUNNING_BIT, &pppoe->flags);
	return 0;
}

gtp_pppoe_t *
gtp_pppoe_init(const char *ifname)
{
	gtp_pppoe_t *pppoe = NULL;
	unsigned int ifindex = if_nametoindex(ifname);

	if (!ifindex)
		return NULL;

	pppoe = gtp_pppoe_get(ifindex);
	if (pppoe)
		return pppoe;

	PMALLOC(pppoe);
	srand(pppoe->seed);
	strlcpy(pppoe->ifname, ifname, GTP_NAME_MAX_LEN);
	pppoe->ifindex = ifindex;
	pkt_queue_init(&pppoe->pkt_q);
	gtp_htab_init(&pppoe->session_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&pppoe->unique_tab, CONN_HASHTAB_SIZE);
	gtp_pppoe_timer_init(pppoe);
	gtp_ppp_init(pppoe);
	gtp_pppoe_add(pppoe);

	return pppoe;
}

static int
__gtp_pppoe_release(gtp_pppoe_t *pppoe)
{
	__set_bit(PPPOE_FL_STOPPING_BIT, &pppoe->flags);
	pthread_join(pppoe->task, NULL);
	gtp_pppoe_timer_destroy(pppoe);
	gtp_pppoe_worker_destroy(pppoe);
	gtp_ppp_destroy(pppoe);
	close(pppoe->fd_disc);
	close(pppoe->fd_session);
	list_head_del(&pppoe->next);
	gtp_htab_destroy(&pppoe->session_tab);
	gtp_htab_destroy(&pppoe->unique_tab);
	pkt_queue_destroy(&pppoe->pkt_q);
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