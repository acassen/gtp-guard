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
#include <net/if.h>
#include <linux/if_packet.h>
#include <errno.h>
#include <libbpf.h>

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
gtp_htab_t *
gtp_pppoe_get_session_tab(gtp_pppoe_t *pppoe)
{
	return (pppoe->bundle) ? &pppoe->bundle->pppoe[0]->session_tab :
				 &pppoe->session_tab;
}

gtp_htab_t *
gtp_pppoe_get_unique_tab(gtp_pppoe_t *pppoe)
{
	return (pppoe->bundle) ? &pppoe->bundle->pppoe[0]->unique_tab :
				 &pppoe->unique_tab;
}

timer_thread_t *
gtp_pppoe_get_session_timer(gtp_pppoe_t *pppoe)
{
	return (pppoe->bundle) ? &pppoe->bundle->pppoe[0]->session_timer :
				 &pppoe->session_timer;
}

timer_thread_t *
gtp_pppoe_get_ppp_timer(gtp_pppoe_t *pppoe)
{
	return (pppoe->bundle) ? &pppoe->bundle->pppoe[0]->ppp_timer :
				 &pppoe->ppp_timer;
}

gtp_pppoe_t *
gtp_pppoe_get_by_name(const char *name)
{
	gtp_pppoe_t *pppoe;

	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_for_each_entry(pppoe, &daemon_data->pppoe, next) {
		if (!strncmp(pppoe->name, name, GTP_NAME_MAX_LEN)) {
			pppoe->refcnt++;
			pthread_mutex_unlock(&gtp_pppoe_mutex);
			return pppoe;
		}
	}
	pthread_mutex_unlock(&gtp_pppoe_mutex);
	return NULL;
}

gtp_pppoe_bundle_t *
gtp_pppoe_bundle_get_by_name(const char *name)
{
	gtp_pppoe_bundle_t *bundle;

	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_for_each_entry(bundle, &daemon_data->pppoe_bundle, next) {
		if (!strncmp(bundle->name, name, GTP_NAME_MAX_LEN)) {
			pthread_mutex_unlock(&gtp_pppoe_mutex);
			return bundle;
		}
	}
	pthread_mutex_unlock(&gtp_pppoe_mutex);
	return NULL;
}

static gtp_pppoe_t *
gtp_pppoe_get_by_ifindex(const unsigned int ifindex)
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

static int
gtp_pppoe_bundle_add(gtp_pppoe_bundle_t *bundle)
{
	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_add_tail(&bundle->next, &daemon_data->pppoe_bundle);
	pthread_mutex_unlock(&gtp_pppoe_mutex);
	return 0;
}


/*
 *	Receive Packet Steering eBPF related
 */
static struct bpf_object *
bpf_rps_filter_init(gtp_pppoe_worker_t *w, int fd, const char *filename)
{
	gtp_pppoe_t *pppoe = w->pppoe;
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog;
	struct bpf_map *bpf_map;
	struct rps_opts opts;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err, key = 0;

	bpf_obj = bpf_object__open(filename);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error opening bpf file err:%d (%s)\n"
				    , errno, errmsg);
		return NULL;
	}

	bpf_prog = bpf_object__next_program(bpf_obj, NULL);
	if (!bpf_prog) {
		log_message(LOG_INFO, "eBPF: no program found in file:%s\n", filename);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	err = bpf_object__load(bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error loading bpf_object err:%d (%s)\n"
				    , err, errmsg);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	bpf_map = bpf_object__find_map_by_name(bpf_obj, "socket_filter_opts");
	if (!bpf_map) {
		log_message(LOG_INFO, "eBPF: error mapping:%s\n"
				    , "socket_filter_ops");
		bpf_object__close(bpf_obj);
		return NULL;
	}

	err = if_setsockopt_attach_bpf(fd, bpf_program__fd(bpf_prog));
	if (err < 0) {
		bpf_object__close(bpf_obj);
		return NULL;
	}

	/* Initialize socket filter option */
	memset(&opts, 0, sizeof(struct rps_opts));
	opts.id = w->id;
	opts.max_id = pppoe->thread_cnt;
	err = bpf_map__update_elem(bpf_map, &key, sizeof(int)
					  , &opts, sizeof(struct rps_opts)
					  , BPF_ANY);
	if (err) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error setting option in map:%s (%s)\n"
				    , "socket_filter_ops", errmsg);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	return bpf_obj;
}

/*
 *	PPPoE Workers
 */
static void
gtp_pppoe_update_rx_stats(gtp_pppoe_worker_t *w, pkt_t *pkt)
{
	w->rx_packets++;
	w->rx_bytes += pkt_buffer_len(pkt->pbuff);
}

static void
gtp_pppoe_update_tx_stats(gtp_pppoe_worker_t *w, pkt_t *pkt)
{
	w->tx_packets++;
	w->tx_bytes += pkt_buffer_len(pkt->pbuff);
}

static int
gtp_pppoe_send(gtp_pppoe_t *pppoe, gtp_pppoe_worker_t *w, pkt_t *pkt)
{
	gtp_pppoe_update_tx_stats(w, pkt);
	return pkt_send(w->fd, &pppoe->pkt_q, pkt);
}

int
gtp_pppoe_disc_send(gtp_pppoe_t *pppoe, pkt_t *pkt)
{
	struct ether_header *eh;
	uint32_t hkey;

	eh = (struct ether_header *) pkt->pbuff->head;
	hkey = eh->ether_shost[ETH_ALEN - 2] & (pppoe->thread_cnt - 1);

	return gtp_pppoe_send(pppoe, &pppoe->worker_disc[hkey], pkt);
}

int
gtp_pppoe_ses_send(gtp_pppoe_t *pppoe, pkt_t *pkt)
{
	struct ether_header *eh;
	uint32_t hkey;

	eh = (struct ether_header *) pkt->pbuff->head;
	hkey = eh->ether_shost[ETH_ALEN - 2] & (pppoe->thread_cnt - 1);

	return gtp_pppoe_send(pppoe, &pppoe->worker_ses[hkey], pkt);
}

static void
gtp_pppoe_ingress(pkt_t *pkt, void *arg)
{
	struct ether_header *eh = (struct ether_header *) pkt->pbuff->head;
	gtp_pppoe_worker_t *w = arg;
	gtp_pppoe_t *pppoe = w->pppoe;

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

	gtp_pppoe_update_rx_stats(w, pkt);
}

static int
gtp_pppoe_socket_init(gtp_pppoe_t *pppoe, uint16_t proto, int id)
{
	struct sockaddr_ll sll;
	int fd, ret;

	/* PPPoE Discovery channel init */
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(proto);
	sll.sll_ifindex = if_nametoindex(pppoe->ifname);

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(proto));
	fd = if_setsockopt_broadcast(fd);
	fd = if_setsockopt_promisc(fd, sll.sll_ifindex, true);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): #%d : Error creating pppoe channel on interface %s (%m)"
				    , __FUNCTION__, id
				    , pppoe->ifname);
		return -1;
	}

	ret = bind(fd, (struct sockaddr *) &sll, sizeof(sll));
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): #%d : Error binding pppoe channel on interface %s (%m)"
				    , __FUNCTION__, id
				    , pppoe->ifname);
		close(fd);
		return -1;
	}

	return fd;
}

static void *
gtp_pppoe_worker_task(void *arg)
{
	gtp_pppoe_worker_t *w = arg;
	gtp_pppoe_t *pppoe = w->pppoe;
	struct bpf_object *bpf_obj = NULL;
	gtp_bpf_opts_t *bpf_opts = &daemon_data->bpf_ppp_rps;
	char pname[128];
	int ret;

	/* Our identity */
	snprintf(pname, 127, "pppoe-%s-w-%s-%d"
		      , pppoe->ifname
		      , (w->proto == ETH_P_PPP_DISC) ? "d" : "s"
		      , w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

	/* Socket init */
	w->fd = gtp_pppoe_socket_init(pppoe, w->proto, w->id);
	if (w->fd < 0)
		return NULL;

	/* RPS Init */
	if (__test_bit(GTP_FL_PPP_RPS_LOADED_BIT, &daemon_data->flags)) {
		bpf_obj = bpf_rps_filter_init(w, w->fd, bpf_opts->filename);
		if (!bpf_obj)
			goto end;
	}

	signal_noignore_sig(SIGUSR1);

	/* Set Cancellation before a blocking syscall such as recvmmsg() */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	log_message(LOG_INFO, "%s(): Starting PPPoE Worker %s"
			    , __FUNCTION__, pname);

  shoot_again:
	if (__test_bit(PPPOE_FL_STOPPING_BIT, &pppoe->flags))
		goto end;

	ret = mpkt_recv(w->fd, &w->mpkt);
	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
			mpkt_reset(&w->mpkt);
			goto shoot_again;
		}

		log_message(LOG_INFO, "%s(): Error recv on pppoe socket for interface %s (%m)"
				    , __FUNCTION__
				    , pppoe->ifname);
		mpkt_reset(&w->mpkt);
		usleep(100000); /* 100ms delay before retry */
		goto shoot_again;
	}

	/* mpkt processing */
	mpkt_process(&w->mpkt, ret, gtp_pppoe_ingress, w);
	mpkt_reset(&w->mpkt);
	goto shoot_again;

  end:
	log_message(LOG_INFO, "%s(): Stopping PPPoE Worker %s"
			    , __FUNCTION__, pname);
	if (bpf_obj)
		bpf_object__close(bpf_obj);
	close(w->fd);
	return NULL;
}

static int
gtp_pppoe_worker_init(gtp_pppoe_t *pppoe, gtp_pppoe_worker_t *w, int id, uint16_t proto)
{
	int ret;

	w->pppoe = pppoe;
	w->id = id;
	w->proto = proto;

	/* Packet queue Init */
	pkt_queue_init(&w->pkt_q);
	ret = mpkt_init(&w->mpkt, PPPOE_MPKT);
	ret = (ret) ? : __pkt_queue_mget(&w->pkt_q, &w->mpkt);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error creating mpkt for Worker %d/%d"
				    , __FUNCTION__, proto, id);
		return -1;
	}

	pthread_create(&w->task, NULL, gtp_pppoe_worker_task, w);
	return 0;
}

static void
gtp_pppoe_worker_release(gtp_pppoe_worker_t *w)
{
	if (!w->task)
		return;
	
	pthread_kill(w->task, SIGUSR1);
	sched_yield(); /* yield to handle the SIGUSR1 */
	pthread_cancel(w->task); /* stop all the blocking syscalls, recvmmsg() */
	pthread_join(w->task, NULL);
	mpkt_destroy(&w->mpkt);
	pkt_queue_destroy(&w->pkt_q);
}

static int
gtp_pppoe_worker_destroy(gtp_pppoe_t *pppoe)
{
	int i;

	for (i = 0; i < pppoe->thread_cnt; i++) {
		gtp_pppoe_worker_release(&pppoe->worker_disc[i]);
		gtp_pppoe_worker_release(&pppoe->worker_ses[i]);
	}

	FREE(pppoe->worker_disc);
	FREE(pppoe->worker_ses);
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
	int i;

	if (__test_bit(PPPOE_FL_RUNNING_BIT, &pppoe->flags))
		return -1;

	log_message(LOG_INFO, "%s(): Starting PPPoE on interface %s"
			    , __FUNCTION__, pppoe->ifname);

	/* worker init */
	pppoe->worker_disc = MALLOC(sizeof(gtp_pppoe_worker_t) * pppoe->thread_cnt);
	for (i = 0; i < pppoe->thread_cnt; i++)
		gtp_pppoe_worker_init(pppoe, &pppoe->worker_disc[i], i, ETH_P_PPP_DISC);

	pppoe->worker_ses = MALLOC(sizeof(gtp_pppoe_worker_t) * pppoe->thread_cnt);
	for (i = 0; i < pppoe->thread_cnt; i++)
		gtp_pppoe_worker_init(pppoe, &pppoe->worker_ses[i], i, ETH_P_PPP_SES);

	__set_bit(PPPOE_FL_RUNNING_BIT, &pppoe->flags);
	return 0;
}

int
gtp_pppoe_interface_init(gtp_pppoe_t *pppoe, const char *ifname)
{
	unsigned int ifindex = if_nametoindex(ifname);

	if (!ifindex) {
		errno = EINVAL;
		return -1;
	}

	if (gtp_pppoe_get_by_ifindex(ifindex)) {
		errno = EEXIST;
		return -1;
	}

	strlcpy(pppoe->ifname, ifname, GTP_NAME_MAX_LEN);
	pppoe->ifindex = ifindex;
	return 0;
}

gtp_pppoe_t *
gtp_pppoe_init(const char *name)
{
	gtp_pppoe_t *pppoe = NULL;

	pppoe = gtp_pppoe_get_by_name(name);
	if (pppoe) {
		errno = EEXIST;
		return NULL;
	}

	PMALLOC(pppoe);
	if (!pppoe) {
		errno = ENOMEM;
		return NULL;
	}
	strlcpy(pppoe->name, name, GTP_NAME_MAX_LEN);
	INIT_LIST_HEAD(&pppoe->next);
	pppoe->seed = time(NULL);
	srand(pppoe->seed);
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
	list_head_del(&pppoe->next);
	spppoe_sessions_destroy(&pppoe->session_tab);
	gtp_htab_destroy(&pppoe->session_tab);
	gtp_htab_destroy(&pppoe->unique_tab);
	pkt_queue_destroy(&pppoe->pkt_q);
	gtp_pppoe_monitor_vrrp_destroy(pppoe);
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


/*
 *	PPPoE Bundle init
 */
gtp_pppoe_bundle_t *
gtp_pppoe_bundle_init(const char *name)
{
	gtp_pppoe_bundle_t *bundle = NULL;

	bundle = gtp_pppoe_bundle_get_by_name(name);
	if (bundle) {
		errno = EEXIST;
		return NULL;
	}

	PMALLOC(bundle);
	if (!bundle) {
		errno = ENOMEM;
		return NULL;
	}
	strlcpy(bundle->name, name, GTP_NAME_MAX_LEN);
	INIT_LIST_HEAD(&bundle->next);
	bundle->pppoe = MALLOC(sizeof(gtp_pppoe_t) * PPPOE_BUNDLE_MAXSIZE);

	gtp_pppoe_bundle_add(bundle);

	return bundle;
}

gtp_pppoe_t *
gtp_pppoe_bundle_get_active_instance(gtp_pppoe_bundle_t *bundle)
{
	gtp_pppoe_t *pppoe;
	int i;

	/* try match primary !fault instance */
	for (i = 0; i < PPPOE_BUNDLE_MAXSIZE && bundle->pppoe[i]; i++) {
		pppoe = bundle->pppoe[i];
		if (__test_bit(PPPOE_FL_PRIMARY_BIT, &pppoe->flags) &&
		    !__test_bit(PPPOE_FL_FAULT_BIT, &pppoe->flags)) {
			return pppoe;
		}
	}

	/* No match, fallback to the first secondary !fault instance */
	for (i = 0; i < PPPOE_BUNDLE_MAXSIZE && bundle->pppoe[i]; i++) {
		pppoe = bundle->pppoe[i];
		if (__test_bit(PPPOE_FL_SECONDARY_BIT, &pppoe->flags) &&
		    !__test_bit(PPPOE_FL_FAULT_BIT, &pppoe->flags)) {
			return pppoe;
		    }
	}

	return NULL;
}

int
__gtp_pppoe_bundle_release(gtp_pppoe_bundle_t *bundle)
{
	list_head_del(&bundle->next);
	FREE(bundle->pppoe);
	return 0;
}

int
gtp_pppoe_bundle_release(gtp_pppoe_bundle_t *bundle)
{
	pthread_mutex_lock(&gtp_pppoe_mutex);
	__gtp_pppoe_bundle_release(bundle);
	pthread_mutex_unlock(&gtp_pppoe_mutex);
	return 0;
}

int
gtp_pppoe_bundle_destroy(void)
{
	gtp_pppoe_bundle_t *bundle, *_bundle;

	pthread_mutex_lock(&gtp_pppoe_mutex);
	list_for_each_entry_safe(bundle, _bundle, &daemon_data->pppoe_bundle, next)
		__gtp_pppoe_bundle_release(bundle);
	pthread_mutex_unlock(&gtp_pppoe_mutex);

	return 0;
}
