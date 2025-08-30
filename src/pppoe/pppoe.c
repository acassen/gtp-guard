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
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/prctl.h>
#include <net/if.h>
#include "ppp.h"
#include "pppoe_proto.h"
#include "pppoe_monitor.h"
#include "inet_utils.h"
#include "logger.h"
#include "bitops.h"
#include "utils.h"
#include "memory.h"
#include "gtp_data.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	PPPoE utilities
 */
void
pppoe_metrics_foreach(int (*hdl) (pppoe_t *, void *, const char *, int),
				      void *arg, const char *var, int direction)
{
	list_head_t *l = &daemon_data->pppoe;
	pppoe_t *pppoe;

	list_for_each_entry(pppoe, l, next)
		(*(hdl)) (pppoe, arg, var, direction);
}

void
pppoe_foreach(int (*hdl) (pppoe_t *, void *), void *arg)
{
	list_head_t *l = &daemon_data->pppoe;
	pppoe_t *pppoe;

	list_for_each_entry(pppoe, l, next)
		(*(hdl)) (pppoe, arg);
}

pppoe_t *
pppoe_get_by_name(const char *name)
{
	pppoe_t *pppoe;

	list_for_each_entry(pppoe, &daemon_data->pppoe, next) {
		if (!strncmp(pppoe->name, name, GTP_NAME_MAX_LEN)) {
			pppoe->refcnt++;
			return pppoe;
		}
	}
	return NULL;
}

pppoe_bundle_t *
pppoe_bundle_get_by_name(const char *name)
{
	pppoe_bundle_t *bundle;

	list_for_each_entry(bundle, &daemon_data->pppoe_bundle, next) {
		if (!strncmp(bundle->name, name, GTP_NAME_MAX_LEN)) {
			return bundle;
		}
	}
	return NULL;
}

static pppoe_t *
pppoe_get_by_ifindex(const unsigned int ifindex)
{
	pppoe_t *pppoe;

	list_for_each_entry(pppoe, &daemon_data->pppoe, next) {
		if (pppoe->ifindex == ifindex) {
			pppoe->refcnt++;
			return pppoe;
		}
	}
	return NULL;
}

int
pppoe_put(pppoe_t *pppoe)
{
	pppoe->refcnt--;
	return 0;
}

static int
pppoe_add(pppoe_t *pppoe)
{
	list_add_tail(&pppoe->next, &daemon_data->pppoe);
	return 0;
}

static int
pppoe_bundle_add(pppoe_bundle_t *bundle)
{
	list_add_tail(&bundle->next, &daemon_data->pppoe_bundle);
	return 0;
}


/*
 *	PPPoE Workers
 */
static int
pppoe_send(pppoe_t *pppoe, pppoe_channel_t *ch, pkt_t *pkt)
{
	gtp_metrics_pkt_update(&ch->tx_metrics, pkt_buffer_len(pkt->pbuff));

	return pkt_send(ch->fd, &pppoe->pkt_q, pkt);
}

int
pppoe_disc_send(pppoe_t *pppoe, pkt_t *pkt)
{
	return pppoe_send(pppoe, &pppoe->channel_disc, pkt);
}

int
pppoe_ses_send(pppoe_t *pppoe, pkt_t *pkt)
{
	return pppoe_send(pppoe, &pppoe->channel_ses, pkt);
}

static void
pppoe_ingress(pkt_t *pkt, void *arg)
{
	struct ether_header *eh = (struct ether_header *) pkt->pbuff->head;
	pppoe_channel_t *ch = arg;
	pppoe_t *pppoe = ch->pppoe;

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

	gtp_metrics_pkt_update(&ch->rx_metrics, pkt_buffer_len(pkt->pbuff));
}

static int
pppoe_socket_init(pppoe_channel_t *ch, uint16_t proto)
{
	pppoe_t *pppoe = ch->pppoe;
	struct sockaddr_ll sll;
	int fd, err;

	/* PPPoE Discovery channel init */
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(proto);
	sll.sll_ifindex = if_nametoindex(pppoe->ifname);

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(proto));
	err = inet_setsockopt_broadcast(fd);
	err = (err) ? : inet_setsockopt_promisc(fd, sll.sll_ifindex, true);
	if (err) {
		log_message(LOG_INFO, "%s(): Error creating pppoe channel on interface %s (%m)"
				    , __FUNCTION__
				    , pppoe->ifname);
		close(fd);
		return -1;
	}

	err = bind(fd, (struct sockaddr *) &sll, sizeof(sll));
	if (err) {
		log_message(LOG_INFO, "%s(): Error binding pppoe channel on interface %s (%m)"
				    , __FUNCTION__
				    , pppoe->ifname);
		close(fd);
		return -1;
	}

	ch->fd = fd;
	return 0;
}

static void
pppoe_async_recv_thread(thread_t *thread)
{
	pppoe_channel_t *ch = THREAD_ARG(thread);
	pppoe_t *pppoe = ch->pppoe;
	int ret;

	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_read;

	ret = mpkt_recv(ch->fd, &ch->mpkt);
	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
			mpkt_reset(&ch->mpkt);
			goto next_read;
		}

		log_message(LOG_INFO, "%s(): Error recv on PPPoE %s socket for interface %s (%m)"
				    , __FUNCTION__
				    , (ch->proto == ETH_P_PPP_DISC) ? "Discovery" : "Session"
				    , pppoe->ifname);
		mpkt_reset(&ch->mpkt);
		goto next_read;
	}

	/* mpkt processing */
	mpkt_process(&ch->mpkt, ret, pppoe_ingress, ch);
	mpkt_reset(&ch->mpkt);

  next_read:
	ch->r_thread = thread_add_read(master, pppoe_async_recv_thread
					     , ch, ch->fd, 3*TIMER_HZ, 0);
}

static int
pppoe_channel_init(pppoe_t *pppoe, pppoe_channel_t *ch, uint16_t proto)
{
	int err;

	ch->pppoe = pppoe;
	ch->proto = proto;

	/* Packet queue Init */
	pkt_queue_init(&ch->pkt_q);
	err = mpkt_init(&ch->mpkt, PPPOE_MPKT);
	err = (err) ? : __pkt_queue_mget(&ch->pkt_q, &ch->mpkt);
	err = (err) ? : pppoe_socket_init(ch, proto);
	if (err) {
		log_message(LOG_INFO, "%s(): Error creating PPPoE %s channel on interface %s"
				    , __FUNCTION__
				    , (proto == ETH_P_PPP_DISC) ? "Discovery" : "Session"
				    , pppoe->ifname);
		return -1;
	}

	log_message(LOG_INFO, "%s(): Starting PPPoE %s channel on interface %s"
			    , __FUNCTION__
			    , (proto == ETH_P_PPP_DISC) ? "Discovery" : "Session"
			    , pppoe->ifname);
	ch->r_thread = thread_add_read(master, pppoe_async_recv_thread
					     , ch, ch->fd, 3*TIMER_HZ, 0);
	return 0;
}

static void
pppoe_channel_release(pppoe_channel_t *ch)
{
	mpkt_destroy(&ch->mpkt);
	pkt_queue_destroy(&ch->pkt_q);
	close(ch->fd);
}

static int
pppoe_channel_destroy(pppoe_t *pppoe)
{
	if (!__test_bit(PPPOE_FL_RUNNING_BIT, &pppoe->flags))
		return -1;

	pppoe_channel_release(&pppoe->channel_disc);
	pppoe_channel_release(&pppoe->channel_ses);
	return 0;
}


/*
 *	PPPoE service init
 */
int
pppoe_start(pppoe_t *pppoe)
{
	if (__test_bit(PPPOE_FL_RUNNING_BIT, &pppoe->flags))
		return -1;

	/* Channel init */
	pppoe_channel_init(pppoe, &pppoe->channel_disc, ETH_P_PPP_DISC);
	pppoe_channel_init(pppoe, &pppoe->channel_ses, ETH_P_PPP_SES);

	__set_bit(PPPOE_FL_RUNNING_BIT, &pppoe->flags);
	return 0;
}

int
pppoe_interface_init(pppoe_t *pppoe, const char *ifname)
{
	unsigned int ifindex = if_nametoindex(ifname);

	if (!ifindex) {
		errno = EINVAL;
		return -1;
	}

	if (pppoe_get_by_ifindex(ifindex)) {
		errno = EEXIST;
		return -1;
	}

	bsd_strlcpy(pppoe->ifname, ifname, GTP_NAME_MAX_LEN);
	pppoe->ifindex = ifindex;
	return 0;
}

pppoe_t *
pppoe_alloc(const char *name)
{
	pppoe_t *new = NULL;

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
	bsd_strlcpy(new->name, name, GTP_NAME_MAX_LEN);
	INIT_LIST_HEAD(&new->next);
	new->seed = time(NULL);
	srand(new->seed);
	pkt_queue_init(&new->pkt_q);
	ppp_set_default(new);
	pppoe_add(new);

	return new;
}

int
pppoe_release(pppoe_t *pppoe)
{
	__set_bit(PPPOE_FL_STOPPING_BIT, &pppoe->flags);
	pppoe_channel_destroy(pppoe);
	list_head_del(&pppoe->next);
	pkt_queue_destroy(&pppoe->pkt_q);
	pppoe_monitor_vrrp_destroy(pppoe);
	pppoe_metrics_destroy(pppoe);
	FREE(pppoe);
	return 0;
}

int
pppoe_init(void)
{
	spppoe_tracking_init();
	pppoe_proto_init();
	ppp_init();
	return 0;
}

int
pppoe_destroy(void)
{
	pppoe_t *pppoe, *_pppoe;

	ppp_destroy();
	pppoe_proto_destroy();
	spppoe_tracking_destroy();
	list_for_each_entry_safe(pppoe, _pppoe, &daemon_data->pppoe, next)
		pppoe_release(pppoe);
	return 0;
}


/*
 *	PPPoE Bundle init
 */
pppoe_bundle_t *
pppoe_bundle_init(const char *name)
{
	pppoe_bundle_t *bundle = NULL;

	bundle = pppoe_bundle_get_by_name(name);
	if (bundle) {
		errno = EEXIST;
		return NULL;
	}

	PMALLOC(bundle);
	if (!bundle) {
		errno = ENOMEM;
		return NULL;
	}
	bsd_strlcpy(bundle->name, name, GTP_NAME_MAX_LEN);
	INIT_LIST_HEAD(&bundle->next);
	bundle->pppoe = MALLOC(sizeof(pppoe_t) * PPPOE_BUNDLE_MAXSIZE);

	pppoe_bundle_add(bundle);

	return bundle;
}

pppoe_t *
pppoe_bundle_get_active_instance(pppoe_bundle_t *bundle)
{
	pppoe_t *pppoe;
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
pppoe_bundle_release(pppoe_bundle_t *bundle)
{
	list_head_del(&bundle->next);
	FREE(bundle->pppoe);
	return 0;
}

int
pppoe_bundle_destroy(void)
{
	pppoe_bundle_t *bundle, *_bundle;

	list_for_each_entry_safe(bundle, _bundle, &daemon_data->pppoe_bundle, next)
		pppoe_bundle_release(bundle);

	return 0;
}
