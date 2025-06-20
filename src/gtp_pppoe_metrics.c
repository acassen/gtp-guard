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


/*
 *	VRRP metrics
 */
static int
pppoe_vrrp_inuse(gtp_pppoe_t *pppoe, void *arg)
{
	bool *inuse = arg;

	if (__test_bit(PPPOE_FL_VRRP_MONITOR_BIT, &pppoe->flags) &&
	    __test_bit(PPPOE_FL_METRIC_VRRP_BIT, &pppoe->flags))
		*inuse = true;

	return 0;
}

static int
vrrp_metrics_tmpl_dump(gtp_pppoe_t *pppoe, void *arg)
{
	FILE *fp = arg;

	if (!__test_bit(PPPOE_FL_VRRP_MONITOR_BIT, &pppoe->flags) ||
	    !__test_bit(PPPOE_FL_METRIC_VRRP_BIT, &pppoe->flags))
		return -1;

	fprintf(fp, "gtpguard_vrrp_in_packet_total{interface=\"%s\"} %ld\n"
		  , pppoe->ifname, pppoe->vrrp_pkt_rx);
	return 0;
}

int
vrrp_metrics_dump(FILE *fp)
{
	bool inuse = false;

	gtp_pppoe_foreach(pppoe_vrrp_inuse, &inuse);
	if (!inuse)
		return -1;

	fprintf(fp, "#HELP gtpguard_vrrp_in_packet_total Count of received VRRP packets\n"
		    "#TYPE gtpguard_vrrp_in_packet_total counter\n");
	gtp_pppoe_foreach(vrrp_metrics_tmpl_dump, fp);
	return 0;
}

int
vrrp_metrics_reset(gtp_pppoe_t *pppoe)
{
	pppoe->vrrp_pkt_rx = 0;
	return 0;
}



/*
 *	PPPoE metrics
 */
int
pppoe_metric_update(gtp_pppoe_t *pppoe, int metric)
{
	if (!__test_bit(PPPOE_FL_METRIC_PPPOE_BIT, &pppoe->flags) ||
	    metric >= PPPOE_METRIC_MAX)
		return -1;

	pppoe->pppoe_metrics[PPPOE_METRIC_TOTAL]++;
	pppoe->pppoe_metrics[metric]++;
	return 0;
}

int
pppoe_metrics_reset(gtp_pppoe_t *pppoe)
{
	int i;

	for (i = 0; i < PPPOE_METRIC_MAX; i++)
		pppoe->pppoe_metrics[i] = 0;


	return 0;
}










/*
 *	PPP metrics
 */
int
ppp_metric_update(gtp_pppoe_t *pppoe, uint16_t protocol, int metric)
{
	ppp_metrics_t *metrics = &pppoe->ppp_metrics;

	if (!__test_bit(PPPOE_FL_METRIC_PPP_BIT, &pppoe->flags) ||
	    metric >= PPP_METRIC_MAX)
		return -1;

	switch (protocol) {
	case PPP_LCP:
		metrics->lcp[metric]++;
		break;
	case PPP_PAP:
		metrics->pap[metric]++;
		break;
	case PPP_IPCP:
		metrics->ipcp[metric]++;
		break;
	case PPP_IPV6CP:
		metrics->ipv6cp[metric]++;
		break;
	}

	return 0;
}

int
ppp_metric_update_total(gtp_pppoe_t *pppoe, uint16_t protocol)
{
	return ppp_metric_update(pppoe, protocol, PPP_METRIC_TOTAL);
}

int
ppp_metric_update_dropped(gtp_pppoe_t *pppoe)
{
	ppp_metrics_t *metrics = &pppoe->ppp_metrics;

	if (!__test_bit(PPPOE_FL_METRIC_PPP_BIT, &pppoe->flags))
		return -1;

	metrics->dropped++;
	return 0;
}

int
ppp_metrics_reset(gtp_pppoe_t *pppoe)
{
	ppp_metrics_t *metrics = &pppoe->ppp_metrics;
	memset(metrics, 0, sizeof(ppp_metrics_t));
	return 0;
}
