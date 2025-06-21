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
	fprintf(fp, "\n");
	return 0;
}

int
vrrp_metrics_reset(gtp_pppoe_t *pppoe)
{
	pppoe->vrrp_pkt_rx = 0;
	return 0;
}


/*
 *	PPP metrics
 */
int
ppp_metric_update(gtp_pppoe_t *pppoe, uint16_t protocol, int direction, int metric)
{
	ppp_metrics_t *metrics = pppoe->ppp_metrics;

	if (!metrics)
		return -1;

	if (!__test_bit(PPPOE_FL_METRIC_PPPOE_BIT, &pppoe->flags) ||
	    metric >= PPP_METRIC_MAX)
		return -1;

	switch (protocol) {
	case PPP_LCP:
		metrics->lcp[direction][metric]++;
		break;
	case PPP_PAP:
		metrics->pap[direction][metric]++;
		break;
	case PPP_IPCP:
		metrics->ipcp[direction][metric]++;
		break;
	case PPP_IPV6CP:
		metrics->ipv6cp[direction][metric]++;
		break;
	}

	return 0;
}

int
ppp_metric_update_total(gtp_pppoe_t *pppoe, uint16_t protocol, int direction)
{
	return ppp_metric_update(pppoe, protocol, direction, PPP_METRIC_TOTAL);
}

int
ppp_metric_update_dropped(gtp_pppoe_t *pppoe, int direction)
{
	if (!pppoe->ppp_metrics)
		return -1;

	if (!__test_bit(PPPOE_FL_METRIC_PPPOE_BIT, &pppoe->flags))
		return -1;

	pppoe->ppp_metrics->dropped[direction]++;
	return 0;
}

int
ppp_metrics_reset(gtp_pppoe_t *pppoe)
{
	if (pppoe->ppp_metrics)
		memset(pppoe->ppp_metrics, 0, sizeof(ppp_metrics_t));
	return 0;
}

static const char *ppp_metrics_name[PPP_METRIC_MAX] = {
	"total", "up", "down", "open", "close", "ack", "nak"
};

static int
ppp_metrics_var_dump(gtp_pppoe_t *pppoe, void *arg, const char *var, int direction)
{
	ppp_metrics_t *metrics = pppoe->ppp_metrics;
	FILE *fp = arg;
	int i;

	if (!metrics)
		return -1;

	fprintf(fp, "%s{interface=\"%s\",type=\"ppp-dropped\"} %ld\n"
			, var, pppoe->name
			, metrics->dropped[direction]);

	for (i = 0; i < PPP_METRIC_MAX; i++) {
		fprintf(fp, "%s{interface=\"%s\",type=\"%s-%s\"} %ld\n"
			  , var, pppoe->name
			  , "lcp", ppp_metrics_name[i]
			  , metrics->lcp[direction][i]);
		fprintf(fp, "%s{interface=\"%s\",type=\"%s-%s\"} %ld\n"
			  , var, pppoe->name
			  , "pap", ppp_metrics_name[i]
			  , metrics->pap[direction][i]);
		fprintf(fp, "%s{interface=\"%s\",type=\"%s-%s\"} %ld\n"
			  , var, pppoe->name
			  , "ipcp", ppp_metrics_name[i]
			  , metrics->ipcp[direction][i]);
		fprintf(fp, "%s{interface=\"%s\",type=\"%s-%s\"} %ld\n"
			  , var, pppoe->name
			  , "ipv6cp", ppp_metrics_name[i]
			  , metrics->ipv6cp[direction][i]);
	}

	return 0;
}


/*
 *	PPPoE metrics
 */
int
pppoe_metric_update(gtp_pppoe_t *pppoe, int dir, int metric)
{
	if (!pppoe->pppoe_metrics)
		return -1;

	if (!__test_bit(PPPOE_FL_METRIC_PPPOE_BIT, &pppoe->flags) ||
	    metric >= PPPOE_METRIC_MAX)
		return -1;

	pppoe->pppoe_metrics->m[dir][PPPOE_METRIC_TOTAL]++;
	pppoe->pppoe_metrics->m[dir][metric]++;
	return 0;
}

int
pppoe_metrics_reset(gtp_pppoe_t *pppoe)
{
	int i;

	if (!pppoe->pppoe_metrics)
		return -1;

	for (i = 0; i < PPPOE_METRIC_MAX; i++) {
		pppoe->pppoe_metrics->m[METRICS_DIR_IN][i] = 0;
		pppoe->pppoe_metrics->m[METRICS_DIR_OUT][i] = 0;
	}

	return 0;
}

static int
pppoe_metrics_inuse(gtp_pppoe_t *pppoe, void *arg)
{
	bool *inuse = arg;

	if (__test_bit(PPPOE_FL_METRIC_PPPOE_BIT, &pppoe->flags))
		*inuse = true;

	return 0;
}

static const char *pppoe_metrics_name[PPPOE_METRIC_MAX] = {
	"pppoe-total", "pppoe-dropped", "padi", "padr", "pado", "pads", "padt"
};

static int
pppoe_metrics_var_dump(gtp_pppoe_t *pppoe, void *arg, const char *var, int direction)
{
	FILE *fp = arg;
	int i;

	for (i = 0; i < PPPOE_METRIC_MAX; i++)
		fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %ld\n"
			  , var, pppoe->name
			  , pppoe_metrics_name[i]
			  , pppoe->pppoe_metrics->m[direction][i]);
	ppp_metrics_var_dump(pppoe, arg, var, direction);
	return 0;
}

static int
pppoe_metrics_tmpl_dump(FILE *fp, const char *var, const char *desc, const char *type,
			int direction)
{
	fprintf(fp, "#HELP %s %s\n#TYPE %s %s\n", var, desc, var, type);
	gtp_pppoe_metrics_foreach(pppoe_metrics_var_dump, fp, var, direction);
	fprintf(fp, "\n");
	return 0;
}

static const struct {
	const char	*var;
	const char	*description;
	const char	*type;
	__u8		direction;
} pppoe_metrics_set[] = {
	{ "gtpguard_pppoe_in_frame_total",
	  "Count of received PPPoE packets", "counter", METRICS_DIR_IN},
	{ "gtpguard_pppoe_out_frame_total",
	  "Count of transmitted PPPoE packets", "counter", METRICS_DIR_OUT},
	{ NULL, NULL, NULL, 0}
};

int
pppoe_metrics_dump(FILE *fp)
{
	bool inuse = false;
	int i;

	gtp_pppoe_foreach(pppoe_metrics_inuse, &inuse);
	if (!inuse)
		return -1;

	for (i = 0; pppoe_metrics_set[i].var; i++)
		pppoe_metrics_tmpl_dump(fp, pppoe_metrics_set[i].var
					  , pppoe_metrics_set[i].description
					  , pppoe_metrics_set[i].type
					  , pppoe_metrics_set[i].direction);
	return 0;
}


/*
 *	Alloc/destroy
 */
int
pppoe_metrics_alloc(gtp_pppoe_t *pppoe)
{
	pppoe_metrics_t *pppoe_m;
	ppp_metrics_t *ppp_m;

	PMALLOC(pppoe_m);
	if (!pppoe_m)
		return -1;

	PMALLOC(ppp_m);
	if (!ppp_m) {
		FREE(pppoe_m);
		return -1;
	}

	pppoe->pppoe_metrics = pppoe_m;
	pppoe->ppp_metrics = ppp_m;
	return 0;
}

int
pppoe_metrics_destroy(gtp_pppoe_t *pppoe)
{
	FREE_PTR(pppoe->ppp_metrics);
	FREE_PTR(pppoe->pppoe_metrics);
	return 0;
}
