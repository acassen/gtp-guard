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

#include "gtp_router.h"
#include "gtp_server.h"
#include "gtp_utils.h"
#include "gtp.h"
#include "bitops.h"


/*
 *	Metrics
 */
static int
gtp_router_server_rx_dump(gtp_router_t *r, void *arg)
{
	gtp_server_t *srv = &r->gtpc;
	gtp_router_t *ctx = srv->ctx;
	const char *var = "gtpguard_gtpc_in_packet_total";
	FILE *fp = arg;
	int i, type = -1;

	/* Can only be GTP-C OR GTP-U */
	if (__test_bit(GTP_FL_CTL_BIT, &srv->flags))
		type = GTP_FL_CTL_BIT;
	else if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
		type = GTP_FL_UPF_BIT;

	fprintf(fp, "%s{interface=\"%s\"} %ld\n"
		  , var, ctx->name, srv->s.rx_pkts);

	for (i = 0; i < GTP_METRIC_MAX_MSG; i++) {
		if (srv->msg_metrics.rx[i].count)
			fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %d\n"
				  , var, ctx->name
		  		  , gtp_msgtype2str(type, i)
				  , srv->msg_metrics.rx[i].count);
		if (srv->msg_metrics.rx[i].unsupported)
			fprintf(fp, "%s{interface=\"%s\",type=\"%s-unsupported\"} %d\n"
				  , var, ctx->name
		  		  , gtp_msgtype2str(type, i)
				  , srv->msg_metrics.rx[i].unsupported);
		if (srv->cause_rx_metrics.cause[i])
			fprintf(fp, "%s{interface=\"%s\",cause=\"%s\"} %d\n"
				  , var, ctx->name
		  		  , gtpc_cause2str(i)
				  , srv->cause_rx_metrics.cause[i]);
	}

	return 0;
}

static int
gtp_router_server_tx_dump(gtp_router_t *r, void *arg)
{
	gtp_server_t *srv = &r->gtpc;
	gtp_router_t *ctx = srv->ctx;
	const char *var = "gtpguard_gtpc_out_packet_total";
	FILE *fp = arg;
	int i, type = -1;

	/* Can only be GTP-C OR GTP-U */
	if (__test_bit(GTP_FL_CTL_BIT, &srv->flags))
		type = GTP_FL_CTL_BIT;
	else if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
		type = GTP_FL_UPF_BIT;

	fprintf(fp, "%s{interface=\"%s\"} %ld\n"
		  , var, ctx->name, srv->s.tx_pkts);

	for (i = 0; i < GTP_METRIC_MAX_MSG; i++) {
		if (srv->msg_metrics.tx[i].count)
			fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %d\n"
				  , var, ctx->name
		  		  , gtp_msgtype2str(type, i)
				  , srv->msg_metrics.tx[i].count);
		if (srv->msg_metrics.tx[i].unsupported)
			fprintf(fp, "%s{interface=\"%s\",type=\"%s-unsupported\"} %d\n"
				  , var, ctx->name
		  		  , gtp_msgtype2str(type, i)
				  , srv->msg_metrics.tx[i].unsupported);
		if (srv->cause_tx_metrics.cause[i])
			fprintf(fp, "%s{interface=\"%s\",cause=\"%s\"} %d\n"
				  , var, ctx->name
		  		  , gtpc_cause2str(i)
				  , srv->cause_tx_metrics.cause[i]);
	}

	return 0;
}

int
gtp_router_metrics_dump(FILE *fp)
{
	const char *var_rx = "gtpguard_gtpc_in_packet_total";
	const char *var_tx = "gtpguard_gtpc_out_packet_total";

	if (!gtp_router_inuse())
		return -1;

	fprintf(fp, "# HELP %s Count of received GTP-C packets\n"
		    "# TYPE %s counter\n", var_rx, var_rx);
	gtp_router_foreach(gtp_router_server_rx_dump, fp);
	fprintf(fp, "\n");

	fprintf(fp, "# HELP %s Count of transmitted GTP-C packets\n"
		    "# TYPE %s counter\n", var_tx, var_tx);
	gtp_router_foreach(gtp_router_server_tx_dump, fp);
	fprintf(fp, "\n");
	return 0;
}
