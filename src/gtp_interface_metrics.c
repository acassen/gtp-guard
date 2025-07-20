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

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	Interface metrics
 *
 * We are supporting Prometheus text-based-format:
 * https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
 */
static int
gtp_interface_nl_rx_dump(gtp_interface_t *iface, FILE *fp,
			 const char *var, __u8 type)
{
	struct rtnl_link_stats64 *s = iface->link_metrics;

	if (type == METRIC_BYTE) {
		fprintf(fp, "%s{interface=\"%s\"} %lld\n"
			  , var, iface->description, s->rx_bytes);
		return 0;
	}
	
	fprintf(fp, "%s{interface=\"%s\"} %lld\n"
		  , var, iface->description, s->rx_packets);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "multicast", s->multicast);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "collisions", s->collisions);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "errors", s->rx_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "dropped", s->rx_dropped);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "length-errors", s->rx_length_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "over-errors", s->rx_over_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "crc-errors", s->rx_crc_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "frame-errors", s->rx_frame_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "fifo-errors", s->rx_fifo_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "missed-errors", s->rx_missed_errors);
	return 0;
}

static int
gtp_interface_nl_tx_dump(gtp_interface_t *iface, FILE *fp,
			 const char *var, __u8 type)
{
	struct rtnl_link_stats64 *s = iface->link_metrics;

	if (type == METRIC_BYTE) {
		fprintf(fp, "%s{interface=\"%s\"} %lld\n"
			  , var, iface->description, s->tx_bytes);
		return 0;
	}

	fprintf(fp, "%s{interface=\"%s\"} %lld\n"
		  , var, iface->description, s->tx_packets);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "errors", s->tx_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "dropped", s->tx_dropped);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "aborted-errors", s->tx_aborted_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "carrier-errors", s->tx_carrier_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "fifo-errors", s->tx_fifo_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "heartbeat-errors", s->tx_heartbeat_errors);
	fprintf(fp, "%s{interface=\"%s\",type=\"%s\"} %lld\n"
		  , var, iface->description
		  , "window-errors", s->tx_window_errors);
	return 0;
}

static int
link_metrics_var_dump(gtp_interface_t *iface, void *arg,
		      const char *var, int var_type,
		      __u8 type, __u8 direction)
{
	struct rtnl_link_stats64 *s = iface->link_metrics;
	FILE *fp = arg;

	if (!__test_bit(GTP_INTERFACE_FL_METRICS_LINK_BIT, &iface->flags) || !s)
		return -1;

	switch (direction) {
	case IF_DIRECTION_RX:
		gtp_interface_nl_rx_dump(iface, fp, var, var_type);
		break;
	case IF_DIRECTION_TX:
		gtp_interface_nl_tx_dump(iface, fp, var, var_type);
		break;
	default:
		return -1;
	}

	return 0;
}

static int
link_metrics_tmpl_dump(FILE *fp, const char *var, int var_type,
		       const char *desc, const char *type,
		       __u8 metric_type, __u8 direction)
{
	fprintf(fp, "# HELP %s %s\n# TYPE %s %s\n", var, desc, var, type);
	gtp_interface_metrics_foreach(link_metrics_var_dump,
				      fp, var, var_type, metric_type, direction);
	fprintf(fp, "\n");
	return 0;
}


static const struct {
	const char	*var;
	int		var_type;
	const char	*description;
	const char	*type;
	__u8		metric_type;
	__u8		direction;
} link_metrics_set[] = {
	{ "gtpguard_in_packet_total", METRIC_PACKET,
	  "Count of received packets", "counter", 0, IF_DIRECTION_RX},
	{ "gtpguard_in_byte_total", METRIC_BYTE,
	  "Count of received bytes", "counter", 0, IF_DIRECTION_RX},
	{ "gtpguard_out_packet_total", METRIC_PACKET,
	  "Count of transmitted packets", "counter", 0, IF_DIRECTION_TX},
	{ "gtpguard_out_byte_total", METRIC_BYTE,
	  "Count of transmitted bytes", "counter", 0, IF_DIRECTION_TX},
	{ NULL, 0, NULL, NULL, 0, 0}
};


static int
gtp_interface_nl_metrics_dump(FILE *fp)
{
	int i;

	for (i = 0; link_metrics_set[i].var; i++)
		link_metrics_tmpl_dump(fp,
				       link_metrics_set[i].var,
				       link_metrics_set[i].var_type,
				       link_metrics_set[i].description,
				       link_metrics_set[i].type,
				       link_metrics_set[i].metric_type,
				       link_metrics_set[i].direction);
	return 0;
}


static int
gtp_interface_metric_inuse(gtp_interface_t *iface, void *arg)
{
	__u16 *type = arg;

	switch (*type >> 8) {
	case IF_METRICS_GTP:
		if (__test_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags))
			*type |= 1;
		break;
	case IF_METRICS_PPPOE:
		if (__test_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags))
			*type |= 1;
		break;
	case IF_METRICS_IPIP:
		if (__test_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags))
			*type |= 1;
		break;
	}

	return 0;
}

static int
gtp_pkt_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->packets);
}
static int
gtp_pkt_dropped_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->dropped_packets);
}
static int
gtp_bytes_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->bytes);
}
static int
gtp_bytes_dropped_dump(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	return fprintf((FILE *) arg, "%lld\n", m->dropped_bytes);
}

static int
gtp_interface_metrics_var_dump(gtp_interface_t *iface, void *arg,
			       const char *var, int var_type,
			       __u8 type, __u8 direction)
{
	gtp_bpf_prog_t *p = gtp_bpf_prog_get_first_by_tpl(GTP_ROUTE);
	__u16 inuse = type << 8;
	FILE *fp = arg;

	if (!p)
		return -1;

	gtp_interface_metric_inuse(iface, &inuse);
	if (!(inuse & 0xff))
		return -1;

	fprintf(fp, "%s{interface=\"%s\"} "
		  , var, iface->description);
	gtp_bpf_rt_metrics_dump(p, (var_type == METRIC_PACKET) ? gtp_pkt_dump :
								 gtp_bytes_dump
				 , fp, iface->ifindex, type, direction);
	fprintf(fp, "%s{interface=\"%s\",type=\"dropped\"} "
		  , var, iface->description);
	gtp_bpf_rt_metrics_dump(p, (var_type == METRIC_PACKET) ? gtp_pkt_dropped_dump :
								 gtp_bytes_dropped_dump
				 , fp, iface->ifindex, type, direction);
	return 0;
}

static int
gtp_interface_metrics_tmpl_dump(FILE *fp, const char *var, int var_type,
				const char *desc, const char *type,
				__u8 metric_type, __u8 direction)
{
	__u16 inuse = metric_type << 8;

	/* at least one interface is using this metric ? */
	gtp_interface_foreach(gtp_interface_metric_inuse, &inuse);
	if (!(inuse & 0xff))
		return -1;

	fprintf(fp, "# HELP %s %s\n# TYPE %s %s\n", var, desc, var, type);
	gtp_interface_metrics_foreach(gtp_interface_metrics_var_dump,
				      fp, var, var_type, metric_type, direction);
	fprintf(fp, "\n");
	return 0;
}

static const struct {
	const char	*var;
	int		var_type;
	const char	*description;
	const char	*type;
	__u8		metric_type;
	__u8		direction;
} gtp_interface_metrics_set[] = {
	{ "gtpguard_gtpu_in_packet_total", METRIC_PACKET,
	  "Count of received GTP-U packets", "counter", IF_METRICS_GTP, IF_DIRECTION_RX},
	{ "gtpguard_gtpu_in_byte_total", METRIC_BYTE,
	  "Count of received GTP bytes", "counter", IF_METRICS_GTP, IF_DIRECTION_RX},
	{ "gtpguard_gtpu_out_packet_total", METRIC_PACKET,
	  "Count of transmitted GTP-U packets", "counter", IF_METRICS_GTP, IF_DIRECTION_TX},
	{ "gtpguard_gtpu_out_byte_total", METRIC_BYTE,
	  "Count of transmitted GTP-U bytes", "counter", IF_METRICS_GTP, IF_DIRECTION_TX},

	{ "gtpguard_pppoe_in_packet_total", METRIC_PACKET,
	  "Count of received PPPoE packets", "counter", IF_METRICS_PPPOE, IF_DIRECTION_RX},
	{ "gtpguard_pppoe_in_byte_total", METRIC_BYTE,
	  "Count of received PPPoE bytes", "counter", IF_METRICS_PPPOE, IF_DIRECTION_RX},
	{ "gtpguard_pppoe_out_packet_total", METRIC_PACKET,
	  "Count of transmitted PPPoE packets", "counter", IF_METRICS_PPPOE, IF_DIRECTION_TX},
	{ "gtpguard_pppoe_out_byte_total", METRIC_BYTE,
	  "Count of transmitted PPPoE bytes", "counter", IF_METRICS_PPPOE, IF_DIRECTION_TX},

	{ "gtpguard_ipip_in_packet_total", METRIC_PACKET,
	  "Count of received IPIP packets", "counter", IF_METRICS_IPIP, IF_DIRECTION_RX},
	{ "gtpguard_ipip_in_byte_total", METRIC_BYTE,
	  "Count of received IPIP bytes", "counter", IF_METRICS_IPIP, IF_DIRECTION_RX},
	{ "gtpguard_ipip_out_packet_total", METRIC_PACKET,
	  "Count of transmitted IPIP packets", "counter", IF_METRICS_IPIP, IF_DIRECTION_TX},
	{ "gtpguard_ipip_out_byte_total", METRIC_BYTE,
	  "Count of transmitted IPIP bytes", "counter", IF_METRICS_IPIP, IF_DIRECTION_TX},

	{ NULL, 0, NULL, NULL, 0, 0}
};

int
gtp_interface_metrics_dump(FILE *fp)
{
	int i;

	gtp_interface_nl_metrics_dump(fp);

	for (i = 0; gtp_interface_metrics_set[i].var; i++)
		gtp_interface_metrics_tmpl_dump(fp,
						gtp_interface_metrics_set[i].var,
						gtp_interface_metrics_set[i].var_type,
						gtp_interface_metrics_set[i].description,
						gtp_interface_metrics_set[i].type,
						gtp_interface_metrics_set[i].metric_type,
						gtp_interface_metrics_set[i].direction);
	return 0;
}
