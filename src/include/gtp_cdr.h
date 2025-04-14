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

#ifndef _GTP_CDR_H
#define _GTP_CDR_H

/* defines */
#define GTP_CDR_TAG_MAX	46

/* GTP CDR informations */
typedef struct _gtp_cdr_ctx {
	uint8_t		*data;
	size_t		data_len;
} gtp_cdr_ctx_t;

typedef struct _gtp_cdr {
	/* Start infos */
	uint8_t		served_imsi[8];
	uint8_t		served_imei[8];
	uint8_t		*served_msisdn;
	int		served_msisdn_len;
	uint8_t		*apn_ni;			/* Allocated */
	uint8_t		pdn_type[2];
	uint8_t		serving_node_type;
	uint8_t		serving_node_plmn[3];
	char		*node_id;
	uint8_t		*uli;				/* Allocated */
	int		uli_len;
	uint8_t		rattype;
	uint8_t		pgw_plmn[3];
	uint16_t	charging_characteristics;
	uint16_t	mstimezone;
	uint8_t		record_opening_time[9];
	uint8_t		start_time[9];
	uint32_t	sgw_addr;
	uint32_t	pgw_addr;
	uint32_t	served_addr;
	uint8_t		rating_group;
	uint8_t		service_condition_change[5];
	uint64_t	charging_id;
	uint8_t		rec_type;

	/* Stop infos */
	uint8_t		cause_for_rec_closing;
	uint8_t		stop_time[9];
	uint64_t	duration;

	/* Data-Path infos */
	uint64_t	volume_down;
	uint64_t	volume_up;

	/* Local infos */
	time_t		start;
	timeval_t	time;
	struct tm	date;

	/* ASN.1 context */
	gtp_cdr_ctx_t	asn1_ctx[GTP_CDR_TAG_MAX];

	list_head_t	next;
} gtp_cdr_t;

/* Prototypes */
extern int gtp_cdr_volumes_update(gtp_cdr_t *, uint64_t, uint64_t);
extern int gtp_cdr_update(pkt_buffer_t *, gtp_msg_t *, gtp_cdr_t *);
extern gtp_cdr_t *gtp_cdr_alloc(void);
extern void gtp_cdr_destroy(gtp_cdr_t *);

#endif
