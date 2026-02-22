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
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include "list_head.h"
#include "pkt_buffer.h"
#include "gtp_teid.h"
#include "gtp_msg.h"

/* defines */
#define GTP_CDR_TAG_MAX	46

/* GTP CDR informations */
struct gtp_cdr_ctx {
	uint8_t		*data;
	size_t		data_len;
};

struct gtp_cdr {
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
	struct tm	date;

	/* ASN.1 context */
	struct gtp_cdr_ctx asn1_ctx[GTP_CDR_TAG_MAX];

	struct list_head next;
};

/* Prototypes */
int gtp_cdr_volumes_update(struct gtp_cdr *, uint64_t, uint64_t);
int gtp_cdr_volumes_update_from_bpf(struct gtp_teid *);
int gtp_cdr_update(struct pkt_buffer *, struct gtp_msg *, struct gtp_cdr *);
int gtp_cdr_close(struct gtp_cdr *);
struct gtp_cdr *gtp_cdr_alloc(void);
void gtp_cdr_destroy(struct gtp_cdr *);
