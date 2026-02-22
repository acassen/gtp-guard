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
#include "gtp_cdr.h"

/* defines */
#define PGW_RECORD_TYPE		85

/* TAGs */
enum gtp_cdr_asn1_tag {
	PGW_RECORD_TAG = 79,
	PGW_IMSI_TAG = 3,
	PGW_PGW_ADDR_TAG = 4,
	PGW_CHARGING_ID_TAG = 5,
	PGW_SGW_ADDR_TAG = 6,
	PGW_APN_NI_TAG = 7,
	PGW_PDN_TYPE_TAG = 8,
	PGW_OPENING_TIME_TAG = 13,
	PGW_DURATION_TAG = 14,
	PGW_CAUSE_TAG = 15,
	PGW_NODE_ID_TAG = 18,
	PGW_MSISDN_TAG = 22,
	PGW_CHARGING_CARAC_TAG = 23,
	PGW_SGW_PLMN_TAG = 27,
	PGW_IMEI_TAG = 29,
	PGW_RATTYPE_TAG = 30,
	PGW_MSTIMEZONE_TAG = 31,
	PGW_ULI_TAG = 32,
	PGW_PGW_PLMN_TAG = 37,	
	PGW_START_TIME_TAG = 38,
	PGW_STOP_TIME_TAG = 39,
};

/* Encoding method */
enum gtp_cdr_asn1_encode_method {
	M_RAW = 0,
	M_IP_ADDRESS,
	M_INTEGER,
	M_MAX,
};

/* Prototypes */
int gtp_cdr_asn1_pgw_record_encode(struct gtp_cdr *, uint8_t *, size_t);
int gtp_cdr_asn1_ctx_set(struct gtp_cdr_ctx *, uint32_t, uint8_t *, size_t);
