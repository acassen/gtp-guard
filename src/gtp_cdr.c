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
#include <errno.h>

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	Utilities
 */
static int
cdr_current_date_to_bcd(gtp_cdr_t *cdr, uint8_t *dst, size_t dsize)
{
	struct tm *date = &cdr->date;
	uint64_t tmp;

	if (dsize < 9)
		return -1;

	gettimeofday(&cdr->time, NULL);
	memset(date, 0, sizeof(struct tm));
	date->tm_isdst = -1;
	localtime_r(&cdr->time.tv_sec, date);

	dst[0] = hex_to_bcd(date->tm_year - 100);
	dst[1] = hex_to_bcd(date->tm_mon + 1);
	dst[2] = hex_to_bcd(date->tm_mday);
	dst[3] = hex_to_bcd(date->tm_hour);
	dst[4] = hex_to_bcd(date->tm_min);
	dst[5] = hex_to_bcd(date->tm_sec);
	dst[6] = (date->tm_gmtoff > 0) ? '+' : '-';
	tmp = (date->tm_gmtoff / 3600) * 100 + date->tm_gmtoff % 3600;
	int64_to_bcd(tmp, dst+7, 2);
	return 0;
}

static uint8_t *
cdr_apn_ni_alloc(gtp_msg_t *msg)
{
	gtp_msg_ie_t *msg_ie;
	char tmp_str[64];
	uint8_t *apn_ni;
	int err;

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_APN_TYPE);
	if (!msg_ie)
		return NULL;

	memset(tmp_str, 0, 64);
	err = gtp_ie_apn_extract_ni((gtp_ie_apn_t *) msg_ie->h, tmp_str, 64);
	if (err)
		return NULL;

	apn_ni = MALLOC(strlen(tmp_str));
	bsd_strlcpy((char *) apn_ni, tmp_str, strlen(tmp_str));

	return apn_ni;
}

static int
cdr_hplmn_set(uint8_t *apn_ni, uint8_t *plmn)
{
	gtp_apn_t *apn;
	gtp_plmn_t *hplmn;

	if (!apn_ni)
		return -1;

	apn = gtp_apn_get((char *) apn_ni);
	if (!apn)
		return -1;

	/* If HPLMN is configured, pick-up first one */
	if (list_empty(&apn->hplmn))
		return -1;

	hplmn = list_first_entry(&apn->hplmn, gtp_plmn_t, next);
	memcpy(plmn, hplmn->plmn, GTP_PLMN_MAX_LEN);
	return 0;
}

static int
cdr_pdn_type_set(gtp_msg_t *msg, uint8_t *pdn_type)
{
	gtp_msg_ie_t *msg_ie;
	uint8_t *cp;

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_PDN_TYPE);
	if (!msg_ie)
		return -1;

	pdn_type[0] = 0xf1;
	cp = (uint8_t *) msg_ie->data;
	if (*cp & GTP_FL_PDN_IPV4)
		pdn_type[1] = 0x21;
	if (*cp & GTP_FL_PDN_IPV6)
		pdn_type[1] = 0x57;
	if (*cp & (GTP_FL_PDN_IPV4|GTP_FL_PDN_IPV6))
		pdn_type[1] = 0x8d;

	return 0;
}

int
cdr_teid_addr_set(gtp_msg_t *msg, uint32_t *dst)
{
	gtp_msg_ie_t *msg_ie;
	gtp_ie_f_teid_t *f_teid;

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_F_TEID_TYPE);
	if (!msg_ie)
		return -1;
	
	f_teid = (gtp_ie_f_teid_t *) msg_ie->h;
	if (!f_teid->v4)
		return -1;

	*dst = f_teid->ipv4;
	return 0;
}

int
cdr_paa_set(gtp_msg_t *msg, uint32_t *dst)
{
	gtp_msg_ie_t *msg_ie;
	gtp_ie_paa_t *paa;

	msg_ie = gtp_msg_ie_get(msg, GTP_IE_PAA_TYPE);
	if (!msg_ie)
		return -1;

	paa = (gtp_ie_paa_t *) msg_ie->h;
	if (paa->type != GTP_PAA_IPV4_TYPE)
		return -1;

	*dst = paa->addr;
	return 0;
}

int
cdr_ie_data_cpy(gtp_msg_t *msg, int ie_type, uint8_t *dst)
{
	gtp_msg_ie_t *msg_ie;

	msg_ie = gtp_msg_ie_get(msg, ie_type);
	if (!msg_ie)
		return -1;

	memcpy(dst, msg_ie->data, ntohs(msg_ie->h->length));
	return 0;
}


/*
 *	Update CDR according to GTP-C msg type
 */
static int
cdr_create_session_request(gtp_cdr_t *cdr, gtp_msg_t *msg)
{
	gtp_msg_ie_t *msg_ie;

	cdr_ie_data_cpy(msg, GTP_IE_IMSI_TYPE, cdr->served_imsi);
	cdr_ie_data_cpy(msg, GTP_IE_MEI_TYPE, cdr->served_imei);
	cdr_ie_data_cpy(msg, GTP_IE_MSISDN_TYPE, cdr->served_msisdn);
	cdr->apn_ni = cdr_apn_ni_alloc(msg);
	cdr_hplmn_set(cdr->apn_ni, cdr->pgw_plmn);
	cdr_pdn_type_set(msg, cdr->pdn_type);
	cdr_ie_data_cpy(msg, GTP_IE_SERVING_NETWORK_TYPE, cdr->serving_node_plmn);
	cdr->node_id = host.name;
	cdr->start = time(NULL);
	cdr_current_date_to_bcd(cdr, cdr->start_time, 9);
	cdr_current_date_to_bcd(cdr, cdr->record_opening_time, 9);
	cdr_teid_addr_set(msg, &cdr->sgw_addr);

	/* Hardcoded value */
	cdr->serving_node_type = 2;	/* S5/S8 GTP-C */
	cdr->charging_characteristics = htons(0x0100);
	cdr->mstimezone = htons(0x8001);

	/* ULI */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_ULI_TYPE);
	if (msg_ie) {
		cdr->uli_len = ntohs(msg_ie->h->length);
		cdr->uli = MALLOC(cdr->uli_len);
		memcpy(cdr->uli, msg_ie->data, cdr->uli_len);
	}

	/* RAT Type */
	msg_ie = gtp_msg_ie_get(msg, GTP_IE_RAT_TYPE_TYPE);
	if (msg_ie)
		cdr->rattype = *(uint8_t *) msg_ie->data;

	return 0;
}

static int
cdr_create_session_response(gtp_cdr_t *cdr, gtp_msg_t *msg)
{
	cdr_teid_addr_set(msg, &cdr->pgw_addr);
	cdr_paa_set(msg, &cdr->served_addr);
	return 0;
}

static int
cdr_delete_session_response(gtp_cdr_t *cdr, gtp_msg_t *msg)
{
	time_t now = time(NULL);

	cdr_current_date_to_bcd(cdr, cdr->stop_time, 9);

	/* time can resync between start and now */
	cdr->duration = (now > cdr->start) ? now - cdr->start : 0;
	return 0;
}

static const struct {
	int (*update) (gtp_cdr_t *, gtp_msg_t *);
} cdr_msg_hdl[0xff + 1] = {
	[GTP_CREATE_SESSION_REQUEST_TYPE]	= { cdr_create_session_request },
	[GTP_CREATE_SESSION_RESPONSE_TYPE]	= { cdr_create_session_response },
	[GTP_DELETE_SESSION_RESPONSE_TYPE]	= { cdr_delete_session_response },
};

int
gtp_cdr_update_volumes(gtp_cdr_t *cdr, uint64_t up, uint64_t down)
{
	cdr->volume_up += up;
	cdr->volume_down += down;
	return 0;
}

int
gtp_cdr_update(pkt_buffer_t *pbuff, gtp_msg_t *msg, gtp_cdr_t *cdr)
{
	gtp_hdr_t *gtph;

	if (!cdr || !pbuff || !msg)
		return -1;

	gtph = (gtp_hdr_t *) pbuff->head;
	if (*(cdr_msg_hdl[gtph->type].update))
		return (*(cdr_msg_hdl[gtph->type].update)) (cdr, msg);

	return -1;
}

gtp_cdr_t *
gtp_cdr_alloc(void)
{
	gtp_cdr_t *cdr;

	PMALLOC(cdr);
	if (!cdr)
		return NULL;
	INIT_LIST_HEAD(&cdr->next);

	return cdr;
}

void
gtp_cdr_destroy(gtp_cdr_t *cdr)
{
	FREE_PTR(cdr->apn_ni);
	FREE_PTR(cdr->uli);
	FREE(cdr);
}
