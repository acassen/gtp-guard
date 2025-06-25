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


/*
 *	GTPv1 utilities
 */
static int
gtp1_ie_uli_set(gtp1_ie_uli_t *uli, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	uli->geographic_location_type = GTP1_ULI_GEOGRAPHIC_LOCATION_TYPE_CGI;
	memcpy(uli->mcc_mnc, p->plmn, GTP_PLMN_MAX_LEN);
	uli->u.value = addr->sin_addr.s_addr;
	return 0;
}

static int
gtp1_ie_uli_append(pkt_buffer_t *pkt, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	gtp1_hdr_t *gtph = (gtp1_hdr_t *) pkt->head;
	uint8_t *cp = pkt_buffer_end(pkt);
	gtp1_ie_uli_t *uli;
	int delta;

	/* Bounds checking */
	delta = sizeof(gtp1_ie_uli_t);
	if (pkt_buffer_tailroom(pkt) < delta) {
		log_message(LOG_INFO, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
				    , __FUNCTION__
				    , pkt_buffer_tailroom(pkt), delta);
		return -1;
	}

	/* Append ULI */
	uli = (gtp1_ie_uli_t *) cp;
	uli->h.type = GTP1_IE_ULI_TYPE;
	uli->h.length = htons(sizeof(gtp1_ie_uli_t) - sizeof(gtp1_ie_t));
	gtp1_ie_uli_set(uli, p, addr);

	/* Update pkt */
	pkt_buffer_put_end(pkt, delta);
	gtph->length = htons(ntohs(gtph->length) + delta);
	return 0;
}

int
gtp1_ie_uli_update(pkt_buffer_t *pkt, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	uint8_t *cp;

	cp = gtp1_get_ie(GTP1_IE_ULI_TYPE, pkt);
	if (cp)
		return gtp1_ie_uli_set((gtp1_ie_uli_t *) cp, p, addr);

	return gtp1_ie_uli_append(pkt, p, addr);
}


/*
 *	GTPv2 utilities
 */
static size_t
gtp_ie_uli_ecgi_offset(gtp_ie_uli_t *uli)
{
	size_t offset = 0;

	/* ECGI offset: Order matter :
	 * Grouped identities in following order according
	 * to presence in bitfield:
	 * CGI / SAI / RAI / TAI / ECGI / LAI / MacroeNBID / extMacroeNBID */
	 offset += (uli->cgi) ? sizeof(gtp_id_cgi_t) : 0;
	 offset += (uli->sai) ? sizeof(gtp_id_sai_t) : 0;
	 offset += (uli->rai) ? sizeof(gtp_id_rai_t) : 0;
	 offset += (uli->tai) ? sizeof(gtp_id_tai_t) : 0;

	 return offset;
 }

gtp_id_ecgi_t *
gtp_ie_uli_extract_ecgi(gtp_ie_uli_t *uli)
{
	size_t offset = 0;

	if (!uli->ecgi)
		return NULL;

	/* overflow protection */
	offset = gtp_ie_uli_ecgi_offset(uli);
	if (offset + sizeof(gtp_id_ecgi_t) > ntohs(uli->h.length))
		return NULL;

	offset += sizeof(gtp_ie_uli_t);
	return (gtp_id_ecgi_t *) ((uint8_t *)uli + offset);
}

int
gtp_id_ecgi_str(gtp_id_ecgi_t *ecgi, char *buffer, size_t size)
{
	int mcc, mnc;

	if (!ecgi) {
		bsd_strlcpy(buffer, "0+0+0+0", size);
		return -1;
	}

	mcc = bcd_to_int64(ecgi->mcc_mnc, 2);
	mnc = bcd_to_int64(ecgi->mcc_mnc+2, 1);

	return snprintf(buffer, size, "%d+%d+%d+%d"
			      , mcc, mnc
			      , ntohs(ecgi->u.ecgi.enbid)
			      , ecgi->u.ecgi.cellid);
}

static int
gtp_ecgi_set(gtp_id_ecgi_t *ecgi, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	memcpy(ecgi->mcc_mnc, p->plmn, GTP_PLMN_MAX_LEN);
	ecgi->u.value = addr->sin_addr.s_addr;
	return 0;
}

static int
gtp_ie_uli_ecgi_append(pkt_buffer_t *pkt, gtp_ie_uli_t *uli, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) pkt->head;
	int tail_len, delta = sizeof(gtp_id_ecgi_t);
	uint8_t *cp = (uint8_t *) uli;

	/* Bounds checking */
	if (pkt_buffer_tailroom(pkt) < delta) {
		log_message(LOG_INFO, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
				    , __FUNCTION__
				    , pkt_buffer_tailroom(pkt), delta);
		return -1;
	}

	/* expand the room */
	cp += sizeof(gtp_ie_uli_t) + gtp_ie_uli_ecgi_offset(uli);
	tail_len = pkt_buffer_end(pkt) - cp;
	memmove(cp + delta, cp, tail_len);
	pkt_buffer_put_end(pkt, delta);

	/* Update IE & pkt */
	uli->ecgi = 1;
	uli->h.length = htons(ntohs(uli->h.length) + delta);
	gtph->length = htons(ntohs(gtph->length) + delta);

	return gtp_ecgi_set((gtp_id_ecgi_t *) cp, p, addr);
}

static int
gtp_ie_uli_ecgi_update(pkt_buffer_t *pkt, gtp_ie_uli_t *uli, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	gtp_id_ecgi_t *ecgi;

	ecgi = gtp_ie_uli_extract_ecgi(uli);
	if (ecgi)
		return gtp_ecgi_set(ecgi, p, addr);

	return gtp_ie_uli_ecgi_append(pkt, uli, p, addr);
}

static int
gtp_ie_uli_append(pkt_buffer_t *pkt, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	gtp_hdr_t *gtph = (gtp_hdr_t *) pkt->head;
	uint8_t *cp = pkt_buffer_end(pkt);
	gtp_ie_uli_t *uli;
	gtp_id_ecgi_t *ecgi;
	int delta;

	/* Bounds checking */
	delta = sizeof(gtp_ie_uli_t) + sizeof(gtp_id_ecgi_t);
	if (pkt_buffer_tailroom(pkt) < delta) {
		log_message(LOG_INFO, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
				    , __FUNCTION__
				    , pkt_buffer_tailroom(pkt), delta);
		return -1;
	}

	/* Append ULI */
	uli = (gtp_ie_uli_t *) cp;
	memset(uli, 0, sizeof(gtp_ie_uli_t));
	uli->h.type = GTP_IE_ULI_TYPE;
	uli->h.length = htons(sizeof(gtp_id_ecgi_t) + 1);
	uli->ecgi = 1;
	ecgi =(gtp_id_ecgi_t *) (cp + sizeof(gtp_ie_uli_t));
	gtp_ecgi_set(ecgi, p, addr);

	/* Update pkt */
	pkt_buffer_put_end(pkt, delta);
	gtph->length = htons(ntohs(gtph->length) + delta);
	return 0;
}

int
gtp_ie_uli_update(pkt_buffer_t *pkt, gtp_plmn_t *p, struct sockaddr_in *addr)
{
	uint8_t *cp;

	cp = gtp_get_ie(GTP_IE_ULI_TYPE, pkt);
	if (cp)
		return gtp_ie_uli_ecgi_update(pkt, (gtp_ie_uli_t *) cp, p, addr);

	return gtp_ie_uli_append(pkt, p, addr);
}
