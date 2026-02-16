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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "pfcp_ie.h"
#include "gtp_utils.h"
#include "pfcp.h"


/*
 *	PFCP Pkt IE Utils
 */
int
pfcp_ie_foreach(const uint8_t *buffer, size_t bsize,
	        int (*hdl) (void *, void *, const uint8_t *), void *arg1, void *arg2)
{
	struct pfcp_ie *ie;
	const uint8_t *cp, *end = buffer + bsize;
	size_t offset;
	int err;

	for (cp = buffer; cp < end; cp += offset) {
		ie = (struct pfcp_ie *) cp;
		offset = sizeof(struct pfcp_ie) + ntohs(ie->length);

		/* bound checking */
		if (cp + offset > end)
			return -1;

		err = (*(hdl)) (arg1, arg2, cp);
		if (err)
			return -1;
	}

	return 0;
}

static int
pfcp_ie_decode_bcd_field(const uint8_t **cp, const uint8_t *end, uint64_t *output)
{
	uint8_t len;

	/* init, NULL argument supported */
	if (!*output)
		return 0;
	*output = 0;

	/* bound checking */
	if (*cp >= end)
		return -1;

	len = *(*cp)++;
	if (len > 10)  /* Max 20 digits, 8 bytes BCD */
		return -1;

	/* bound checking */
	if (*cp + len > end)
		return -1;

	*output = bcd_to_int64(*cp, len);

	*cp += len;
	return 0;
}

int
pfcp_ie_decode_user_id(struct pfcp_ie_user_id *uid, uint64_t *imsi, uint64_t *imei, uint64_t *msisdn)
{
	const uint8_t *end = (const uint8_t *)uid + sizeof(struct pfcp_ie) + ntohs(uid->h.length);
	const uint8_t *cp = uid->value;

	if (uid->imsif && pfcp_ie_decode_bcd_field(&cp, end, imsi))
		return -1;

	if (uid->imeif && pfcp_ie_decode_bcd_field(&cp, end, imei))
		return -1;

	if (uid->msisdnf && pfcp_ie_decode_bcd_field(&cp, end, msisdn))
		return -1;

	return 0;
}

int
pfcp_ie_decode_apn_dnn_ni(struct pfcp_ie_apn_dnn *apn, char *dst, size_t dsize)
{
	return gtp_apn_extract_ni(apn->apn_dnn, ntohs(apn->h.length), dst, dsize);
}


/*
 *	PFCP Pkt IE Factory
 */
int
pfcp_ie_put(struct pkt_buffer *pbuff, uint16_t type, uint16_t length)
{
	struct pfcp_hdr *h = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_ie *ie;

	if (pkt_buffer_tailroom(pbuff) < length)
		return -1;

	ie = (struct pfcp_ie *) pbuff->data;
	ie->type = htons(type);
	ie->length = htons(length - sizeof(*ie));
	h->length = htons(ntohs(h->length) + length);
	return 0;
}

int
pfcp_ie_put_type(struct pkt_buffer *pbuff, uint16_t type)
{
	struct pfcp_ie *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, type, length) < 0)
		return -1;

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_recovery_ts(struct pkt_buffer *pbuff, uint32_t ts)
{
	struct pfcp_ie_recovery_time_stamp *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_RECOVERY_TIME_STAMP, length) < 0)
		return -1;

	ie = (struct pfcp_ie_recovery_time_stamp *) pbuff->data;
	ie->ts = htonl(ts);

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_up_function_features(struct pkt_buffer *pbuff, uint8_t *supported_features)
{
	struct pfcp_ie_up_function_features *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_UP_FUNCTION_FEATURES, length) < 0)
		return -1;

	ie = (struct pfcp_ie_up_function_features *) pbuff->data;
	memcpy(ie->feature_flags, supported_features, sizeof(ie->feature_flags));

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_cause(struct pkt_buffer *pbuff, uint8_t cause)
{
	struct pfcp_ie_cause *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_CAUSE, length) < 0)
		return -1;

	ie = (struct pfcp_ie_cause *) pbuff->data;
	ie->value = cause;

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_node_id(struct pkt_buffer *pbuff, const uint8_t *node_id, size_t nsize)
{
	struct pfcp_ie_node_id *ie;
	unsigned int length = sizeof(struct pfcp_ie) + 1 + nsize;

	if (pfcp_ie_put(pbuff, PFCP_IE_NODE_ID, length) < 0)
		return -1;

	ie = (struct pfcp_ie_node_id *) pbuff->data;
	ie->node_id_type = PFCP_NODE_ID_TYPE_FQDN;
	memcpy(ie->fqdn, node_id, (nsize > PFCP_NODE_ID_FQDN_MAX_LEN) ? PFCP_NODE_ID_FQDN_MAX_LEN - 1 : nsize);

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_error_cause(struct pkt_buffer *pbuff, const uint8_t *node_id, size_t nsize,
			uint8_t cause)
{
	int err = pfcp_ie_put_node_id(pbuff, node_id, nsize);
	return (err) ? : pfcp_ie_put_cause(pbuff, cause);
}

int
pfcp_ie_put_f_seid(struct pkt_buffer *pbuff, const uint64_t seid,
		   const struct sockaddr_storage *addr)
{
	struct pfcp_ie_f_seid *ie;
	unsigned int length = sizeof(struct pfcp_ie) + sizeof(uint64_t) + 1;

	switch (addr->ss_family) {
	case AF_INET:
		length += sizeof(struct in_addr);
		break;
	case AF_INET6:
		length += sizeof(struct in6_addr);
		break;
	default:
		return -1;
	}

	if (pfcp_ie_put(pbuff, PFCP_IE_F_SEID, length) < 0)
		return -1;

	ie = (struct pfcp_ie_f_seid *) pbuff->data;
	ie->seid = seid;
	ie->flags = 0;
	switch (addr->ss_family) {
	case AF_INET:
		ie->v4 = 1;
		ie->ipv4 = ((struct sockaddr_in *)addr)->sin_addr;
		break;
	case AF_INET6:
		ie->v6 = 1;
		memcpy(&ie->ipv6, &((struct sockaddr_in6 *)addr)->sin6_addr,
		       sizeof(struct in6_addr));
		break;
	}

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_f_teid(struct pkt_buffer *pbuff, struct pfcp_ie *c, const uint32_t teid,
		   const struct in_addr *ipv4, const struct in6_addr *ipv6)
{
	struct pfcp_ie_f_teid *ie;
	unsigned int length = sizeof(struct pfcp_ie) + sizeof(uint32_t) + 1;

	if (!teid)
		return 0;

	length += (ipv4) ? sizeof(struct in_addr) : 0;
	length += (ipv6) ? sizeof(struct in6_addr) : 0;

	if (pfcp_ie_put(pbuff, PFCP_IE_F_TEID, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_f_teid *) pbuff->data;
	ie->s.teid = teid;
	ie->spare = 0;
	ie->ch = 0;
	ie->chid = 0;
	ie->v4 = (ipv4) ? 1 : 0;
	ie->v6 = (ipv6) ? 1 : 0;

	if (ipv4 && !ipv6)
		ie->s.ip.v4 = *ipv4;

	if (ipv6 && !ipv4)
		memcpy(&ie->s.ip.v6, ipv6, sizeof(struct in6_addr));

	if (ipv6 && ipv4) {
		ie->s.ip.both.v4 = *ipv4;
		memcpy(&ie->s.ip.both.v6, ipv6, sizeof(struct in6_addr));
	}

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_pdr_id(struct pkt_buffer *pbuff, struct pfcp_ie *c, const uint16_t pdr_id)
{
	struct pfcp_ie_pdr_id *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_PDR_ID, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_pdr_id *) pbuff->data;
	ie->rule_id = pdr_id;
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_created_pdr(struct pkt_buffer *pbuff, const uint16_t pdr_id,
		       const uint32_t teid, const struct in_addr *ipv4,
		       const struct in6_addr *ipv6)
{
	struct pfcp_ie *ie_created_pdr = (struct pfcp_ie *) pbuff->data;
	int err;

	err = pfcp_ie_put_type(pbuff, PFCP_IE_CREATED_PDR);
	err = (err) ? : pfcp_ie_put_pdr_id(pbuff, ie_created_pdr, pdr_id);
	err = (err) ? : pfcp_ie_put_f_teid(pbuff, ie_created_pdr, teid, ipv4, ipv6);

	return err;
}

static int
pfcp_ie_put_te_id(struct pkt_buffer *pbuff, struct pfcp_ie *c, const uint8_t id)
{
	struct pfcp_ie_traffic_endpoint_id *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_TRAFFIC_ENDPOINT_ID, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_traffic_endpoint_id *) pbuff->data;
	ie->value = id;
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_ue_ip_address(struct pkt_buffer *pbuff, struct pfcp_ie *c,
			  const struct in_addr *ipv4, const struct in6_addr *ipv6)
{
	struct pfcp_ie_ue_ip_address *ie;
	unsigned int length = sizeof(struct pfcp_ie) + 1;

	if (!ipv4 && !ipv6)
		return 0;

	length += (ipv4) ? sizeof(struct in_addr) : 0;
	length += (ipv6) ? sizeof(struct in6_addr) : 0;

	if (pfcp_ie_put(pbuff, PFCP_IE_UE_IP_ADDRESS, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_ue_ip_address *) pbuff->data;
	ie->spare = 0;
	ie->ipv6pl = 0;
	ie->chv6 = 0;
	ie->chv4 = 0;
	ie->ipv6d = 0;
	ie->sd = 0;
	ie->v4 = (ipv4) ? 1 : 0;
	ie->v6 = (ipv6) ? 1 : 0;

	if (ipv4 && !ipv6)
		ie->ip_address.v4 = *ipv4;

	if (ipv6 && !ipv4)
		memcpy(&ie->ip_address.v6, ipv6, sizeof(struct in6_addr));

	if (ipv6 && ipv4) {
		ie->ip_address.both.v4 = *ipv4;
		memcpy(&ie->ip_address.both.v6, ipv6, sizeof(struct in6_addr));
	}

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_created_te(struct pkt_buffer *pbuff, const uint8_t id, const uint32_t teid,
		       const struct in_addr *t_ipv4, const struct in6_addr *t_ipv6,
		       const struct in_addr *ue_ipv4, const struct in6_addr *ue_ipv6)
{
	struct pfcp_ie *ie_created_te = (struct pfcp_ie *) pbuff->data;
	int err;

	err = pfcp_ie_put_type(pbuff, PFCP_IE_CREATED_TRAFFIC_ENDPOINT);
	err = (err) ? : pfcp_ie_put_te_id(pbuff, ie_created_te, id);
	err = (err) ? : pfcp_ie_put_f_teid(pbuff, ie_created_te, teid, t_ipv4, t_ipv6);
	err = (err) ? : pfcp_ie_put_ue_ip_address(pbuff, ie_created_te, ue_ipv4, ue_ipv6);

	return err;
}

/* Usage Report */
static int
pfcp_ie_put_urr_id(struct pkt_buffer *pbuff, struct pfcp_ie *c, const uint32_t id)
{
	struct pfcp_ie_urr_id *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_URR_ID, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_urr_id *) pbuff->data;
	ie->value = id;
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_ur_seqn(struct pkt_buffer *pbuff, struct pfcp_ie *c, const uint32_t seqn)
{
	struct pfcp_ie_ur_seqn *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_UR_SEQN, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_ur_seqn *) pbuff->data;
	ie->value = htonl(seqn);
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_ur_trigger(struct pkt_buffer *pbuff, struct pfcp_ie *c, bool term)
{
	struct pfcp_ie_usage_report_trigger *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_USAGE_REPORT_TRIGGER, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_usage_report_trigger *) pbuff->data;
	ie->immer = 1;		/* Immediate report */
	ie->termr = (term);	/* Termination report */
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_start_time(struct pkt_buffer *pbuff, struct pfcp_ie *c, const uint32_t time)
{
	struct pfcp_ie_start_time *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_START_TIME, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_start_time *) pbuff->data;
	ie->value = htonl(time);
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_end_time(struct pkt_buffer *pbuff, struct pfcp_ie *c, const uint32_t time)
{
	struct pfcp_ie_end_time *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_END_TIME, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_end_time *) pbuff->data;
	ie->value = htonl(time);
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_volume_measurement(struct pkt_buffer *pbuff, struct pfcp_ie *c,
			      const struct pfcp_metrics_pkt *up,
			      const struct pfcp_metrics_pkt *down)
{
	struct pfcp_ie_volume_measurement *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_VOLUME_MEASUREMENT, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_volume_measurement *) pbuff->data;
	ie->spare = 0;
	ie->dlnop = 1;
	ie->ulnop = 1;
	ie->tonop = 1;
	ie->dlvol = 1;
	ie->ulvol = 1;
	ie->tovol = 1;
	ie->total_volume = htobe64(up->bytes + down->bytes);
	ie->uplink_volume = htobe64(up->bytes);
	ie->downlink_volume = htobe64(down->bytes);
	ie->total_packets = htobe64(up->count + down->count);
	ie->uplink_packets = htobe64(up->count);
	ie->downlink_packets = htobe64(down->count);
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_duration_measurement(struct pkt_buffer *pbuff, struct pfcp_ie *c,
				 const uint32_t duration)
{
	struct pfcp_ie_duration_measurement *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_DURATION_MEASUREMENT, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_duration_measurement *) pbuff->data;
	ie->value = htonl(duration);
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_time_first_pkt(struct pkt_buffer *pbuff, struct pfcp_ie *c,
			   const uint32_t time)
{
	struct pfcp_ie_time_of_first_packet *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_TIME_OF_FIRST_PACKET, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_time_of_first_packet *) pbuff->data;
	ie->value = htonl(time);
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_time_last_pkt(struct pkt_buffer *pbuff, struct pfcp_ie *c,
			  const uint32_t time)
{
	struct pfcp_ie_time_of_last_packet *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_TIME_OF_LAST_PACKET, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_time_of_last_packet *) pbuff->data;
	ie->value = htonl(time);
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

static int
pfcp_ie_put_usage_report(uint8_t type, struct pkt_buffer *pbuff, uint32_t id,
			 uint32_t start_time, uint32_t end_time, uint32_t seqn,
			 bool termr,
			 struct pfcp_metrics_pkt *uplink,
			 struct pfcp_metrics_pkt *downlink)
{
	struct pfcp_ie *ie_usage_report = (struct pfcp_ie *) pbuff->data;
	uint32_t duration = end_time - start_time;
	int err;

	err = pfcp_ie_put_type(pbuff, type);
	err = (err) ? : pfcp_ie_put_urr_id(pbuff, ie_usage_report, id);
	err = (err) ? : pfcp_ie_put_ur_seqn(pbuff, ie_usage_report, seqn);
	err = (err) ? : pfcp_ie_put_ur_trigger(pbuff, ie_usage_report, termr);
	err = (err) ? : pfcp_ie_put_start_time(pbuff, ie_usage_report, start_time);
	err = (err) ? : pfcp_ie_put_end_time(pbuff, ie_usage_report, end_time);
	err = (err) ? : pfcp_ie_put_volume_measurement(pbuff, ie_usage_report,
						       uplink, downlink);
	err = (err) ? : pfcp_ie_put_duration_measurement(pbuff, ie_usage_report,
							 duration);
	if (!pfcp_metrics_pkt_is_null(uplink) && !pfcp_metrics_pkt_is_null(downlink)) {
		err = (err) ? : pfcp_ie_put_time_first_pkt(pbuff, ie_usage_report, start_time);
		err = (err) ? : pfcp_ie_put_time_last_pkt(pbuff, ie_usage_report, end_time);
	}

	return err;
}

int
pfcp_ie_put_usage_report_deletion(struct pkt_buffer *pbuff, uint32_t id,
				  uint32_t start_time, uint32_t end_time, uint32_t seqn,
				  struct pfcp_metrics_pkt *uplink,
				  struct pfcp_metrics_pkt *downlink)
{
	return pfcp_ie_put_usage_report(PFCP_IE_USAGE_REPORT_DELETION, pbuff, id,
					start_time, end_time, seqn, true,
					uplink, downlink);
}

static int
pfcp_ie_put_query_urr_ref(struct pkt_buffer *pbuff, struct pfcp_ie *c,
			  const uint32_t query_urr_ref)
{
	struct pfcp_ie_query_urr_reference *ie;
	unsigned int length = sizeof(*ie);

	if (!query_urr_ref)
		return 0;

	if (pfcp_ie_put(pbuff, PFCP_IE_QUERY_URR_REFERENCE, length) < 0)
		return -1;

	/* Update Container IE */
	c->length = htons(ntohs(c->length) + length);

	ie = (struct pfcp_ie_query_urr_reference *) pbuff->data;
	ie->value = query_urr_ref;
	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_usage_report_request(struct pkt_buffer *pbuff, uint32_t query_urr_ref,
				 uint32_t id, uint32_t start_time, uint32_t end_time,
				 uint32_t seqn, struct pfcp_metrics_pkt *uplink,
				 struct pfcp_metrics_pkt *downlink)
{
	struct pfcp_ie *ie_usage_report = (struct pfcp_ie *) pbuff->data;
	int err;

	err = pfcp_ie_put_usage_report(PFCP_IE_USAGE_REPORT, pbuff, id,
				       start_time, end_time, seqn, false,
				       uplink, downlink);
	err  = (err) ? : pfcp_ie_put_query_urr_ref(pbuff, ie_usage_report, query_urr_ref);

	return err;
}

int
pfcp_ie_put_report_type(struct pkt_buffer *pbuff, uint8_t type)
{
	struct pfcp_ie_report_type *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_REPORT_TYPE, length) < 0)
		return -1;

	ie = (struct pfcp_ie_report_type *) pbuff->data;
	ie->report_type = type;

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}

int
pfcp_ie_put_additional_usage_reports_info(struct pkt_buffer *pbuff, bool auri,
					  uint16_t nr_reports)
{
	struct pfcp_ie_additional_usage_reports_information *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION, length) < 0)
		return -1;

	ie = (struct pfcp_ie_additional_usage_reports_information *) pbuff->data;
	ie->flags = htons(nr_reports);
	ie->auri = auri;

	pkt_buffer_put_data(pbuff, length);
	pkt_buffer_put_end(pbuff, length);
	return 0;
}
