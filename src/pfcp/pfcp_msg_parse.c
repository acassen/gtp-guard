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
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "pfcp_msg.h"
#include "pfcp.h"
#include "pkt_buffer.h"


/*
 * 	PFCP Setup Request
 */
static void
pfcp_parse_association_setup_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_association_setup_request *req = (struct pfcp_association_setup_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_RECOVERY_TIME_STAMP:
		req->recovery_time_stamp = (struct pfcp_ie_recovery_time_stamp *)cp;
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_UP_FUNCTION_FEATURES:
		req->up_function_features = (struct pfcp_ie_up_function_features *)cp;
		break;

	case PFCP_IE_CP_FUNCTION_FEATURES:
		req->cp_function_features = (struct pfcp_ie_cp_function_features *)cp;
		break;

	case PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION:
		req->user_plane_ip_resource_info = (struct pfcp_ie_user_plane_ip_resource_information *)cp;
		break;

	case PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS:
		req->alternative_smf_ip_address = (struct pfcp_ie_alternative_smf_ip_address *)cp;
		break;

	case PFCP_IE_SMF_SET_ID:
		req->smf_set_id = (struct pfcp_ie_smf_set_id *)cp;
		break;

	case PFCP_IE_PFCPASREQ_FLAGS:
		req->pfcpasreq_flags = (struct pfcp_ie_pfcpasreq_flags *)cp;
		break;

	case PFCP_IE_SESSION_RETENTION_INFORMATION:
		req->session_retention_info = (struct pfcp_ie_session_retention_information *)cp;
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION:
		req->ue_ip_address_pool_info = (struct pfcp_ie_ue_ip_address_pool_information *)cp;
		break;

	default:
		break;
	}
}


/*
 *	PFCP Messages decoders
 */
static const struct {
	int mandatory_ie;
	size_t arg_size;
	void (*parse) (const uint8_t *, int *, void *);
} pfcp_msg_decoder[1 << 8] = {
	[PFCP_ASSOCIATION_SETUP_REQUEST]	= { 3,
						    sizeof(struct pfcp_association_setup_request),
						    pfcp_parse_association_setup_request
						  },
};

int
pfcp_msg_parse(struct pkt_buffer *pbuff, void *arg)
{
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	int mandatory_found = 0;
	struct pfcp_ie *ie;
	const uint8_t *cp;
	size_t offset;

	if (!pbuff || pkt_buffer_len(pbuff) < sizeof(struct pfcp_hdr) || !arg)
		return -1;

	/* Parse PFCP header */
	offset = pfcp_msg_hlen(pfcph);
	if (pbuff->head + offset > pbuff->end)
		return -1;

	if (!*(pfcp_msg_decoder[pfcph->type].parse))
		return -1;

	/* Initialize all pointers to NULL */
	memset(arg, 0, pfcp_msg_decoder[pfcph->type].arg_size);

	/* Parse IEs */
	for (cp = pbuff->head + offset; cp < pbuff->end; cp += offset) {
		ie = (struct pfcp_ie *) cp;
		offset = sizeof(struct pfcp_ie) + ntohs(ie->length);

		/* bound checking */
		if (cp + offset > pbuff->end)
			continue;

		(*(pfcp_msg_decoder[pfcph->type].parse)) (cp, &mandatory_found, arg);
	}

	/* Validate mandatory IEs are present */
	if (mandatory_found != pfcp_msg_decoder[pfcph->type].mandatory_ie)
		return -1;

	return 0;
}
