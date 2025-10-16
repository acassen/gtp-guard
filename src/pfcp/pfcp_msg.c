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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "pfcp_msg.h"
#include "include/pfcp.h"
#include "include/pfcp_ie.h"
#include "include/pfcp_ie_group.h"
#include "pkt_buffer.h"
#include "mempool.h"

/*
 *	PFCP msg helpers
 */
int
pfcp_msg_hlen(struct pkt_buffer *pbuff)
{
	struct pfcp_hdr *hdr = (struct pfcp_hdr *) pbuff->head;

	return (hdr->s) ? PFCP_HEADER_LEN : PFCP_HEADER_LEN - PFCP_SEID_LEN;
}

int
pfcp_msg_reset_hlen(struct pkt_buffer *pbuff)
{
	struct pfcp_hdr *hdr = (struct pfcp_hdr *) pbuff->head;
	uint16_t len = PFCP_HEADER_LEN - 4;

	/* 3GPP.TS.29.244 7.2.2.4.1 */
	len -= (hdr->s) ? 0 : PFCP_SEID_LEN ;
	hdr->length = htons(len);
	pkt_buffer_set_data_pointer(pbuff, pfcp_msg_hlen(pbuff));
	pkt_buffer_set_end_pointer(pbuff, pfcp_msg_hlen(pbuff));
	return 0;
}


/*
 * 	PFCP Heartbeat Request
 */
static void
pfcp_parse_heartbeat_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_heartbeat_request *req = msg->heartbeat_request;;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->heartbeat_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_RECOVERY_TIME_STAMP:
		req->recovery_time_stamp = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_SOURCE_IP_ADDRESS:
		req->source_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP PFD Management Request
 */
static int
pfcp_parse_ie_pfd_context(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_pfd_context *pfd_context = n;

	switch (ie_type) {
	case PFCP_IE_PFD_CONTENTS:
		pfd_context->pfd_contents = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_application_id_pfds(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_application_id_pfds *pfds = n;
	struct pfcp_ie_pfd_context *pfd_context;

	switch (ie_type) {
	case PFCP_IE_APPLICATION_ID:
		pfds->application_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PFD_CONTEXT:
		pfd_context = mpool_zalloc(&msg->mp, sizeof(*pfd_context));
		if (!pfd_context)
			return -1;
		pfds->pfd_context = pfd_context;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_pfd_context, msg, pfd_context);
		break;

	default:
		break;
	}

	return 0;
}

static struct pfcp_ie_application_id_pfds *
pfcp_parse_application_id_pfds(struct pfcp_msg *msg, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	struct pfcp_ie_application_id_pfds *new;

	new = mpool_zalloc(&msg->mp, sizeof(*new));
	if (!new)
		return NULL;

	pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
			pfcp_parse_ie_application_id_pfds, msg, new);
	return new;
}

static void
pfcp_parse_pfd_management_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_pfd_management_request *req = msg->pfd_management_request;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->pfd_management_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_APPLICATION_ID_PFDS:
		req->application_id_pfds = pfcp_parse_application_id_pfds(msg, cp);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Association Setup Request
 */
static void
pfcp_parse_association_setup_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_association_setup_request *req = msg->association_setup_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

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
 * 	PFCP Association Update Request
 */
static void
pfcp_parse_association_update_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_association_update_request *req = msg->association_update_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_UP_FUNCTION_FEATURES:
		req->up_function_features = (struct pfcp_ie_up_function_features *)cp;
		break;

	case PFCP_IE_CP_FUNCTION_FEATURES:
		req->cp_function_features = (struct pfcp_ie_cp_function_features *)cp;
		break;

	case PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST:
		req->association_release_request = (struct pfcp_ie_pfcp_association_release_request *)cp;
		break;

	case PFCP_IE_GRACEFUL_RELEASE_PERIOD:
		req->graceful_release_period = (struct pfcp_ie_graceful_release_period *)cp;
		break;

	case PFCP_IE_PFCPAUREQ_FLAGS:
		req->pfcpaureq_flags = (struct pfcp_ie_pfcpaureq_flags *)cp;
		break;

	case PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS:
		req->alternative_smf_ip_address = (struct pfcp_ie_alternative_smf_ip_address *)cp;
		break;

	case PFCP_IE_SMF_SET_ID:
		req->smf_set_id = (struct pfcp_ie_smf_set_id *)cp;
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION:
		req->ue_ip_address_pool_information = (struct pfcp_ie_ue_ip_address_pool_information *)cp;
		break;

	case PFCP_IE_GTP_U_PATH_QOS_CONTROL_INFORMATION:
		req->gtp_u_path_qos_control_information = (struct pfcp_ie_gtp_u_path_qos_control_information *)cp;
		break;

	case PFCP_IE_UE_IP_ADDRESS_USAGE_INFORMATION:
		req->ue_ip_address_usage_information = (struct pfcp_ie_ue_ip_address_usage_information *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Association Release Request
 */
static void
pfcp_parse_association_release_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_association_release_request *req = msg->association_release_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		*mandatory |= (1 << 0);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Node Report Request
 */
static void
pfcp_parse_node_report_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_node_report_request *req = msg->node_report_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_NODE_REPORT_TYPE:
		req->node_report_type = (struct pfcp_ie_node_report_type *)cp;
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT:
		req->user_plane_path_failure_report = (struct pfcp_ie_user_plane_path_failure_report *)cp;
		break;

	case PFCP_IE_USER_PLANE_PATH_RECOVERY_REPORT:
		req->user_plane_path_recovery_report = (struct pfcp_ie_user_plane_path_recovery_report *)cp;
		break;

	case PFCP_IE_PEER_UP_RESTART_REPORT:
		req->peer_up_restart_report = (struct pfcp_ie_peer_up_restart_report *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Session Set Deletion Request
 */
static void
pfcp_parse_session_set_deletion_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_session_set_deletion_request *req = msg->session_set_deletion_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->sgw_c_fq_csid)
			req->sgw_c_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->pgw_c_fq_csid)
			req->pgw_c_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->sgw_u_fq_csid)
			req->sgw_u_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->pgw_u_fq_csid)
			req->pgw_u_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->twan_fq_csid)
			req->twan_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->epdg_fq_csid)
			req->epdg_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->mme_fq_csid)
			req->mme_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Session Establishment Request
 */
static int
pfcp_parse_ie_pdi(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_pdi *pdi = n;

	switch (ie_type) {
	case PFCP_IE_SOURCE_INTERFACE:
		pdi->source_interface = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_F_TEID:
		pdi->local_f_teid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_LOCAL_INGRESS_TUNNEL:
		pdi->local_ingress_tunnel = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pdi->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REDUNDANT_TRANSMISSION_DETECTION_PARAMETERS:
		pdi->redundant_transmission_detection_parameters = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS:
		pdi->ue_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		pdi->traffic_endpoint_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SDF_FILTER:
		pdi->sdf_filter = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_APPLICATION_ID:
		pdi->application_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION:
		pdi->ethernet_pdu_session_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ETHERNET_PACKET_FILTER:
		pdi->ethernet_packet_filter = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QFI:
		pdi->qfi = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTE:
		pdi->framed_route = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTING :
		pdi->framed_routing = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_IPV6_ROUTE:
		pdi->framed_ipv6_route = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		pdi->source_interface_type = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_AREA_SESSION_ID:
		pdi->area_session_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}


	return 0;
}

static int
pfcp_parse_ie_create_pdr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_pdr *create_pdr = n;
	struct pfcp_ie_pdi *pdi;

	switch (ie_type) {
	case PFCP_IE_PDR_ID:
		create_pdr->pdr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PRECEDENCE:
		create_pdr->precedence = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PDI: /* Grouped */
		pdi = mpool_zalloc(&msg->mp, sizeof(*pdi));
		if (!pdi)
			return -1;
		create_pdr->pdi = pdi;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_pdi, msg, pdi);
		break;

	case PFCP_IE_OUTER_HEADER_REMOVAL:
		create_pdr->outer_header_removal = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FAR_ID:
		create_pdr->far_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_URR_ID:
		create_pdr->urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QER_ID:
		create_pdr->qer_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MAR_ID:
		create_pdr->mar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ACTIVATE_PREDEFINED_RULES:
		create_pdr->activate_predefined_rules = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ACTIVATION_TIME:
		create_pdr->activation_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DEACTIVATION_TIME:
		create_pdr->deactivation_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY:
		create_pdr->ue_ip_address_pool_identity = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_RAT_TYPE:
		create_pdr->rat_type = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_fwd_params(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_forwarding_parameters *fwd_params = n;

	switch (ie_type) {
	case PFCP_IE_DESTINATION_INTERFACE:
		fwd_params->destination_interface = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		fwd_params->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REDIRECT_INFORMATION:
		fwd_params->redirect_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		fwd_params->outer_header_creation = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		fwd_params->transport_level_marking = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		fwd_params->forwarding_policy = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_HEADER_ENRICHMENT:
		fwd_params->header_enrichment = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		fwd_params->linked_traffic_endpoint_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PROXYING:
		fwd_params->proxying = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		fwd_params->destination_interface_type = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DATA_NETWORK_ACCESS_IDENTIFIER:
		fwd_params->data_network_access_identifier = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_IP_ADDRESS_AND_PORT_NUMBER_REPLACEMENT:
		fwd_params->ip_address_and_port_number_replacement = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_dup_params(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_duplicating_parameters *dup_params = n;

	switch (ie_type) {
	case PFCP_IE_DESTINATION_INTERFACE:
		dup_params->destination_interface = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		dup_params->outer_header_creation = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		dup_params->transport_level_marking = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		dup_params->forwarding_policy = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_create_far(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_far *create_far = n;
	struct pfcp_ie_forwarding_parameters *fwd_params;
	struct pfcp_ie_duplicating_parameters *dup_params;

	switch (ie_type) {
	case PFCP_IE_FAR_ID:
		create_far->far_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_APPLY_ACTION:
		create_far->apply_action = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FORWARDING_PARAMETERS: /* Grouped */
		fwd_params = mpool_zalloc(&msg->mp, sizeof(*fwd_params));
		if (!fwd_params)
			return -1;
		create_far->forwarding_parameters = fwd_params;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_fwd_params, msg, fwd_params);
		break;

	case PFCP_IE_DUPLICATING_PARAMETERS: /* Grouped */
		dup_params = mpool_zalloc(&msg->mp, sizeof(*dup_params));
		if (!dup_params)
			return -1;
		create_far->duplicating_parameters = dup_params;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_dup_params, msg, dup_params);
		break;

	case PFCP_IE_BAR_ID:
		create_far->bar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_aggregated_urrs(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_aggregated_urrs *aggregated_urrs = n;

	switch (ie_type) {
	case PFCP_IE_AGGREGATED_URR_ID:
		aggregated_urrs->aggregated_urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MULTIPLIER:
		aggregated_urrs->multiplier = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_additional_monitoring_time(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_additional_monitoring_time *additional_monitoring_time = n;

	switch (ie_type) {
	case PFCP_IE_MONITORING_TIME:
		additional_monitoring_time->monitoring_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD:
		additional_monitoring_time->subsequent_volume_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_THRESHOLD:
		additional_monitoring_time->subsequent_time_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_QUOTA:
		additional_monitoring_time->subsequent_volume_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_QUOTA:
		additional_monitoring_time->subsequent_time_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD:
		additional_monitoring_time->subsequent_event_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_QUOTA:
		additional_monitoring_time->subsequent_event_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_EVENT_THRESHOLD:
		additional_monitoring_time->event_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_EVENT_QUOTA:
		additional_monitoring_time->event_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_create_urr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_urr *create_urr = n;
	struct pfcp_ie_aggregated_urrs *aggregated_urrs;
	struct pfcp_ie_additional_monitoring_time *additional_monitoring_time;

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		create_urr->urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_METHOD:
		create_urr->measurement_method = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REPORTING_TRIGGERS:
		create_urr->reporting_triggers = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_PERIOD:
		create_urr->measurement_period = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_VOLUME_THRESHOLD:
		create_urr->volume_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_VOLUME_QUOTA:
		create_urr->volume_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_EVENT_THRESHOLD:
		create_urr->event_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_EVENT_QUOTA:
		create_urr->event_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_THRESHOLD:
		create_urr->time_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA:
		create_urr->time_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QUOTA_HOLDING_TIME:
		create_urr->quota_holding_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD:
		create_urr->dropped_dl_traffic_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QUOTA_VALIDITY_TIME:
		create_urr->quota_validity_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MONITORING_TIME:
		create_urr->monitoring_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD:
		create_urr->subsequent_volume_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_THRESHOLD:
		create_urr->subsequent_time_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_QUOTA:
		create_urr->subsequent_volume_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_QUOTA:
		create_urr->subsequent_time_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD:
		create_urr->subsequent_event_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_QUOTA:
		create_urr->subsequent_event_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_INACTIVITY_DETECTION_TIME:
		create_urr->inactivity_detection_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_LINKED_URR_ID:
		create_urr->linked_urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_INFORMATION:
		create_urr->measurement_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA_MECHANISM:
		create_urr->time_quota_mechanism = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_AGGREGATED_URRS: /* Grouped */
		aggregated_urrs = mpool_zalloc(&msg->mp, sizeof(*aggregated_urrs));
		if (!aggregated_urrs)
			return -1;
		create_urr->aggregated_urrs = aggregated_urrs;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_aggregated_urrs, msg, aggregated_urrs);
		break;

	case PFCP_IE_FAR_ID:
		create_urr->far_id_for_quota_action = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ETHERNET_INACTIVITY_TIMER:
		create_urr->ethernet_inactivity_timer = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ADDITIONAL_MONITORING_TIME: /* Grouped */
		additional_monitoring_time = mpool_zalloc(&msg->mp, sizeof(*additional_monitoring_time));
		if (!additional_monitoring_time)
			return -1;
		create_urr->additional_monitoring_time = additional_monitoring_time;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_additional_monitoring_time, msg, additional_monitoring_time);
		break;

	case PFCP_IE_NUMBER_OF_REPORTS:
		create_urr->number_of_reports = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_create_qer(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_qer *create_qer = n;

	switch (ie_type) {
	case PFCP_IE_QER_ID:
		create_qer->qer_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QER_CORRELATION_ID:
		create_qer->qer_correlation_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GATE_STATUS:
		create_qer->gate_status = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MBR:
		create_qer->maximum_bitrate = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GBR:
		create_qer->guaranteed_bitrate = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PACKET_RATE:
		create_qer->packet_rate = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PACKET_RATE_STATUS:
		create_qer->packet_rate_status = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DL_FLOW_LEVEL_MARKING:
		create_qer->dl_flow_level_marking = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QFI:
		create_qer->qos_flow_identifier = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_RQI:
		create_qer->reflective_qos = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PPI:
		create_qer->paging_policy_indicator = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_AVERAGING_WINDOW:
		create_qer->averaging_window = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QER_CONTROL_INDICATIONS:
		create_qer->qer_control_indications = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QER_INDICATIONS:
		create_qer->qer_indications = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_create_bar(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_bar *create_bar = n;

	switch (ie_type) {
	case PFCP_IE_BAR_ID:
		create_bar->bar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY:
		create_bar->downlink_data_notification_delay = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT:
		create_bar->suggested_buffering_packets_count = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MT_EDT_CONTROL_INFORMATION:
		create_bar->mt_edt_control_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DL_BUFFERING_DURATION:
		create_bar->dl_buffering_duration = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT:
		create_bar->dl_buffering_suggested_packet_count = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_create_traffic_endpoint(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_traffic_endpoint *create_traffic_endpoint = n;

	switch (ie_type) {
	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		create_traffic_endpoint->traffic_endpoint_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_F_TEID:
		create_traffic_endpoint->local_f_teid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		create_traffic_endpoint->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REDUNDANT_TRANSMISSION_DETECTION_PARAMETERS:
		create_traffic_endpoint->redundant_transmission_detection_parameters = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS:
		create_traffic_endpoint->ue_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION:
		create_traffic_endpoint->ethernet_pdu_session_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTE:
		create_traffic_endpoint->framed_route = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTING:
		create_traffic_endpoint->framed_routing = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_IPV6_ROUTE:
		create_traffic_endpoint->framed_ipv6_route = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QFI:
		create_traffic_endpoint->qfi = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		create_traffic_endpoint->source_interface_type = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_LOCAL_INGRESS_TUNNEL:
		create_traffic_endpoint->local_ingress_tunnel = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_AREA_SESSION_ID:
		create_traffic_endpoint->area_session_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_RAT_TYPE:
		create_traffic_endpoint->rat_type = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_create_mar(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_mar *create_mar = n;

	switch (ie_type) {
	case PFCP_IE_MAR_ID:
		create_mar->mar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_STEERING_FUNCTIONALITY:
		create_mar->steering_functionality = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_STEERING_MODE:
		create_mar->steering_mode = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_create_srr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_create_srr *create_srr = n;

	switch (ie_type) {
	case PFCP_IE_SRR_ID:
		create_srr->srr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static void
pfcp_parse_session_establishment_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_session_establishment_request *req = msg->session_establishment_request;
	struct pfcp_ie_create_pdr *new_pdr;
	struct pfcp_ie_create_far *new_far;
	struct pfcp_ie_create_urr *new_urr;
	struct pfcp_ie_create_qer *new_qer;
	struct pfcp_ie_create_bar *new_bar;
	struct pfcp_ie_create_traffic_endpoint *new_te;
	struct pfcp_ie_create_mar *new_mar;
	struct pfcp_ie_create_srr *new_srr;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->session_establishment_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_F_SEID:
		req->cp_f_seid = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_PDN_TYPE:
		req->pdn_type = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_USER_PLANE_INACTIVITY_TIMER:
		req->user_plane_inactivity_timer = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_USER_ID:
		req->user_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRACE_INFORMATION:
		req->trace_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_APN_DNN:
		req->apn_dnn = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->sgw_c_fq_csid)
			req->sgw_c_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->mme_fq_csid)
			req->mme_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->pgwc_smf_fq_csid)
			req->pgwc_smf_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->epdg_fq_csid)
			req->epdg_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->twan_fq_csid)
			req->twan_fq_csid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PFCPSEREQ_FLAGS:
		req->pfcpsereq_flags = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_CREATE_BRIDGE_ROUTER_INFO:
		req->create_bridge_router_info = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_RAT_TYPE:
		req->rat_type = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GROUP_ID:
		req->group_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_CREATE_PDR:
		new_pdr = mpool_realloc(&msg->mp, req, sizeof(*new_pdr) * (req->nr_create_pdr + 1));
		if (!new_pdr)
			return;
		req->create_pdr[req->nr_create_pdr++] = new_pdr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_pdr, msg, new_pdr);
		break;

	case PFCP_IE_CREATE_FAR:
		new_far = mpool_realloc(&msg->mp, req, sizeof(*new_far) * (req->nr_create_far + 1));
		if (!new_far)
			return;
		req->create_far[req->nr_create_far++] = new_far;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_far, msg, new_far);
		break;

	case PFCP_IE_CREATE_URR:
		new_urr = mpool_realloc(&msg->mp, req, sizeof(*new_urr) * (req->nr_create_urr + 1));
		if (!new_urr)
			return;
		req->create_urr[req->nr_create_urr++] = new_urr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_urr, msg, new_urr);
		break;

	case PFCP_IE_CREATE_QER:
		new_qer = mpool_realloc(&msg->mp, req, sizeof(*new_pdr) * (req->nr_create_qer + 1));
		if (!new_qer)
			return;
		req->create_qer[req->nr_create_qer++] = new_qer;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_qer, msg, new_qer);
		break;

	case PFCP_IE_CREATE_BAR:
		new_bar = mpool_realloc(&msg->mp, req, sizeof(*new_bar) * (req->nr_create_bar + 1));
		if (!new_bar)
			return;
		req->create_bar[req->nr_create_bar++] = new_bar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_bar, msg, new_bar);
		break;

	case PFCP_IE_CREATE_TRAFFIC_ENDPOINT:
		new_te = mpool_realloc(&msg->mp, req, sizeof(*new_te) * (req->nr_create_traffic_endpoint + 1));
		if (!new_te)
			return;
		req->create_traffic_endpoint[req->nr_create_traffic_endpoint++] = new_te;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_traffic_endpoint, msg, new_te);
		break;

	case PFCP_IE_CREATE_MAR:
		new_mar = mpool_realloc(&msg->mp, req, sizeof(*new_mar) * (req->nr_create_mar + 1));
		if (!new_mar)
			return;
		req->create_mar[req->nr_create_mar++] = new_mar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_mar, msg, new_mar);
		break;

	case PFCP_IE_CREATE_SRR:
		new_srr = mpool_realloc(&msg->mp, req, sizeof(*new_srr) * (req->nr_create_srr + 1));
		if (!new_srr)
			return;
		req->create_srr[req->nr_create_srr++] = new_srr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_srr, msg, new_srr);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Session Modification Request
 */
static void
pfcp_parse_session_modification_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_session_modification_request *req = msg->session_modification_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

	switch (ie_type) {
	case PFCP_IE_F_SEID:
		req->cp_f_seid = (struct pfcp_ie_f_seid *)cp;
		break;

	case PFCP_IE_REMOVE_PDR:
		req->remove_pdr = (struct pfcp_ie_remove_pdr *)cp;
		break;

	case PFCP_IE_REMOVE_FAR:
		req->remove_far = (struct pfcp_ie_remove_far *)cp;
		break;

	case PFCP_IE_REMOVE_URR:
		req->remove_urr = (struct pfcp_ie_remove_urr *)cp;
		break;

	case PFCP_IE_REMOVE_QER:
		req->remove_qer = (struct pfcp_ie_remove_qer *)cp;
		break;

	case PFCP_IE_REMOVE_BAR:
		req->remove_bar = (struct pfcp_ie_remove_bar *)cp;
		break;

	case PFCP_IE_REMOVE_TRAFFIC_ENDPOINT:
		req->remove_traffic_endpoint = (struct pfcp_ie_remove_traffic_endpoint *)cp;
		break;

	case PFCP_IE_CREATE_PDR:
		req->create_pdr = (struct pfcp_ie_create_pdr *)cp;
		break;

	case PFCP_IE_CREATE_FAR:
		req->create_far = (struct pfcp_ie_create_far *)cp;
		break;

	case PFCP_IE_CREATE_URR:
		req->create_urr = (struct pfcp_ie_create_urr *)cp;
		break;

	case PFCP_IE_CREATE_QER:
		req->create_qer = (struct pfcp_ie_create_qer *)cp;
		break;

	case PFCP_IE_CREATE_BAR:
		req->create_bar = (struct pfcp_ie_create_bar *)cp;
		break;

	case PFCP_IE_CREATE_TRAFFIC_ENDPOINT:
		req->create_traffic_endpoint = (struct pfcp_ie_create_traffic_endpoint *)cp;
		break;

	case PFCP_IE_UPDATE_PDR:
		req->update_pdr = (struct pfcp_ie_update_pdr *)cp;
		break;

	case PFCP_IE_UPDATE_FAR:
		req->update_far = (struct pfcp_ie_update_far *)cp;
		break;

	case PFCP_IE_UPDATE_URR:
		req->update_urr = (struct pfcp_ie_update_urr *)cp;
		break;

	case PFCP_IE_UPDATE_QER:
		req->update_qer = (struct pfcp_ie_update_qer *)cp;
		break;

	case PFCP_IE_UPDATE_BAR:
		req->update_bar = (struct pfcp_ie_update_bar *)cp;
		break;

	case PFCP_IE_UPDATE_TRAFFIC_ENDPOINT:
		req->update_traffic_endpoint = (struct pfcp_ie_update_traffic_endpoint *)cp;
		break;

	case PFCP_IE_PFCPSMREQ_FLAGS:
		req->pfcpsmreq_flags = (struct pfcp_ie_pfcpsmreq_flags *)cp;
		break;

	case PFCP_IE_QUERY_URR:
		req->query_urr = (struct pfcp_ie_query_urr *)cp;
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->pgw_c_fq_csid)
			req->pgw_c_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->sgw_c_fq_csid)
			req->sgw_c_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->mme_fq_csid)
			req->mme_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->epdg_fq_csid)
			req->epdg_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->twan_fq_csid)
			req->twan_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		break;

	case PFCP_IE_USER_PLANE_INACTIVITY_TIMER:
		req->user_plane_inactivity_timer = (struct pfcp_ie_user_plane_inactivity_timer *)cp;
		break;

	case PFCP_IE_QUERY_URR_REFERENCE:
		req->query_urr_reference = (struct pfcp_ie_query_urr_reference *)cp;
		break;

	case PFCP_IE_TRACE_INFORMATION:
		req->trace_information = (struct pfcp_ie_trace_information *)cp;
		break;

	case PFCP_IE_REMOVE_MAR:
		req->remove_mar = (struct pfcp_ie_remove_mar *)cp;
		break;

	case PFCP_IE_UPDATE_MAR:
		req->update_mar = (struct pfcp_ie_update_mar *)cp;
		break;

	case PFCP_IE_CREATE_MAR:
		req->create_mar = (struct pfcp_ie_create_mar *)cp;
		break;

	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		break;

	case PFCP_IE_REMOVE_SRR:
		req->remove_srr = (struct pfcp_ie_remove_srr *)cp;
		break;

	case PFCP_IE_CREATE_SRR:
		req->create_srr = (struct pfcp_ie_create_srr *)cp;
		break;

	case PFCP_IE_UPDATE_SRR:
		req->update_srr = (struct pfcp_ie_update_srr *)cp;
		break;

	case PFCP_IE_RAT_TYPE:
		req->rat_type = (struct pfcp_ie_rat_type *)cp;
		break;

	case PFCP_IE_GROUP_ID:
		req->group_id = (struct pfcp_ie_group_id *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Session Deletion Request
 */
static void
pfcp_parse_session_deletion_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_session_deletion_request *req = msg->session_deletion_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

	switch (ie_type) {
	case PFCP_IE_TL_CONTAINER:
		req->tl_container = (struct pfcp_ie_tl_container *)cp;
		break;

	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		break;

	case PFCP_IE_F_SEID:
		req->cp_f_seid = (struct pfcp_ie_f_seid *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Session Report Request
 */
static void
pfcp_parse_session_report_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_session_report_request *req = msg->session_report_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);

	switch (ie_type) {
	case PFCP_IE_REPORT_TYPE:
		req->report_type = (struct pfcp_ie_report_type *)cp;
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_DOWNLINK_DATA_REPORT:
		req->downlink_data_report = (struct pfcp_ie_downlink_data_report *)cp;
		break;

	case PFCP_IE_USAGE_REPORT:
		req->usage_report = (struct pfcp_ie_usage_report *)cp;
		break;

	case PFCP_IE_ERROR_INDICATION_REPORT:
		req->error_indication_report = (struct pfcp_ie_error_indication_report *)cp;
		break;

	case PFCP_IE_LOAD_CONTROL_INFORMATION:
		req->load_control_information = (struct pfcp_ie_load_control_information *)cp;
		break;

	case PFCP_IE_OVERLOAD_CONTROL_INFORMATION:
		req->overload_control_information = (struct pfcp_ie_overload_control_information *)cp;
		break;

	case PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION:
		req->additional_usage_reports_information = (struct pfcp_ie_additional_usage_reports_information *)cp;
		break;

	case PFCP_IE_PFCPSRREQ_FLAGS:
		req->pfcpsrreq_flags = (struct pfcp_ie_pfcpsrreq_flags *)cp;
		break;

	case PFCP_IE_F_SEID:
		req->old_cp_f_seid = (struct pfcp_ie_f_seid *)cp;
		break;

	case PFCP_IE_PACKET_RATE_STATUS_REPORT:
		req->packet_rate_status_report = (struct pfcp_ie_packet_rate_status_report *)cp;
		break;

	case PFCP_IE_SESSION_REPORT:
		req->session_report = (struct pfcp_ie_session_report *)cp;
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
	void (*parse) (struct pfcp_msg *, const uint8_t *, int *);
} pfcp_msg_decoder[1 << 8] = {
	[PFCP_HEARTBEAT_REQUEST]		= { 1,
						    pfcp_parse_heartbeat_request
						  },
	[PFCP_PFD_MANAGEMENT_REQUEST]		= { 0,
						    pfcp_parse_pfd_management_request
						  },
	[PFCP_ASSOCIATION_SETUP_REQUEST]	= { 3,
						    pfcp_parse_association_setup_request
						  },
	[PFCP_ASSOCIATION_UPDATE_REQUEST]	= { 1,
						    pfcp_parse_association_update_request
						  },
	[PFCP_ASSOCIATION_RELEASE_REQUEST]	= { 1,
						    pfcp_parse_association_release_request
						  },
	[PFCP_NODE_REPORT_REQUEST]		= { 3,
						    pfcp_parse_node_report_request
						  },
	[PFCP_SESSION_SET_DELETION_REQUEST]	= { 1,
						    pfcp_parse_session_set_deletion_request
						  },
	[PFCP_SESSION_ESTABLISHMENT_REQUEST]	= { 3,
						    pfcp_parse_session_establishment_request
						  },
	[PFCP_SESSION_MODIFICATION_REQUEST]	= { 0,
						    pfcp_parse_session_modification_request
						  },
	[PFCP_SESSION_DELETION_REQUEST]		= { 0,
						    pfcp_parse_session_deletion_request
						  },
	[PFCP_SESSION_REPORT_REQUEST]		= { 1,
						    pfcp_parse_session_report_request
						  },
};

/*
 *	Parse PFCP message.
 *
 * We are parsing first level since most of IEs are Optional and there is
 * no need to waste time parsing something that is potentially not useful.
 * Parse recursion over set of IEs will be made during message handling.
 */
int
pfcp_msg_parse(struct pfcp_msg *msg, struct pkt_buffer *pbuff)
{
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	int mandatory_found = 0;
	struct pfcp_ie *ie;
	const uint8_t *cp;
	size_t offset;

	if (!pbuff || !msg)
		return -1;

	/* Parse PFCP header */
	offset = pfcp_msg_hlen(pbuff);
	if (pbuff->head + offset > pbuff->end)
		return -1;

	if (!*(pfcp_msg_decoder[pfcph->type].parse))
		return -1;

	/* Parse IEs */
	for (cp = pbuff->head + offset; cp < pbuff->end; cp += offset) {
		ie = (struct pfcp_ie *) cp;
		offset = sizeof(struct pfcp_ie) + ntohs(ie->length);

		/* bound checking */
		if (cp + offset > pbuff->end)
			continue;

		(*(pfcp_msg_decoder[pfcph->type].parse)) (msg, cp, &mandatory_found);
	}

	/* Validate mandatory IEs are present */
	if (mandatory_found != pfcp_msg_decoder[pfcph->type].mandatory_ie)
		return -1;

	return 0;
}

struct pfcp_msg *
pfcp_msg_alloc(void)
{
	struct pfcp_msg *new;
	int err;

	new = mpool_new(sizeof(*new));
	if (!new)
		return NULL;

	err = mpool_prealloc(&new->mp, MPOOL_DEFAULT_SIZE);
	if (err) {
		free(new);
		return NULL;
	}

	return new;
}

void
pfcp_msg_free(struct pfcp_msg *msg)
{
	mpool_release(&msg->mp);
}
