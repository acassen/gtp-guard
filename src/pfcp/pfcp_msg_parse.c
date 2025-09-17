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
 * 	PFCP Heartbeat Request
 */
static void
pfcp_parse_heartbeat_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_heartbeat_request *req = (struct pfcp_heartbeat_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

	switch (ie_type) {
	case PFCP_IE_RECOVERY_TIME_STAMP:
		req->recovery_time_stamp = (struct pfcp_ie_recovery_time_stamp *)cp;
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_SOURCE_IP_ADDRESS:
		req->source_ip_address = (struct pfcp_ie_source_ip_address *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP PFD Management Request
 */
static void
pfcp_parse_pfd_management_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_pfd_management_request *req = (struct pfcp_pfd_management_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		break;

	case PFCP_IE_APPLICATION_ID_PFDS:
		req->application_id_pfds = (struct pfcp_ie_application_id_pfds *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Association Setup Request
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
 * 	PFCP Association Update Request
 */
static void
pfcp_parse_association_update_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_association_update_request *req = (struct pfcp_association_update_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

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
pfcp_parse_association_release_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_association_release_request *req = (struct pfcp_association_release_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

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
pfcp_parse_node_report_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_node_report_request *req = (struct pfcp_node_report_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

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
pfcp_parse_session_set_deletion_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_session_set_deletion_request *req = (struct pfcp_session_set_deletion_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

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
static void
pfcp_parse_session_establishment_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_session_establishment_request *req = (struct pfcp_session_establishment_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = (struct pfcp_ie_node_id *)cp;
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_F_SEID:
		req->cp_f_seid = (struct pfcp_ie_f_seid *)cp;
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_PDN_TYPE:
		req->pdn_type = (struct pfcp_ie_pdn_type *)cp;
		break;

	case PFCP_IE_USER_PLANE_INACTIVITY_TIMER:
		req->user_plane_inactivity_timer = (struct pfcp_ie_user_plane_inactivity_timer *)cp;
		break;

	case PFCP_IE_USER_ID:
		req->user_id = (struct pfcp_ie_user_id *)cp;
		break;

	case PFCP_IE_TRACE_INFORMATION:
		req->trace_information = (struct pfcp_ie_trace_information *)cp;
		break;

	case PFCP_IE_APN_DNN:
		req->apn_dnn = (struct pfcp_ie_apn_dnn *)cp;
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->sgw_c_fq_csid)
			req->sgw_c_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->mme_fq_csid)
			req->mme_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->pgwc_smf_fq_csid)
			req->pgwc_smf_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->epdg_fq_csid)
			req->epdg_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		else if (!req->twan_fq_csid)
			req->twan_fq_csid = (struct pfcp_ie_fq_csid *)cp;
		break;

	case PFCP_IE_PFCPSEREQ_FLAGS:
		req->pfcpsereq_flags = (struct pfcp_ie_pfcpsereq_flags *)cp;
		break;

	case PFCP_IE_CREATE_BRIDGE_ROUTER_INFO:
		req->create_bridge_router_info = (struct pfcp_ie_create_bridge_router_info *)cp;
		break;

	case PFCP_IE_RAT_TYPE:
		req->rat_type = (struct pfcp_ie_rat_type *)cp;
		break;

	case PFCP_IE_GROUP_ID:
		req->group_id = (struct pfcp_ie_group_id *)cp;
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

	case PFCP_IE_CREATE_MAR:
		req->create_mar = (struct pfcp_ie_create_mar *)cp;
		break;

	case PFCP_IE_CREATE_SRR:
		req->create_srr = (struct pfcp_ie_create_srr *)cp;
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Session Modification Request
 */
static void
pfcp_parse_session_modification_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_session_modification_request *req = (struct pfcp_session_modification_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

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
pfcp_parse_session_deletion_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_session_deletion_request *req = (struct pfcp_session_deletion_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

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
pfcp_parse_session_report_request(const uint8_t *cp, int *mandatory, void *arg)
{
	struct pfcp_session_report_request *req = (struct pfcp_session_report_request *) arg;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = be16toh(ie->type);

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
	size_t arg_size;
	void (*parse) (const uint8_t *, int *, void *);
} pfcp_msg_decoder[1 << 8] = {
	[PFCP_HEARTBEAT_REQUEST]		= { 1,
						    sizeof(struct pfcp_heartbeat_request),
						    pfcp_parse_heartbeat_request
						  },
	[PFCP_PFD_MANAGEMENT_REQUEST]		= { 0,
						    sizeof(struct pfcp_pfd_management_request),
						    pfcp_parse_pfd_management_request
						  },
	[PFCP_ASSOCIATION_SETUP_REQUEST]	= { 3,
						    sizeof(struct pfcp_association_setup_request),
						    pfcp_parse_association_setup_request
						  },
	[PFCP_ASSOCIATION_UPDATE_REQUEST]	= { 1,
						    sizeof(struct pfcp_association_update_request),
						    pfcp_parse_association_update_request
						  },
	[PFCP_ASSOCIATION_RELEASE_REQUEST]	= { 1,
						    sizeof(struct pfcp_association_release_request),
						    pfcp_parse_association_release_request
						  },
	[PFCP_NODE_REPORT_REQUEST]		= { 3,
						    sizeof(struct pfcp_node_report_request),
						    pfcp_parse_node_report_request
						  },
	[PFCP_SESSION_SET_DELETION_REQUEST]	= { 1,
						    sizeof(struct pfcp_session_set_deletion_request),
						    pfcp_parse_session_set_deletion_request
						  },
	[PFCP_SESSION_ESTABLISHMENT_REQUEST]	= { 3,
						    sizeof(struct pfcp_session_establishment_request),
						    pfcp_parse_session_establishment_request
						  },
	[PFCP_SESSION_MODIFICATION_REQUEST]	= { 0,
						    sizeof(struct pfcp_session_modification_request),
						    pfcp_parse_session_modification_request
						  },
	[PFCP_SESSION_DELETION_REQUEST]		= { 0,
						    sizeof(struct pfcp_session_deletion_request),
						    pfcp_parse_session_deletion_request
						  },
	[PFCP_SESSION_REPORT_REQUEST]		= { 1,
						    sizeof(struct pfcp_session_report_request),
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
