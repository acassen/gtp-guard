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
static int
pfcp_parse_ie_session_retention_information(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_session_retention_information *session_retention_info = n;

	switch (ie_type) {
	case PFCP_IE_CP_PFCP_ENTITY_IP_ADDRESS:
		session_retention_info->cp_pfcp_entity_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_ue_ip_address_pool_information(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_ue_ip_address_pool_information *ue_ip_address_pool_info = n;

	switch (ie_type) {
	case PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY:
		ue_ip_address_pool_info->ue_ip_address_pool_identity = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		ue_ip_address_pool_info->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_S_NSSAI:
		ue_ip_address_pool_info->s_nssai = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_IP_VERSION:
		ue_ip_address_pool_info->ip_version = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static void
pfcp_parse_association_setup_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_association_setup_request *req = msg->association_setup_request;
	struct pfcp_ie_session_retention_information *session_retention_info;
	struct pfcp_ie_ue_ip_address_pool_information *ue_ip_address_pool_info;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->association_setup_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_RECOVERY_TIME_STAMP:
		req->recovery_time_stamp = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_UP_FUNCTION_FEATURES:
		req->up_function_features = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_CP_FUNCTION_FEATURES:
		req->cp_function_features = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION:
		req->user_plane_ip_resource_info = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS:
		req->alternative_smf_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SMF_SET_ID:
		req->smf_set_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PFCPASREQ_FLAGS:
		req->pfcpasreq_flags = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SESSION_RETENTION_INFORMATION: /* Grouped */
		session_retention_info = mpool_zalloc(&msg->mp, sizeof(*session_retention_info));
		if (!session_retention_info)
			return;
		req->session_retention_info = session_retention_info;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_session_retention_information, msg, session_retention_info);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION: /* Grouped */
		ue_ip_address_pool_info = mpool_zalloc(&msg->mp, sizeof(*ue_ip_address_pool_info));
		if (!ue_ip_address_pool_info)
			return;
		req->ue_ip_address_pool_info = ue_ip_address_pool_info;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_ue_ip_address_pool_information, msg, ue_ip_address_pool_info);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Association Update Request
 */
static int
pfcp_parse_ie_gtp_u_path_qos_control_information(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_gtp_u_path_qos_control_information *qos_control_info = n;

	switch (ie_type) {
	case PFCP_IE_REMOTE_GTP_U_PEER:
		qos_control_info->remote_gtp_u_peer = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GTP_U_PATH_INTERFACE_TYPE:
		qos_control_info->gtp_u_path_interface_type = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QOS_REPORT_TRIGGER:
		qos_control_info->qos_report_trigger = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		qos_control_info->transport_level_marking = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_PERIOD:
		qos_control_info->measurement_period = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MT_EDT_CONTROL_INFORMATION:
		qos_control_info->mt_edt_control_information = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_ue_ip_address_usage_information(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_ue_ip_address_usage_information *usage_info = n;

	switch (ie_type) {
	case PFCP_IE_SEQUENCE_NUMBER:
		usage_info->sequence_number = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_METRIC:
		usage_info->number_of_ue_ip_addresses = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_VALIDITY_TIMER:
		usage_info->validity_timer = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NUMBER_OF_UE_IP_ADDRESSES:
		usage_info->number_of_ue_ip_addresses_ie = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		usage_info->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY:
		usage_info->ue_ip_address_pool_identity = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_S_NSSAI:
		usage_info->s_nssai = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static void
pfcp_parse_association_update_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_association_update_request *req = msg->association_update_request;
	struct pfcp_ie_ue_ip_address_pool_information *ue_ip_address_pool_info;
	struct pfcp_ie_gtp_u_path_qos_control_information *qos_control_info;
	struct pfcp_ie_ue_ip_address_usage_information *usage_info;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->association_update_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_UP_FUNCTION_FEATURES:
		req->up_function_features = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_CP_FUNCTION_FEATURES:
		req->cp_function_features = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST:
		req->association_release_request = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GRACEFUL_RELEASE_PERIOD:
		req->graceful_release_period = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PFCPAUREQ_FLAGS:
		req->pfcpaureq_flags = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS:
		req->alternative_smf_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SMF_SET_ID:
		req->smf_set_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION: /* Grouped */
		ue_ip_address_pool_info = mpool_zalloc(&msg->mp, sizeof(*ue_ip_address_pool_info));
		if (!ue_ip_address_pool_info)
			return;
		req->ue_ip_address_pool_information = ue_ip_address_pool_info;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_ue_ip_address_pool_information, msg, ue_ip_address_pool_info);
		break;

	case PFCP_IE_GTP_U_PATH_QOS_CONTROL_INFORMATION: /* Grouped */
		qos_control_info = mpool_zalloc(&msg->mp, sizeof(*qos_control_info));
		if (!qos_control_info)
			return;
		req->gtp_u_path_qos_control_information = qos_control_info;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_gtp_u_path_qos_control_information, msg, qos_control_info);
		break;

	case PFCP_IE_UE_IP_ADDRESS_USAGE_INFORMATION: /* Grouped */
		usage_info = mpool_zalloc(&msg->mp, sizeof(*usage_info));
		if (!usage_info)
			return;
		req->ue_ip_address_usage_information = usage_info;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_ue_ip_address_usage_information, msg, usage_info);
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
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_association_release_request *req = msg->association_release_request;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->association_release_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Node Report Request
 */
static int
pfcp_parse_ie_user_plane_path_failure_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_user_plane_path_failure_report *failure_report = n;

	switch (ie_type) {
	case PFCP_IE_REMOTE_GTP_U_PEER:
		failure_report->remote_gtp_u_peer = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_user_plane_path_recovery_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_user_plane_path_recovery_report *recovery_report = n;

	switch (ie_type) {
	case PFCP_IE_REMOTE_GTP_U_PEER:
		recovery_report->remote_gtp_u_peer = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_peer_up_restart_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_peer_up_restart_report *restart_report = n;

	switch (ie_type) {
	case PFCP_IE_REMOTE_GTP_U_PEER:
		restart_report->remote_gtp_u_peer = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static void
pfcp_parse_node_report_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_node_report_request *req = msg->node_report_request;
	struct pfcp_ie_user_plane_path_failure_report *failure_report;
	struct pfcp_ie_user_plane_path_recovery_report *recovery_report;
	struct pfcp_ie_peer_up_restart_report *restart_report;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->node_report_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_NODE_REPORT_TYPE:
		req->node_report_type = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT: /* Grouped */
		failure_report = mpool_zalloc(&msg->mp, sizeof(*failure_report));
		if (!failure_report)
			return;
		req->user_plane_path_failure_report = failure_report;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_user_plane_path_failure_report, msg, failure_report);
		break;

	case PFCP_IE_USER_PLANE_PATH_RECOVERY_REPORT: /* Grouped */
		recovery_report = mpool_zalloc(&msg->mp, sizeof(*recovery_report));
		if (!recovery_report)
			return;
		req->user_plane_path_recovery_report = recovery_report;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_user_plane_path_recovery_report, msg, recovery_report);
		break;

	case PFCP_IE_PEER_UP_RESTART_REPORT: /* Grouped */
		restart_report = mpool_zalloc(&msg->mp, sizeof(*restart_report));
		if (!restart_report)
			return;
		req->peer_up_restart_report = restart_report;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_peer_up_restart_report, msg, restart_report);
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
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_session_set_deletion_request *req = msg->session_set_deletion_request;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->session_set_deletion_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->sgw_c_fq_csid)
			req->sgw_c_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->pgw_c_fq_csid)
			req->pgw_c_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->sgw_u_fq_csid)
			req->sgw_u_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->pgw_u_fq_csid)
			req->pgw_u_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->twan_fq_csid)
			req->twan_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->epdg_fq_csid)
			req->epdg_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->mme_fq_csid)
			req->mme_fq_csid = mpool_memdup(&msg->mp, cp, size);
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
static int
pfcp_parse_ie_remove_pdr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_pdr *remove_pdr = n;

	switch (ie_type) {
	case PFCP_IE_PDR_ID:
		remove_pdr->pdr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_remove_far(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_far *remove_far = n;

	switch (ie_type) {
	case PFCP_IE_FAR_ID:
		remove_far->far_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_remove_urr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_urr *remove_urr = n;

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		remove_urr->urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_remove_qer(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_qer *remove_qer = n;

	switch (ie_type) {
	case PFCP_IE_QER_ID:
		remove_qer->qer_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_remove_bar(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_bar *remove_bar = n;

	switch (ie_type) {
	case PFCP_IE_BAR_ID:
		remove_bar->bar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_remove_traffic_endpoint(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_traffic_endpoint *remove_traffic_endpoint = n;

	switch (ie_type) {
	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		remove_traffic_endpoint->traffic_endpoint_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_remove_mar(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_mar *remove_mar = n;

	switch (ie_type) {
	case PFCP_IE_MAR_ID:
		remove_mar->mar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_remove_srr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_remove_srr *remove_srr = n;

	switch (ie_type) {
	case PFCP_IE_SRR_ID:
		remove_srr->srr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_pdr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_pdr *update_pdr = n;
	struct pfcp_ie_pdi *pdi;

	switch (ie_type) {
	case PFCP_IE_PDR_ID:
		update_pdr->pdr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_REMOVAL:
		update_pdr->outer_header_removal = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PRECEDENCE:
		update_pdr->precedence = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PDI: /* Grouped */
		pdi = mpool_zalloc(&msg->mp, sizeof(*pdi));
		if (!pdi)
			return -1;
		update_pdr->pdi = pdi;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_pdi, msg, pdi);
		break;

	case PFCP_IE_FAR_ID:
		update_pdr->far_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_URR_ID:
		update_pdr->urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QER_ID:
		update_pdr->qer_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ACTIVATE_PREDEFINED_RULES:
		update_pdr->activate_predefined_rules = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DEACTIVATE_PREDEFINED_RULES:
		update_pdr->deactivate_predefined_rules = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ACTIVATION_TIME:
		update_pdr->activation_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DEACTIVATION_TIME:
		update_pdr->deactivation_time = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_fwd_params(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_forwarding_parameters *update_fwd_params = n;

	switch (ie_type) {
	case PFCP_IE_DESTINATION_INTERFACE:
		update_fwd_params->destination_interface = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		update_fwd_params->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REDIRECT_INFORMATION:
		update_fwd_params->redirect_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		update_fwd_params->outer_header_creation = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		update_fwd_params->transport_level_marking = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		update_fwd_params->forwarding_policy = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_HEADER_ENRICHMENT:
		update_fwd_params->header_enrichment = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		update_fwd_params->linked_traffic_endpoint_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PFCPSMREQ_FLAGS:
		update_fwd_params->pfcpsm_req_flags = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		update_fwd_params->destination_interface_type = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_dup_params(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_duplicating_parameters *update_dup_params = n;

	switch (ie_type) {
	case PFCP_IE_DESTINATION_INTERFACE:
		update_dup_params->destination_interface = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		update_dup_params->outer_header_creation = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		update_dup_params->transport_level_marking = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		update_dup_params->forwarding_policy = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_far(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_far *update_far = n;
	struct pfcp_ie_update_forwarding_parameters *update_fwd_params;
	struct pfcp_ie_update_duplicating_parameters *update_dup_params;

	switch (ie_type) {
	case PFCP_IE_FAR_ID:
		update_far->far_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_APPLY_ACTION:
		update_far->apply_action = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UPDATE_FORWARDING_PARAMETERS: /* Grouped */
		update_fwd_params = mpool_zalloc(&msg->mp, sizeof(*update_fwd_params));
		if (!update_fwd_params)
			return -1;
		update_far->update_forwarding_parameters = update_fwd_params;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_fwd_params, msg, update_fwd_params);
		break;

	case PFCP_IE_UPDATE_DUPLICATING_PARAMETERS: /* Grouped */
		update_dup_params = mpool_zalloc(&msg->mp, sizeof(*update_dup_params));
		if (!update_dup_params)
			return -1;
		update_far->update_duplicating_parameters = update_dup_params;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_dup_params, msg, update_dup_params);
		break;

	case PFCP_IE_BAR_ID:
		update_far->bar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_urr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_urr *update_urr = n;
	struct pfcp_ie_aggregated_urrs *aggregated_urrs;
	struct pfcp_ie_additional_monitoring_time *additional_monitoring_time;

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		update_urr->urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_METHOD:
		update_urr->measurement_method = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REPORTING_TRIGGERS:
		update_urr->reporting_triggers = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_PERIOD:
		update_urr->measurement_period = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_VOLUME_THRESHOLD:
		update_urr->volume_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_VOLUME_QUOTA:
		update_urr->volume_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_THRESHOLD:
		update_urr->time_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA:
		update_urr->time_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_EVENT_THRESHOLD:
		update_urr->event_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_EVENT_QUOTA:
		update_urr->event_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QUOTA_HOLDING_TIME:
		update_urr->quota_holding_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD:
		update_urr->dropped_dl_traffic_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QUOTA_VALIDITY_TIME:
		update_urr->quota_validity_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MONITORING_TIME:
		update_urr->monitoring_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD:
		update_urr->subsequent_volume_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_THRESHOLD:
		update_urr->subsequent_time_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_QUOTA:
		update_urr->subsequent_volume_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_QUOTA:
		update_urr->subsequent_time_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD:
		update_urr->subsequent_event_threshold = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_QUOTA:
		update_urr->subsequent_event_quota = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_INACTIVITY_DETECTION_TIME:
		update_urr->inactivity_detection_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_LINKED_URR_ID:
		update_urr->linked_urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_INFORMATION:
		update_urr->measurement_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA_MECHANISM:
		update_urr->time_quota_mechanism = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_AGGREGATED_URRS: /* Grouped */
		aggregated_urrs = mpool_zalloc(&msg->mp, sizeof(*aggregated_urrs));
		if (!aggregated_urrs)
			return -1;
		update_urr->aggregated_urrs = aggregated_urrs;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_aggregated_urrs, msg, aggregated_urrs);
		break;

	case PFCP_IE_FAR_ID:
		update_urr->far_id_for_quota_action = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ETHERNET_INACTIVITY_TIMER:
		update_urr->ethernet_inactivity_timer = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ADDITIONAL_MONITORING_TIME: /* Grouped */
		additional_monitoring_time = mpool_zalloc(&msg->mp, sizeof(*additional_monitoring_time));
		if (!additional_monitoring_time)
			return -1;
		update_urr->additional_monitoring_time = additional_monitoring_time;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_additional_monitoring_time, msg, additional_monitoring_time);
		break;

	case PFCP_IE_NUMBER_OF_REPORTS:
		update_urr->number_of_reports = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_qer(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_qer *update_qer = n;

	switch (ie_type) {
	case PFCP_IE_QER_ID:
		update_qer->qer_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QER_CORRELATION_ID:
		update_qer->qer_correlation_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GATE_STATUS:
		update_qer->gate_status = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_MBR:
		update_qer->maximum_bitrate = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GBR:
		update_qer->guaranteed_bitrate = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PACKET_RATE:
		update_qer->packet_rate = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DL_FLOW_LEVEL_MARKING:
		update_qer->dl_flow_level_marking = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QFI:
		update_qer->qos_flow_identifier = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_RQI:
		update_qer->reflective_qos = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PPI:
		update_qer->paging_policy_indicator = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_AVERAGING_WINDOW:
		update_qer->averaging_window = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QER_CONTROL_INDICATIONS:
		update_qer->qer_control_indications = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_bar(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_bar *update_bar = n;

	switch (ie_type) {
	case PFCP_IE_BAR_ID:
		update_bar->bar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY:
		update_bar->downlink_data_notification_delay = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT:
		update_bar->suggested_buffering_packets_count = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_traffic_endpoint(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_traffic_endpoint *update_traffic_endpoint = n;

	switch (ie_type) {
	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		update_traffic_endpoint->traffic_endpoint_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_F_TEID:
		update_traffic_endpoint->local_f_teid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		update_traffic_endpoint->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS:
		update_traffic_endpoint->ue_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTE:
		update_traffic_endpoint->framed_route = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTING:
		update_traffic_endpoint->framed_routing = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_FRAMED_IPV6_ROUTE:
		update_traffic_endpoint->framed_ipv6_route = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QFI:
		update_traffic_endpoint->qfi = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_mar(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_mar *update_mar = n;

	switch (ie_type) {
	case PFCP_IE_MAR_ID:
		update_mar->mar_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_STEERING_FUNCTIONALITY:
		update_mar->steering_functionality = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_STEERING_MODE:
		update_mar->steering_mode = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_update_srr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_update_srr *update_srr = n;

	switch (ie_type) {
	case PFCP_IE_SRR_ID:
		update_srr->srr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ACCESS_AVAILABILITY_INFORMATION:
		update_srr->access_availability_control_information = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_query_urr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_query_urr *query_urr = n;

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		query_urr->urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static void
pfcp_parse_session_modification_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_session_modification_request *req = msg->session_modification_request;
	struct pfcp_ie_remove_pdr *new_remove_pdr;
	struct pfcp_ie_remove_far *new_remove_far;
	struct pfcp_ie_remove_urr *new_remove_urr;
	struct pfcp_ie_remove_qer *new_remove_qer;
	struct pfcp_ie_remove_bar *new_remove_bar;
	struct pfcp_ie_remove_traffic_endpoint *new_remove_te;
	struct pfcp_ie_remove_mar *new_remove_mar;
	struct pfcp_ie_remove_srr *new_remove_srr;
	struct pfcp_ie_create_pdr *new_create_pdr;
	struct pfcp_ie_create_far *new_create_far;
	struct pfcp_ie_create_urr *new_create_urr;
	struct pfcp_ie_create_qer *new_create_qer;
	struct pfcp_ie_create_bar *new_create_bar;
	struct pfcp_ie_create_traffic_endpoint *new_create_te;
	struct pfcp_ie_create_mar *new_create_mar;
	struct pfcp_ie_create_srr *new_create_srr;
	struct pfcp_ie_update_pdr *new_update_pdr;
	struct pfcp_ie_update_far *new_update_far;
	struct pfcp_ie_update_urr *new_update_urr;
	struct pfcp_ie_update_qer *new_update_qer;
	struct pfcp_ie_update_bar *new_update_bar;
	struct pfcp_ie_update_traffic_endpoint *new_update_te;
	struct pfcp_ie_update_mar *new_update_mar;
	struct pfcp_ie_update_srr *new_update_srr;
	struct pfcp_ie_query_urr *new_query_urr;

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->session_modification_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_F_SEID:
		req->cp_f_seid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REMOVE_PDR:
		new_remove_pdr = mpool_zalloc(&msg->mp, sizeof(*new_remove_pdr));
		if (!new_remove_pdr)
			return;
		req->remove_pdr = new_remove_pdr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_pdr, msg, new_remove_pdr);
		break;

	case PFCP_IE_REMOVE_FAR:
		new_remove_far = mpool_zalloc(&msg->mp, sizeof(*new_remove_far));
		if (!new_remove_far)
			return;
		req->remove_far = new_remove_far;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_far, msg, new_remove_far);
		break;

	case PFCP_IE_REMOVE_URR:
		new_remove_urr = mpool_zalloc(&msg->mp, sizeof(*new_remove_urr));
		if (!new_remove_urr)
			return;
		req->remove_urr = new_remove_urr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_urr, msg, new_remove_urr);
		break;

	case PFCP_IE_REMOVE_QER:
		new_remove_qer = mpool_zalloc(&msg->mp, sizeof(*new_remove_qer));
		if (!new_remove_qer)
			return;
		req->remove_qer = new_remove_qer;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_qer, msg, new_remove_qer);
		break;

	case PFCP_IE_REMOVE_BAR:
		new_remove_bar = mpool_zalloc(&msg->mp, sizeof(*new_remove_bar));
		if (!new_remove_bar)
			return;
		req->remove_bar = new_remove_bar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_bar, msg, new_remove_bar);
		break;

	case PFCP_IE_REMOVE_TRAFFIC_ENDPOINT:
		new_remove_te = mpool_zalloc(&msg->mp, sizeof(*new_remove_te));
		if (!new_remove_te)
			return;
		req->remove_traffic_endpoint = new_remove_te;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_traffic_endpoint, msg, new_remove_te);
		break;

	case PFCP_IE_CREATE_PDR:
		new_create_pdr = mpool_zalloc(&msg->mp, sizeof(*new_create_pdr));
		if (!new_create_pdr)
			return;
		req->create_pdr = new_create_pdr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_pdr, msg, new_create_pdr);
		break;

	case PFCP_IE_CREATE_FAR:
		new_create_far = mpool_zalloc(&msg->mp, sizeof(*new_create_far));
		if (!new_create_far)
			return;
		req->create_far = new_create_far;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_far, msg, new_create_far);
		break;

	case PFCP_IE_CREATE_URR:
		new_create_urr = mpool_zalloc(&msg->mp, sizeof(*new_create_urr));
		if (!new_create_urr)
			return;
		req->create_urr = new_create_urr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_urr, msg, new_create_urr);
		break;

	case PFCP_IE_CREATE_QER:
		new_create_qer = mpool_zalloc(&msg->mp, sizeof(*new_create_qer));
		if (!new_create_qer)
			return;
		req->create_qer = new_create_qer;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_qer, msg, new_create_qer);
		break;

	case PFCP_IE_CREATE_BAR:
		new_create_bar = mpool_zalloc(&msg->mp, sizeof(*new_create_bar));
		if (!new_create_bar)
			return;
		req->create_bar = new_create_bar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_bar, msg, new_create_bar);
		break;

	case PFCP_IE_CREATE_TRAFFIC_ENDPOINT:
		new_create_te = mpool_zalloc(&msg->mp, sizeof(*new_create_te));
		if (!new_create_te)
			return;
		req->create_traffic_endpoint = new_create_te;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_traffic_endpoint, msg, new_create_te);
		break;

	case PFCP_IE_UPDATE_PDR:
		new_update_pdr = mpool_zalloc(&msg->mp, sizeof(*new_update_pdr));
		if (!new_update_pdr)
			return;
		req->update_pdr = new_update_pdr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_pdr, msg, new_update_pdr);
		break;

	case PFCP_IE_UPDATE_FAR:
		new_update_far = mpool_zalloc(&msg->mp, sizeof(*new_update_far));
		if (!new_update_far)
			return;
		req->update_far = new_update_far;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_far, msg, new_update_far);
		break;

	case PFCP_IE_UPDATE_URR:
		new_update_urr = mpool_zalloc(&msg->mp, sizeof(*new_update_urr));
		if (!new_update_urr)
			return;
		req->update_urr = new_update_urr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_urr, msg, new_update_urr);
		break;

	case PFCP_IE_UPDATE_QER:
		new_update_qer = mpool_zalloc(&msg->mp, sizeof(*new_update_qer));
		if (!new_update_qer)
			return;
		req->update_qer = new_update_qer;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_qer, msg, new_update_qer);
		break;

	case PFCP_IE_UPDATE_BAR:
		new_update_bar = mpool_zalloc(&msg->mp, sizeof(*new_update_bar));
		if (!new_update_bar)
			return;
		req->update_bar = new_update_bar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_bar, msg, new_update_bar);
		break;

	case PFCP_IE_UPDATE_TRAFFIC_ENDPOINT:
		new_update_te = mpool_zalloc(&msg->mp, sizeof(*new_update_te));
		if (!new_update_te)
			return;
		req->update_traffic_endpoint = new_update_te;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_traffic_endpoint, msg, new_update_te);
		break;

	case PFCP_IE_PFCPSMREQ_FLAGS:
		req->pfcpsmreq_flags = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QUERY_URR:
		new_query_urr = mpool_zalloc(&msg->mp, sizeof(*new_query_urr));
		if (!new_query_urr)
			return;
		req->query_urr = new_query_urr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_query_urr, msg, new_query_urr);
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->pgw_c_fq_csid)
			req->pgw_c_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->sgw_c_fq_csid)
			req->sgw_c_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->mme_fq_csid)
			req->mme_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->epdg_fq_csid)
			req->epdg_fq_csid = mpool_memdup(&msg->mp, cp, size);
		else if (!req->twan_fq_csid)
			req->twan_fq_csid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_USER_PLANE_INACTIVITY_TIMER:
		req->user_plane_inactivity_timer = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QUERY_URR_REFERENCE:
		req->query_urr_reference = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TRACE_INFORMATION:
		req->trace_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REMOVE_MAR:
		new_remove_mar = mpool_zalloc(&msg->mp, sizeof(*new_remove_mar));
		if (!new_remove_mar)
			return;
		req->remove_mar = new_remove_mar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_mar, msg, new_remove_mar);
		break;

	case PFCP_IE_UPDATE_MAR:
		new_update_mar = mpool_zalloc(&msg->mp, sizeof(*new_update_mar));
		if (!new_update_mar)
			return;
		req->update_mar = new_update_mar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_mar, msg, new_update_mar);
		break;

	case PFCP_IE_CREATE_MAR:
		new_create_mar = mpool_zalloc(&msg->mp, sizeof(*new_create_mar));
		if (!new_create_mar)
			return;
		req->create_mar = new_create_mar;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_mar, msg, new_create_mar);
		break;

	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_REMOVE_SRR:
		new_remove_srr = mpool_zalloc(&msg->mp, sizeof(*new_remove_srr));
		if (!new_remove_srr)
			return;
		req->remove_srr = new_remove_srr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_remove_srr, msg, new_remove_srr);
		break;

	case PFCP_IE_CREATE_SRR:
		new_create_srr = mpool_zalloc(&msg->mp, sizeof(*new_create_srr));
		if (!new_create_srr)
			return;
		req->create_srr = new_create_srr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_create_srr, msg, new_create_srr);
		break;

	case PFCP_IE_UPDATE_SRR:
		new_update_srr = mpool_zalloc(&msg->mp, sizeof(*new_update_srr));
		if (!new_update_srr)
			return;
		req->update_srr = new_update_srr;
		pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
				pfcp_parse_ie_update_srr, msg, new_update_srr);
		break;

	case PFCP_IE_RAT_TYPE:
		req->rat_type = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_GROUP_ID:
		req->group_id = mpool_memdup(&msg->mp, cp, size);
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
	size_t size = sizeof(*ie) + ntohs(ie->length);

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->session_deletion_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_TL_CONTAINER:
		req->tl_container = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NODE_ID:
		req->node_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_F_SEID:
		req->cp_f_seid = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Session Report Request
 */
static int
pfcp_parse_ie_downlink_data_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_downlink_data_report *report = n;

	switch (ie_type) {
	case PFCP_IE_PDR_ID:
		report->pdr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION:
		report->downlink_data_service_information = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_usage_report_srr(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_usage_report *report = n;

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		report->urr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_UR_SEQN:
		report->ur_seqn = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_USAGE_REPORT_TRIGGER:
		report->usage_report_trigger = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_START_TIME:
		report->start_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_END_TIME:
		report->end_time = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_VOLUME_MEASUREMENT:
		report->volume_measurement = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_DURATION_MEASUREMENT:
		report->duration_measurement = mpool_memdup(&msg->mp, cp, size);
		break;
#if 0
	case PFCP_IE_APPLICATION_DETECTION_INFORMATION:
		report->application_detection_information = mpool_memdup(&msg->mp, cp, size);
		break;
#endif
	case PFCP_IE_UE_IP_ADDRESS:
		report->ue_ip_address = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		report->network_instance = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_OF_FIRST_PACKET:
		report->time_of_first_packet = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_OF_LAST_PACKET:
		report->time_of_last_packet = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_USAGE_INFORMATION:
		report->usage_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_QUERY_URR_REFERENCE:
		report->query_urr_reference = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIME_STAMP:
		report->event_time_stamp = mpool_memdup(&msg->mp, cp, size);
		break;
#if 0
	case PFCP_IE_ETHERNET_TRAFFIC_INFORMATION:
		report->ethernet_traffic_information = mpool_memdup(&msg->mp, cp, size);
		break;
#endif
	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_error_indication_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_error_indication_report *report = n;

	switch (ie_type) {
	case PFCP_IE_F_TEID:
		report->remote_f_teid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PDR_ID:
		report->pdr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_load_control_information(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_load_control_information *info = n;

	switch (ie_type) {
	case PFCP_IE_SEQUENCE_NUMBER:
		info->load_control_sequence_number = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_METRIC:
		info->load_metric = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_overload_control_information(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_overload_control_information *info = n;

	switch (ie_type) {
	case PFCP_IE_SEQUENCE_NUMBER:
		info->overload_control_sequence_number = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_METRIC:
		info->overload_reduction_metric = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_TIMER:
		info->period_of_validity = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_OCI_FLAGS:
		info->overload_control_information_flags = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_packet_rate_status_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_packet_rate_status_report *report = n;

	switch (ie_type) {
	case PFCP_IE_QER_ID:
		report->qer_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PACKET_RATE_STATUS:
		report->packet_rate_status = mpool_memdup(&msg->mp, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_session_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_session_report *report = n;

	switch (ie_type) {
	case PFCP_IE_SRR_ID:
		report->srr_id = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_ACCESS_AVAILABILITY_REPORT:
		report->access_availability_report = mpool_memdup(&msg->mp, cp, size);
		break;
#if 0
	case PFCP_IE_QOS_MONITORING_REPORT:
		report->qos_monitoring_report = mpool_memdup(&msg->mp, cp, size);
		break;
#endif
	default:
		break;
	}

	return 0;
}


static void
pfcp_parse_session_report_request(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_session_report_request *req = msg->session_report_request;
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->session_report_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_REPORT_TYPE:
		req->report_type = mpool_memdup(&msg->mp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_DOWNLINK_DATA_REPORT:
		req->downlink_data_report = mpool_zalloc(&msg->mp, sizeof(*req->downlink_data_report));
		if (req->downlink_data_report)
			pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
					pfcp_parse_ie_downlink_data_report,
					msg, req->downlink_data_report);
		break;

	case PFCP_IE_USAGE_REPORT:
		req->usage_report = mpool_zalloc(&msg->mp, sizeof(*req->usage_report));
		if (req->usage_report)
			pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
					pfcp_parse_ie_usage_report_srr,
					msg, req->usage_report);
		break;

	case PFCP_IE_ERROR_INDICATION_REPORT:
		req->error_indication_report = mpool_zalloc(&msg->mp, sizeof(*req->error_indication_report));
		if (req->error_indication_report)
			pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
					pfcp_parse_ie_error_indication_report,
					msg, req->error_indication_report);
		break;

	case PFCP_IE_LOAD_CONTROL_INFORMATION:
		req->load_control_information = mpool_zalloc(&msg->mp, sizeof(*req->load_control_information));
		if (req->load_control_information)
			pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
					pfcp_parse_ie_load_control_information,
					msg, req->load_control_information);
		break;

	case PFCP_IE_OVERLOAD_CONTROL_INFORMATION:
		req->overload_control_information = mpool_zalloc(&msg->mp, sizeof(*req->overload_control_information));
		if (req->overload_control_information)
			pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
					pfcp_parse_ie_overload_control_information,
					msg, req->overload_control_information);
		break;

	case PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION:
		req->additional_usage_reports_information = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PFCPSRREQ_FLAGS:
		req->pfcpsrreq_flags = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_F_SEID:
		req->old_cp_f_seid = mpool_memdup(&msg->mp, cp, size);
		break;

	case PFCP_IE_PACKET_RATE_STATUS_REPORT:
		req->packet_rate_status_report = mpool_zalloc(&msg->mp, sizeof(*req->packet_rate_status_report));
		if (req->packet_rate_status_report)
			pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
					pfcp_parse_ie_packet_rate_status_report,
					msg, req->packet_rate_status_report);
		break;

	case PFCP_IE_SESSION_REPORT:
		req->session_report = mpool_zalloc(&msg->mp, sizeof(*req->session_report));
		if (req->session_report)
			pfcp_ie_foreach(cp + sizeof(*ie), ntohs(ie->length),
					pfcp_parse_ie_session_report,
					msg, req->session_report);
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
