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

static int
pfcp_parse_add_ie_to_array(struct pfcp_msg *msg, const uint8_t *buffer,
			   void ***ie_array, int *nr_ie, size_t ie_size,
			   int (*ie_parse) (void *, void *, const uint8_t *))
{
	struct pfcp_ie *ie = (struct pfcp_ie *) buffer;
	void **array;
	void *new_ie;

	new_ie = mpool_zalloc(&msg->mp, ie_size);
	if (!new_ie)
		return -1;

	array = mpool_realloc(&msg->mp, *ie_array, (*nr_ie + 1) * sizeof(void *));
	if (!array) {
		mpool_free(new_ie);
		return -1;
	}
	*ie_array = array;

	array[(*nr_ie)++] = new_ie;
	if (ie_parse)
		pfcp_ie_foreach(buffer + sizeof(*ie), ntohs(ie->length),
				ie_parse, msg, new_ie);
	return 0;
}

static int
pfcp_parse_alloc_ie(struct pfcp_msg *msg, const uint8_t *buffer,
		    void **ie_dst, size_t ie_size,
		    int (*ie_parse) (void *, void *, const uint8_t *))
{
	struct pfcp_ie *ie = (struct pfcp_ie *) buffer;

	/* preserve previously parsed ie */
	if (*ie_dst)
		return -1;

	*ie_dst = mpool_zalloc(&msg->mp, ie_size);
	if (!*ie_dst)
		return -1;

	pfcp_ie_foreach(buffer + sizeof(*ie), ntohs(ie->length),
			ie_parse, msg, *ie_dst);
	return 0;
}

static void
pfcp_msg_alloc_scheme(struct pfcp_msg *msg, void **dst, const uint8_t *src, size_t ssize)
{
	switch (msg->m_scheme) {
	case PFCP_MSG_MEM_DUP:
		*dst = mpool_memdup(&msg->mp, src, ssize);
		break;

	case PFCP_MSG_MEM_ZEROCOPY:
		*dst = (void *)src;
		break;

	default:
		break;
	}
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
		pfcp_msg_alloc_scheme(msg, (void **)&req->recovery_time_stamp, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_SOURCE_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->source_ip_address, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&pfd_context->pfd_contents, cp, size);
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

	switch (ie_type) {
	case PFCP_IE_APPLICATION_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&pfds->application_id, cp, size);
		break;

	case PFCP_IE_PFD_CONTEXT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&pfds->pfd_context,
				    sizeof(*pfds->pfd_context), pfcp_parse_ie_pfd_context);
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
	if (new)
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
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&session_retention_info->cp_pfcp_entity_ip_address, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&ue_ip_address_pool_info->ue_ip_address_pool_identity, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&ue_ip_address_pool_info->network_instance, cp, size);
		break;

	case PFCP_IE_S_NSSAI:
		pfcp_msg_alloc_scheme(msg, (void **)&ue_ip_address_pool_info->s_nssai, cp, size);
		break;

	case PFCP_IE_IP_VERSION:
		pfcp_msg_alloc_scheme(msg, (void **)&ue_ip_address_pool_info->ip_version, cp, size);
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

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->association_setup_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_RECOVERY_TIME_STAMP:
		pfcp_msg_alloc_scheme(msg, (void **)&req->recovery_time_stamp, cp, size);
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_UP_FUNCTION_FEATURES:
		pfcp_msg_alloc_scheme(msg, (void **)&req->up_function_features, cp, size);
		break;

	case PFCP_IE_CP_FUNCTION_FEATURES:
		pfcp_msg_alloc_scheme(msg, (void **)&req->cp_function_features, cp, size);
		break;

	case PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&req->user_plane_ip_resource_info, cp, size);
		break;

	case PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->alternative_smf_ip_address, cp, size);
		break;

	case PFCP_IE_SMF_SET_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->smf_set_id, cp, size);
		break;

	case PFCP_IE_PFCPASREQ_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->pfcpasreq_flags, cp, size);
		break;

	case PFCP_IE_SESSION_RETENTION_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->session_retention_info,
				    sizeof(*req->session_retention_info), pfcp_parse_ie_session_retention_information);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->ue_ip_address_pool_info,
				    sizeof(*req->ue_ip_address_pool_info), pfcp_parse_ie_ue_ip_address_pool_information);
		break;

	default:
		break;
	}
}

/*
 * 	PFCP Association Setup Response
 */
static void
pfcp_parse_association_setup_response(struct pfcp_msg *msg, const uint8_t *cp, int *mandatory)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_association_setup_response *rsp = msg->association_setup_response;

	if (!rsp) {
		rsp = mpool_zalloc(&msg->mp, sizeof(*rsp));
		if (!rsp)
			return;
		msg->association_setup_response = rsp;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->node_id, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_CAUSE:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->cause, cp, size);
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_RECOVERY_TIME_STAMP:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->recovery_time_stamp, cp, size);
		*mandatory |= (1 << 2);
		break;

	case PFCP_IE_UP_FUNCTION_FEATURES:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->up_function_features, cp, size);
		break;

	case PFCP_IE_CP_FUNCTION_FEATURES:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->cp_function_features, cp, size);
		break;

	case PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->user_plane_ip_resource_info, cp, size);
		break;

	case PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->alternative_smf_ip_address, cp, size);
		break;

	case PFCP_IE_SMF_SET_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->smf_set_id, cp, size);
		break;

	case PFCP_IE_PFCPASRSP_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->pfcpasrsp_flags, cp, size);
		break;

	case PFCP_IE_NF_INSTANCE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&rsp->upf_instance_id, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&rsp->ue_ip_address_pool_info,
				    sizeof(*rsp->ue_ip_address_pool_info),
				    pfcp_parse_ie_ue_ip_address_pool_information);
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
		pfcp_msg_alloc_scheme(msg, (void **)&qos_control_info->remote_gtp_u_peer, cp, size);
		break;

	case PFCP_IE_GTP_U_PATH_INTERFACE_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&qos_control_info->gtp_u_path_interface_type, cp, size);
		break;

	case PFCP_IE_QOS_REPORT_TRIGGER:
		pfcp_msg_alloc_scheme(msg, (void **)&qos_control_info->qos_report_trigger, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		pfcp_msg_alloc_scheme(msg, (void **)&qos_control_info->transport_level_marking, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_PERIOD:
		pfcp_msg_alloc_scheme(msg, (void **)&qos_control_info->measurement_period, cp, size);
		break;

	case PFCP_IE_MT_EDT_CONTROL_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&qos_control_info->mt_edt_control_information, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&usage_info->sequence_number, cp, size);
		break;

	case PFCP_IE_METRIC:
		pfcp_msg_alloc_scheme(msg, (void **)&usage_info->number_of_ue_ip_addresses, cp, size);
		break;

	case PFCP_IE_VALIDITY_TIMER:
		pfcp_msg_alloc_scheme(msg, (void **)&usage_info->validity_timer, cp, size);
		break;

	case PFCP_IE_NUMBER_OF_UE_IP_ADDRESSES:
		pfcp_msg_alloc_scheme(msg, (void **)&usage_info->number_of_ue_ip_addresses_ie, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&usage_info->network_instance, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY:
		pfcp_msg_alloc_scheme(msg, (void **)&usage_info->ue_ip_address_pool_identity, cp, size);
		break;

	case PFCP_IE_S_NSSAI:
		pfcp_msg_alloc_scheme(msg, (void **)&usage_info->s_nssai, cp, size);
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
	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->association_update_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_UP_FUNCTION_FEATURES:
		pfcp_msg_alloc_scheme(msg, (void **)&req->up_function_features, cp, size);
		break;

	case PFCP_IE_CP_FUNCTION_FEATURES:
		pfcp_msg_alloc_scheme(msg, (void **)&req->cp_function_features, cp, size);
		break;

	case PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST:
		pfcp_msg_alloc_scheme(msg, (void **)&req->association_release_request, cp, size);
		break;

	case PFCP_IE_GRACEFUL_RELEASE_PERIOD:
		pfcp_msg_alloc_scheme(msg, (void **)&req->graceful_release_period, cp, size);
		break;

	case PFCP_IE_PFCPAUREQ_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->pfcpaureq_flags, cp, size);
		break;

	case PFCP_IE_ALTERNATIVE_SMF_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->alternative_smf_ip_address, cp, size);
		break;

	case PFCP_IE_SMF_SET_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->smf_set_id, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->ue_ip_address_pool_information,
				    sizeof(*req->ue_ip_address_pool_information), pfcp_parse_ie_ue_ip_address_pool_information);
		break;

	case PFCP_IE_GTP_U_PATH_QOS_CONTROL_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->gtp_u_path_qos_control_information,
				    sizeof(*req->gtp_u_path_qos_control_information), pfcp_parse_ie_gtp_u_path_qos_control_information);
		break;

	case PFCP_IE_UE_IP_ADDRESS_USAGE_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->ue_ip_address_usage_information,
				    sizeof(*req->ue_ip_address_usage_information), pfcp_parse_ie_ue_ip_address_usage_information);
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
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&failure_report->remote_gtp_u_peer, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&recovery_report->remote_gtp_u_peer, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&restart_report->remote_gtp_u_peer, cp, size);
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

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->node_report_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_NODE_REPORT_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_report_type, cp, size);
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->user_plane_path_failure_report,
				    sizeof(*req->user_plane_path_failure_report), pfcp_parse_ie_user_plane_path_failure_report);
		break;

	case PFCP_IE_USER_PLANE_PATH_RECOVERY_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->user_plane_path_recovery_report,
				    sizeof(*req->user_plane_path_recovery_report), pfcp_parse_ie_user_plane_path_recovery_report);
		break;

	case PFCP_IE_PEER_UP_RESTART_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->peer_up_restart_report,
				    sizeof(*req->peer_up_restart_report), pfcp_parse_ie_peer_up_restart_report);
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
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->sgw_c_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->sgw_c_fq_csid, cp, size);
		else if (!req->pgw_c_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->pgw_c_fq_csid, cp, size);
		else if (!req->sgw_u_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->sgw_u_fq_csid, cp, size);
		else if (!req->pgw_u_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->pgw_u_fq_csid, cp, size);
		else if (!req->twan_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->twan_fq_csid, cp, size);
		else if (!req->epdg_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->epdg_fq_csid, cp, size);
		else if (!req->mme_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->mme_fq_csid, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->source_interface, cp, size);
		break;

	case PFCP_IE_F_TEID:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->local_f_teid, cp, size);
		break;

	case PFCP_IE_LOCAL_INGRESS_TUNNEL:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->local_ingress_tunnel, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->network_instance, cp, size);
		break;

	case PFCP_IE_REDUNDANT_TRANSMISSION_DETECTION_PARAMETERS:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->redundant_transmission_detection_parameters, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->ue_ip_address, cp, size);
		break;

	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->traffic_endpoint_id, cp, size);
		break;

	case PFCP_IE_SDF_FILTER:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->sdf_filter, cp, size);
		break;

	case PFCP_IE_APPLICATION_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->application_id, cp, size);
		break;

	case PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->ethernet_pdu_session_information, cp, size);
		break;

	case PFCP_IE_ETHERNET_PACKET_FILTER:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->ethernet_packet_filter, cp, size);
		break;

	case PFCP_IE_QFI:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->qfi, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTE:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->framed_route, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTING :
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->framed_routing, cp, size);
		break;

	case PFCP_IE_FRAMED_IPV6_ROUTE:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->framed_ipv6_route, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->source_interface_type, cp, size);
		break;

	case PFCP_IE_AREA_SESSION_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&pdi->area_session_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->pdr_id, cp, size);
		break;

	case PFCP_IE_PRECEDENCE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->precedence, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->outer_header_removal, cp, size);
		break;

	case PFCP_IE_FAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->far_id, cp, size);
		break;

	case PFCP_IE_URR_ID:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&create_pdr->urr_id,
					   &create_pdr->nr_urr_id,
					   sizeof(struct pfcp_ie_urr_id), NULL);
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->urr_id[create_pdr->nr_urr_id - 1],
				      cp, size);
		break;

	case PFCP_IE_QER_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->qer_id, cp, size);
		break;

	case PFCP_IE_MAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->mar_id, cp, size);
		break;

	case PFCP_IE_ACTIVATE_PREDEFINED_RULES:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->activate_predefined_rules, cp, size);
		break;

	case PFCP_IE_ACTIVATION_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->activation_time, cp, size);
		break;

	case PFCP_IE_DEACTIVATION_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->deactivation_time, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS_POOL_IDENTITY:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->ue_ip_address_pool_identity, cp, size);
		break;

	case PFCP_IE_RAT_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_pdr->rat_type, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->destination_interface, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->network_instance, cp, size);
		break;

	case PFCP_IE_REDIRECT_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->redirect_information, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->outer_header_creation, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->transport_level_marking, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->forwarding_policy, cp, size);
		break;

	case PFCP_IE_HEADER_ENRICHMENT:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->header_enrichment, cp, size);
		break;

	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->linked_traffic_endpoint_id, cp, size);
		break;

	case PFCP_IE_PROXYING:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->proxying, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->destination_interface_type, cp, size);
		break;

	case PFCP_IE_DATA_NETWORK_ACCESS_IDENTIFIER:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->data_network_access_identifier, cp, size);
		break;

	case PFCP_IE_IP_ADDRESS_AND_PORT_NUMBER_REPLACEMENT:
		pfcp_msg_alloc_scheme(msg, (void **)&fwd_params->ip_address_and_port_number_replacement, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&dup_params->destination_interface, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		pfcp_msg_alloc_scheme(msg, (void **)&dup_params->outer_header_creation, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		pfcp_msg_alloc_scheme(msg, (void **)&dup_params->transport_level_marking, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		pfcp_msg_alloc_scheme(msg, (void **)&dup_params->forwarding_policy, cp, size);
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

	switch (ie_type) {
	case PFCP_IE_FAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_far->far_id, cp, size);
		break;

	case PFCP_IE_APPLY_ACTION:
		pfcp_msg_alloc_scheme(msg, (void **)&create_far->apply_action, cp, size);
		break;

	case PFCP_IE_FORWARDING_PARAMETERS:
		pfcp_parse_alloc_ie(msg, cp, (void **)&create_far->forwarding_parameters,
				    sizeof(*create_far->forwarding_parameters), pfcp_parse_ie_fwd_params);
		break;

	case PFCP_IE_DUPLICATING_PARAMETERS:
		pfcp_parse_alloc_ie(msg, cp, (void **)&create_far->duplicating_parameters,
				    sizeof(*create_far->duplicating_parameters), pfcp_parse_ie_dup_params);
		break;

	case PFCP_IE_BAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_far->bar_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&aggregated_urrs->aggregated_urr_id, cp, size);
		break;

	case PFCP_IE_MULTIPLIER:
		pfcp_msg_alloc_scheme(msg, (void **)&aggregated_urrs->multiplier, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->monitoring_time, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->subsequent_volume_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->subsequent_time_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->subsequent_volume_quota, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->subsequent_time_quota, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->subsequent_event_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->subsequent_event_quota, cp, size);
		break;

	case PFCP_IE_EVENT_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->event_threshold, cp, size);
		break;

	case PFCP_IE_EVENT_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&additional_monitoring_time->event_quota, cp, size);
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

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->urr_id, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_METHOD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->measurement_method, cp, size);
		break;

	case PFCP_IE_REPORTING_TRIGGERS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->reporting_triggers, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_PERIOD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->measurement_period, cp, size);
		break;

	case PFCP_IE_VOLUME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->volume_threshold, cp, size);
		break;

	case PFCP_IE_VOLUME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->volume_quota, cp, size);
		break;

	case PFCP_IE_EVENT_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->event_threshold, cp, size);
		break;

	case PFCP_IE_EVENT_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->event_quota, cp, size);
		break;

	case PFCP_IE_TIME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->time_threshold, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->time_quota, cp, size);
		break;

	case PFCP_IE_QUOTA_HOLDING_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->quota_holding_time, cp, size);
		break;

	case PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->dropped_dl_traffic_threshold, cp, size);
		break;

	case PFCP_IE_QUOTA_VALIDITY_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->quota_validity_time, cp, size);
		break;

	case PFCP_IE_MONITORING_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->monitoring_time, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->subsequent_volume_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->subsequent_time_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->subsequent_volume_quota, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->subsequent_time_quota, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->subsequent_event_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->subsequent_event_quota, cp, size);
		break;

	case PFCP_IE_INACTIVITY_DETECTION_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->inactivity_detection_time, cp, size);
		break;

	case PFCP_IE_LINKED_URR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->linked_urr_id, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->measurement_information, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA_MECHANISM:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->time_quota_mechanism, cp, size);
		break;

	case PFCP_IE_AGGREGATED_URRS:
		pfcp_parse_alloc_ie(msg, cp, (void **)&create_urr->aggregated_urrs,
				    sizeof(*create_urr->aggregated_urrs), pfcp_parse_ie_aggregated_urrs);
		break;

	case PFCP_IE_FAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->far_id_for_quota_action, cp, size);
		break;

	case PFCP_IE_ETHERNET_INACTIVITY_TIMER:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->ethernet_inactivity_timer, cp, size);
		break;

	case PFCP_IE_ADDITIONAL_MONITORING_TIME:
		pfcp_parse_alloc_ie(msg, cp, (void **)&create_urr->additional_monitoring_time,
				    sizeof(*create_urr->additional_monitoring_time), pfcp_parse_ie_additional_monitoring_time);
		break;

	case PFCP_IE_NUMBER_OF_REPORTS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_urr->number_of_reports, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->qer_id, cp, size);
		break;

	case PFCP_IE_QER_CORRELATION_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->qer_correlation_id, cp, size);
		break;

	case PFCP_IE_GATE_STATUS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->gate_status, cp, size);
		break;

	case PFCP_IE_MBR:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->maximum_bitrate, cp, size);
		break;

	case PFCP_IE_GBR:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->guaranteed_bitrate, cp, size);
		break;

	case PFCP_IE_PACKET_RATE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->packet_rate, cp, size);
		break;

	case PFCP_IE_PACKET_RATE_STATUS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->packet_rate_status, cp, size);
		break;

	case PFCP_IE_DL_FLOW_LEVEL_MARKING:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->dl_flow_level_marking, cp, size);
		break;

	case PFCP_IE_QFI:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->qos_flow_identifier, cp, size);
		break;

	case PFCP_IE_RQI:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->reflective_qos, cp, size);
		break;

	case PFCP_IE_PPI:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->paging_policy_indicator, cp, size);
		break;

	case PFCP_IE_AVERAGING_WINDOW:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->averaging_window, cp, size);
		break;

	case PFCP_IE_QER_CONTROL_INDICATIONS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->qer_control_indications, cp, size);
		break;

	case PFCP_IE_QER_INDICATIONS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_qer->qer_indications, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&create_bar->bar_id, cp, size);
		break;

	case PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY:
		pfcp_msg_alloc_scheme(msg, (void **)&create_bar->downlink_data_notification_delay, cp, size);
		break;

	case PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT:
		pfcp_msg_alloc_scheme(msg, (void **)&create_bar->suggested_buffering_packets_count, cp, size);
		break;

	case PFCP_IE_MT_EDT_CONTROL_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&create_bar->mt_edt_control_information, cp, size);
		break;

	case PFCP_IE_DL_BUFFERING_DURATION:
		pfcp_msg_alloc_scheme(msg, (void **)&create_bar->dl_buffering_duration, cp, size);
		break;

	case PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT:
		pfcp_msg_alloc_scheme(msg, (void **)&create_bar->dl_buffering_suggested_packet_count, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->traffic_endpoint_id, cp, size);
		break;

	case PFCP_IE_F_TEID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->local_f_teid, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->network_instance, cp, size);
		break;

	case PFCP_IE_REDUNDANT_TRANSMISSION_DETECTION_PARAMETERS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->redundant_transmission_detection_parameters, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->ue_ip_address, cp, size);
		break;

	case PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->ethernet_pdu_session_information, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->framed_route, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTING:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->framed_routing, cp, size);
		break;

	case PFCP_IE_FRAMED_IPV6_ROUTE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->framed_ipv6_route, cp, size);
		break;

	case PFCP_IE_QFI:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->qfi, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->source_interface_type, cp, size);
		break;

	case PFCP_IE_LOCAL_INGRESS_TUNNEL:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->local_ingress_tunnel, cp, size);
		break;

	case PFCP_IE_AREA_SESSION_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->area_session_id, cp, size);
		break;

	case PFCP_IE_RAT_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_traffic_endpoint->rat_type, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&create_mar->mar_id, cp, size);
		break;

	case PFCP_IE_STEERING_FUNCTIONALITY:
		pfcp_msg_alloc_scheme(msg, (void **)&create_mar->steering_functionality, cp, size);
		break;

	case PFCP_IE_STEERING_MODE:
		pfcp_msg_alloc_scheme(msg, (void **)&create_mar->steering_mode, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&create_srr->srr_id, cp, size);
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

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->session_establishment_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_NODE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_F_SEID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->cp_f_seid, cp, size);
		*mandatory |= (1 << 1);
		break;

	case PFCP_IE_PDN_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&req->pdn_type, cp, size);
		break;

	case PFCP_IE_USER_PLANE_INACTIVITY_TIMER:
		pfcp_msg_alloc_scheme(msg, (void **)&req->user_plane_inactivity_timer, cp, size);
		break;

	case PFCP_IE_USER_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->user_id, cp, size);
		break;

	case PFCP_IE_TRACE_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&req->trace_information, cp, size);
		break;

	case PFCP_IE_APN_DNN:
		pfcp_msg_alloc_scheme(msg, (void **)&req->apn_dnn, cp, size);
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->sgw_c_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->sgw_c_fq_csid, cp, size);
		else if (!req->mme_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->mme_fq_csid, cp, size);
		else if (!req->pgwc_smf_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->pgwc_smf_fq_csid, cp, size);
		else if (!req->epdg_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->epdg_fq_csid, cp, size);
		else if (!req->twan_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->twan_fq_csid, cp, size);
		break;

	case PFCP_IE_PFCPSEREQ_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->pfcpsereq_flags, cp, size);
		break;

	case PFCP_IE_CREATE_BRIDGE_ROUTER_INFO:
		pfcp_msg_alloc_scheme(msg, (void **)&req->create_bridge_router_info, cp, size);
		break;

	case PFCP_IE_RAT_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&req->rat_type, cp, size);
		break;

	case PFCP_IE_GROUP_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->group_id, cp, size);
		break;

	case PFCP_IE_CREATE_PDR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_pdr, &req->nr_create_pdr,
					   sizeof(struct pfcp_ie_create_pdr), pfcp_parse_ie_create_pdr);
		break;

	case PFCP_IE_CREATE_FAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_far, &req->nr_create_far,
					   sizeof(struct pfcp_ie_create_far), pfcp_parse_ie_create_far);
		break;

	case PFCP_IE_CREATE_URR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_urr, &req->nr_create_urr,
					   sizeof(struct pfcp_ie_create_urr), pfcp_parse_ie_create_urr);
		break;

	case PFCP_IE_CREATE_QER:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_qer, &req->nr_create_qer,
					   sizeof(struct pfcp_ie_create_qer), pfcp_parse_ie_create_qer);
		break;

	case PFCP_IE_CREATE_BAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_bar, &req->nr_create_bar,
					   sizeof(struct pfcp_ie_create_bar), pfcp_parse_ie_create_bar);
		break;

	case PFCP_IE_CREATE_TRAFFIC_ENDPOINT:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_traffic_endpoint,
					   &req->nr_create_traffic_endpoint,
					   sizeof(struct pfcp_ie_create_traffic_endpoint),
					   pfcp_parse_ie_create_traffic_endpoint);
		break;

	case PFCP_IE_CREATE_MAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_mar, &req->nr_create_mar,
					   sizeof(struct pfcp_ie_create_mar), pfcp_parse_ie_create_mar);
		break;

	case PFCP_IE_CREATE_SRR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_srr, &req->nr_create_srr,
					   sizeof(struct pfcp_ie_create_srr), pfcp_parse_ie_create_srr);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_pdr->pdr_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_far->far_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_urr->urr_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_qer->qer_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_bar->bar_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_traffic_endpoint->traffic_endpoint_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_mar->mar_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&remove_srr->srr_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->pdr_id, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_REMOVAL:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->outer_header_removal, cp, size);
		break;

	case PFCP_IE_PRECEDENCE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->precedence, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->far_id, cp, size);
		break;

	case PFCP_IE_URR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->urr_id, cp, size);
		break;

	case PFCP_IE_QER_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->qer_id, cp, size);
		break;

	case PFCP_IE_ACTIVATE_PREDEFINED_RULES:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->activate_predefined_rules, cp, size);
		break;

	case PFCP_IE_DEACTIVATE_PREDEFINED_RULES:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->deactivate_predefined_rules, cp, size);
		break;

	case PFCP_IE_ACTIVATION_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->activation_time, cp, size);
		break;

	case PFCP_IE_DEACTIVATION_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&update_pdr->deactivation_time, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->destination_interface, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->network_instance, cp, size);
		break;

	case PFCP_IE_REDIRECT_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->redirect_information, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->outer_header_creation, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->transport_level_marking, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->forwarding_policy, cp, size);
		break;

	case PFCP_IE_HEADER_ENRICHMENT:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->header_enrichment, cp, size);
		break;

	case PFCP_IE_TRAFFIC_ENDPOINT_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->linked_traffic_endpoint_id, cp, size);
		break;

	case PFCP_IE_PFCPSMREQ_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->pfcpsm_req_flags, cp, size);
		break;

	case PFCP_IE_3GPP_INTERFACE_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_fwd_params->destination_interface_type, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_dup_params->destination_interface, cp, size);
		break;

	case PFCP_IE_OUTER_HEADER_CREATION:
		pfcp_msg_alloc_scheme(msg, (void **)&update_dup_params->outer_header_creation, cp, size);
		break;

	case PFCP_IE_TRANSPORT_LEVEL_MARKING:
		pfcp_msg_alloc_scheme(msg, (void **)&update_dup_params->transport_level_marking, cp, size);
		break;

	case PFCP_IE_FORWARDING_POLICY:
		pfcp_msg_alloc_scheme(msg, (void **)&update_dup_params->forwarding_policy, cp, size);
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

	switch (ie_type) {
	case PFCP_IE_FAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_far->far_id, cp, size);
		break;

	case PFCP_IE_APPLY_ACTION:
		pfcp_msg_alloc_scheme(msg, (void **)&update_far->apply_action, cp, size);
		break;

	case PFCP_IE_UPDATE_FORWARDING_PARAMETERS:
		pfcp_parse_alloc_ie(msg, cp, (void **)&update_far->update_forwarding_parameters,
				    sizeof(*update_far->update_forwarding_parameters), pfcp_parse_ie_update_fwd_params);
		break;

	case PFCP_IE_UPDATE_DUPLICATING_PARAMETERS:
		pfcp_parse_alloc_ie(msg, cp, (void **)&update_far->update_duplicating_parameters,
				    sizeof(*update_far->update_duplicating_parameters), pfcp_parse_ie_update_dup_params);
		break;

	case PFCP_IE_BAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_far->bar_id, cp, size);
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

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->urr_id, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_METHOD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->measurement_method, cp, size);
		break;

	case PFCP_IE_REPORTING_TRIGGERS:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->reporting_triggers, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_PERIOD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->measurement_period, cp, size);
		break;

	case PFCP_IE_VOLUME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->volume_threshold, cp, size);
		break;

	case PFCP_IE_VOLUME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->volume_quota, cp, size);
		break;

	case PFCP_IE_TIME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->time_threshold, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->time_quota, cp, size);
		break;

	case PFCP_IE_EVENT_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->event_threshold, cp, size);
		break;

	case PFCP_IE_EVENT_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->event_quota, cp, size);
		break;

	case PFCP_IE_QUOTA_HOLDING_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->quota_holding_time, cp, size);
		break;

	case PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->dropped_dl_traffic_threshold, cp, size);
		break;

	case PFCP_IE_QUOTA_VALIDITY_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->quota_validity_time, cp, size);
		break;

	case PFCP_IE_MONITORING_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->monitoring_time, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->subsequent_volume_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->subsequent_time_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_VOLUME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->subsequent_volume_quota, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_TIME_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->subsequent_time_quota, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_THRESHOLD:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->subsequent_event_threshold, cp, size);
		break;

	case PFCP_IE_SUBSEQUENT_EVENT_QUOTA:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->subsequent_event_quota, cp, size);
		break;

	case PFCP_IE_INACTIVITY_DETECTION_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->inactivity_detection_time, cp, size);
		break;

	case PFCP_IE_LINKED_URR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->linked_urr_id, cp, size);
		break;

	case PFCP_IE_MEASUREMENT_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->measurement_information, cp, size);
		break;

	case PFCP_IE_TIME_QUOTA_MECHANISM:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->time_quota_mechanism, cp, size);
		break;

	case PFCP_IE_AGGREGATED_URRS:
		pfcp_parse_alloc_ie(msg, cp, (void **)&update_urr->aggregated_urrs,
				    sizeof(*update_urr->aggregated_urrs), pfcp_parse_ie_aggregated_urrs);
		break;

	case PFCP_IE_FAR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->far_id_for_quota_action, cp, size);
		break;

	case PFCP_IE_ETHERNET_INACTIVITY_TIMER:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->ethernet_inactivity_timer, cp, size);
		break;

	case PFCP_IE_ADDITIONAL_MONITORING_TIME:
		pfcp_parse_alloc_ie(msg, cp, (void **)&update_urr->additional_monitoring_time,
				    sizeof(*update_urr->additional_monitoring_time), pfcp_parse_ie_additional_monitoring_time);
		break;

	case PFCP_IE_NUMBER_OF_REPORTS:
		pfcp_msg_alloc_scheme(msg, (void **)&update_urr->number_of_reports, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->qer_id, cp, size);
		break;

	case PFCP_IE_QER_CORRELATION_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->qer_correlation_id, cp, size);
		break;

	case PFCP_IE_GATE_STATUS:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->gate_status, cp, size);
		break;

	case PFCP_IE_MBR:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->maximum_bitrate, cp, size);
		break;

	case PFCP_IE_GBR:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->guaranteed_bitrate, cp, size);
		break;

	case PFCP_IE_PACKET_RATE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->packet_rate, cp, size);
		break;

	case PFCP_IE_DL_FLOW_LEVEL_MARKING:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->dl_flow_level_marking, cp, size);
		break;

	case PFCP_IE_QFI:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->qos_flow_identifier, cp, size);
		break;

	case PFCP_IE_RQI:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->reflective_qos, cp, size);
		break;

	case PFCP_IE_PPI:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->paging_policy_indicator, cp, size);
		break;

	case PFCP_IE_AVERAGING_WINDOW:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->averaging_window, cp, size);
		break;

	case PFCP_IE_QER_CONTROL_INDICATIONS:
		pfcp_msg_alloc_scheme(msg, (void **)&update_qer->qer_control_indications, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_bar->bar_id, cp, size);
		break;

	case PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY:
		pfcp_msg_alloc_scheme(msg, (void **)&update_bar->downlink_data_notification_delay, cp, size);
		break;

	case PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT:
		pfcp_msg_alloc_scheme(msg, (void **)&update_bar->suggested_buffering_packets_count, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->traffic_endpoint_id, cp, size);
		break;

	case PFCP_IE_F_TEID:
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->local_f_teid, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->network_instance, cp, size);
		break;

	case PFCP_IE_UE_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->ue_ip_address, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->framed_route, cp, size);
		break;

	case PFCP_IE_FRAMED_ROUTING:
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->framed_routing, cp, size);
		break;

	case PFCP_IE_FRAMED_IPV6_ROUTE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->framed_ipv6_route, cp, size);
		break;

	case PFCP_IE_QFI:
		pfcp_msg_alloc_scheme(msg, (void **)&update_traffic_endpoint->qfi, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_mar->mar_id, cp, size);
		break;

	case PFCP_IE_STEERING_FUNCTIONALITY:
		pfcp_msg_alloc_scheme(msg, (void **)&update_mar->steering_functionality, cp, size);
		break;

	case PFCP_IE_STEERING_MODE:
		pfcp_msg_alloc_scheme(msg, (void **)&update_mar->steering_mode, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&update_srr->srr_id, cp, size);
		break;

	case PFCP_IE_ACCESS_AVAILABILITY_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&update_srr->access_availability_control_information, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&query_urr->urr_id, cp, size);
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

	if (!req) {
		req = mpool_zalloc(&msg->mp, sizeof(*req));
		if (!req)
			return;
		msg->session_modification_request = req;
	}

	switch (ie_type) {
	case PFCP_IE_F_SEID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->cp_f_seid, cp, size);
		break;

	case PFCP_IE_REMOVE_PDR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_pdr, &req->nr_remove_pdr,
					   sizeof(struct pfcp_ie_remove_pdr), pfcp_parse_ie_remove_pdr);
		break;

	case PFCP_IE_REMOVE_FAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_far, &req->nr_remove_far,
					   sizeof(struct pfcp_ie_remove_far), pfcp_parse_ie_remove_far);
		break;

	case PFCP_IE_REMOVE_URR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_urr, &req->nr_remove_urr,
					   sizeof(struct pfcp_ie_remove_urr), pfcp_parse_ie_remove_urr);
		break;

	case PFCP_IE_REMOVE_QER:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_qer, &req->nr_remove_qer,
					   sizeof(struct pfcp_ie_remove_qer), pfcp_parse_ie_remove_qer);
		break;

	case PFCP_IE_REMOVE_BAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_bar, &req->nr_remove_bar,
					   sizeof(struct pfcp_ie_remove_bar), pfcp_parse_ie_remove_bar);
		break;

	case PFCP_IE_REMOVE_TRAFFIC_ENDPOINT:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_traffic_endpoint,
					   &req->nr_remove_traffic_endpoint,
					   sizeof(struct pfcp_ie_remove_traffic_endpoint),
					   pfcp_parse_ie_remove_traffic_endpoint);
		break;

	case PFCP_IE_REMOVE_MAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_mar, &req->nr_remove_mar,
					   sizeof(struct pfcp_ie_remove_mar), pfcp_parse_ie_remove_mar);
		break;

	case PFCP_IE_REMOVE_SRR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->remove_srr, &req->nr_remove_srr,
					   sizeof(struct pfcp_ie_remove_srr), pfcp_parse_ie_remove_srr);
		break;

	case PFCP_IE_CREATE_PDR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_pdr, &req->nr_create_pdr,
					   sizeof(struct pfcp_ie_create_pdr), pfcp_parse_ie_create_pdr);
		break;

	case PFCP_IE_CREATE_FAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_far, &req->nr_create_far,
					   sizeof(struct pfcp_ie_create_far), pfcp_parse_ie_create_far);
		break;

	case PFCP_IE_CREATE_URR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_urr, &req->nr_create_urr,
					   sizeof(struct pfcp_ie_create_urr), pfcp_parse_ie_create_urr);
		break;

	case PFCP_IE_CREATE_QER:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_qer, &req->nr_create_qer,
					   sizeof(struct pfcp_ie_create_qer), pfcp_parse_ie_create_qer);
		break;

	case PFCP_IE_CREATE_BAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_bar, &req->nr_create_bar,
					   sizeof(struct pfcp_ie_create_bar), pfcp_parse_ie_create_bar);
		break;

	case PFCP_IE_CREATE_TRAFFIC_ENDPOINT:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_traffic_endpoint,
					   &req->nr_create_traffic_endpoint,
					   sizeof(struct pfcp_ie_create_traffic_endpoint),
					   pfcp_parse_ie_create_traffic_endpoint);
		break;

	case PFCP_IE_CREATE_MAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_mar, &req->nr_create_mar,
					   sizeof(struct pfcp_ie_create_mar), pfcp_parse_ie_create_mar);
		break;

	case PFCP_IE_CREATE_SRR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->create_srr, &req->nr_create_srr,
					   sizeof(struct pfcp_ie_create_srr), pfcp_parse_ie_create_srr);
		break;

	case PFCP_IE_UPDATE_PDR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_pdr, &req->nr_update_pdr,
					   sizeof(struct pfcp_ie_update_pdr), pfcp_parse_ie_update_pdr);
		break;

	case PFCP_IE_UPDATE_FAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_far, &req->nr_update_far,
					   sizeof(struct pfcp_ie_update_far), pfcp_parse_ie_update_far);
		break;

	case PFCP_IE_UPDATE_URR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_urr, &req->nr_update_urr,
					   sizeof(struct pfcp_ie_update_urr), pfcp_parse_ie_update_urr);
		break;

	case PFCP_IE_UPDATE_QER:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_qer, &req->nr_update_qer,
					   sizeof(struct pfcp_ie_update_qer), pfcp_parse_ie_update_qer);
		break;

	case PFCP_IE_UPDATE_BAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_bar, &req->nr_update_bar,
					   sizeof(struct pfcp_ie_update_bar), pfcp_parse_ie_update_bar);
		break;

	case PFCP_IE_UPDATE_TRAFFIC_ENDPOINT:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_traffic_endpoint,
					   &req->nr_update_traffic_endpoint,
					   sizeof(struct pfcp_ie_update_traffic_endpoint),
					   pfcp_parse_ie_update_traffic_endpoint);
		break;

	case PFCP_IE_UPDATE_MAR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_mar, &req->nr_update_mar,
					   sizeof(struct pfcp_ie_update_mar), pfcp_parse_ie_update_mar);
		break;

	case PFCP_IE_UPDATE_SRR:
		pfcp_parse_add_ie_to_array(msg, cp, (void ***)&req->update_srr, &req->nr_update_srr,
					   sizeof(struct pfcp_ie_update_srr), pfcp_parse_ie_update_srr);
		break;

	case PFCP_IE_PFCPSMREQ_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->pfcpsmreq_flags, cp, size);
		break;

	case PFCP_IE_QUERY_URR:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->query_urr,
				    sizeof(*req->query_urr), pfcp_parse_ie_query_urr);
		break;

	case PFCP_IE_FQ_CSID:
		if (!req->pgw_c_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->pgw_c_fq_csid, cp, size);
		else if (!req->sgw_c_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->sgw_c_fq_csid, cp, size);
		else if (!req->mme_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->mme_fq_csid, cp, size);
		else if (!req->epdg_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->epdg_fq_csid, cp, size);
		else if (!req->twan_fq_csid)
			pfcp_msg_alloc_scheme(msg, (void **)&req->twan_fq_csid, cp, size);
		break;

	case PFCP_IE_USER_PLANE_INACTIVITY_TIMER:
		pfcp_msg_alloc_scheme(msg, (void **)&req->user_plane_inactivity_timer, cp, size);
		break;

	case PFCP_IE_QUERY_URR_REFERENCE:
		pfcp_msg_alloc_scheme(msg, (void **)&req->query_urr_reference, cp, size);
		break;

	case PFCP_IE_TRACE_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&req->trace_information, cp, size);
		break;

	case PFCP_IE_NODE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
		break;

	case PFCP_IE_RAT_TYPE:
		pfcp_msg_alloc_scheme(msg, (void **)&req->rat_type, cp, size);
		break;

	case PFCP_IE_GROUP_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->group_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&req->tl_container, cp, size);
		break;

	case PFCP_IE_NODE_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->node_id, cp, size);
		break;

	case PFCP_IE_F_SEID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->cp_f_seid, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&report->pdr_id, cp, size);
		break;

	case PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&report->downlink_data_service_information, cp, size);
		break;

	default:
		break;
	}

	return 0;
}

static int
pfcp_parse_ie_usage_report(void *m, void *n, const uint8_t *cp)
{
	struct pfcp_ie *ie = (struct pfcp_ie *) cp;
	uint16_t ie_type = ntohs(ie->type);
	size_t size = sizeof(*ie) + ntohs(ie->length);
	struct pfcp_msg *msg = m;
	struct pfcp_ie_usage_report *report = n;

	switch (ie_type) {
	case PFCP_IE_URR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&report->urr_id, cp, size);
		break;

	case PFCP_IE_UR_SEQN:
		pfcp_msg_alloc_scheme(msg, (void **)&report->ur_seqn, cp, size);
		break;

	case PFCP_IE_USAGE_REPORT_TRIGGER:
		pfcp_msg_alloc_scheme(msg, (void **)&report->usage_report_trigger, cp, size);
		break;

	case PFCP_IE_START_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&report->start_time, cp, size);
		break;

	case PFCP_IE_END_TIME:
		pfcp_msg_alloc_scheme(msg, (void **)&report->end_time, cp, size);
		break;

	case PFCP_IE_VOLUME_MEASUREMENT:
		pfcp_msg_alloc_scheme(msg, (void **)&report->volume_measurement, cp, size);
		break;

	case PFCP_IE_DURATION_MEASUREMENT:
		pfcp_msg_alloc_scheme(msg, (void **)&report->duration_measurement, cp, size);
		break;
#if 0
	case PFCP_IE_APPLICATION_DETECTION_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&report->application_detection_information, cp, size);
		break;
#endif
	case PFCP_IE_UE_IP_ADDRESS:
		pfcp_msg_alloc_scheme(msg, (void **)&report->ue_ip_address, cp, size);
		break;

	case PFCP_IE_NETWORK_INSTANCE:
		pfcp_msg_alloc_scheme(msg, (void **)&report->network_instance, cp, size);
		break;

	case PFCP_IE_TIME_OF_FIRST_PACKET:
		pfcp_msg_alloc_scheme(msg, (void **)&report->time_of_first_packet, cp, size);
		break;

	case PFCP_IE_TIME_OF_LAST_PACKET:
		pfcp_msg_alloc_scheme(msg, (void **)&report->time_of_last_packet, cp, size);
		break;

	case PFCP_IE_USAGE_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&report->usage_information, cp, size);
		break;

	case PFCP_IE_QUERY_URR_REFERENCE:
		pfcp_msg_alloc_scheme(msg, (void **)&report->query_urr_reference, cp, size);
		break;

	case PFCP_IE_TIME_STAMP:
		pfcp_msg_alloc_scheme(msg, (void **)&report->event_time_stamp, cp, size);
		break;
#if 0
	case PFCP_IE_ETHERNET_TRAFFIC_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&report->ethernet_traffic_information, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&report->remote_f_teid, cp, size);
		break;

	case PFCP_IE_PDR_ID:
		pfcp_msg_alloc_scheme(msg, (void **)&report->pdr_id, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&info->load_control_sequence_number, cp, size);
		break;

	case PFCP_IE_METRIC:
		pfcp_msg_alloc_scheme(msg, (void **)&info->load_metric, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&info->overload_control_sequence_number, cp, size);
		break;

	case PFCP_IE_METRIC:
		pfcp_msg_alloc_scheme(msg, (void **)&info->overload_reduction_metric, cp, size);
		break;

	case PFCP_IE_TIMER:
		pfcp_msg_alloc_scheme(msg, (void **)&info->period_of_validity, cp, size);
		break;

	case PFCP_IE_OCI_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&info->overload_control_information_flags, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&report->qer_id, cp, size);
		break;

	case PFCP_IE_PACKET_RATE_STATUS:
		pfcp_msg_alloc_scheme(msg, (void **)&report->packet_rate_status, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&report->srr_id, cp, size);
		break;

	case PFCP_IE_ACCESS_AVAILABILITY_REPORT:
		pfcp_msg_alloc_scheme(msg, (void **)&report->access_availability_report, cp, size);
		break;
#if 0
	case PFCP_IE_QOS_MONITORING_REPORT:
		pfcp_msg_alloc_scheme(msg, (void **)&report->qos_monitoring_report, cp, size);
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
		pfcp_msg_alloc_scheme(msg, (void **)&req->report_type, cp, size);
		*mandatory |= (1 << 0);
		break;

	case PFCP_IE_DOWNLINK_DATA_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->downlink_data_report,
				    sizeof(*req->downlink_data_report), pfcp_parse_ie_downlink_data_report);
		break;

	case PFCP_IE_USAGE_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->usage_report,
				    sizeof(*req->usage_report), pfcp_parse_ie_usage_report);
		break;

	case PFCP_IE_ERROR_INDICATION_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->error_indication_report,
				    sizeof(*req->error_indication_report),
				    pfcp_parse_ie_error_indication_report);
		break;

	case PFCP_IE_LOAD_CONTROL_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->load_control_information,
				    sizeof(*req->load_control_information),
				    pfcp_parse_ie_load_control_information);
		break;

	case PFCP_IE_OVERLOAD_CONTROL_INFORMATION:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->overload_control_information,
				    sizeof(*req->overload_control_information),
				    pfcp_parse_ie_overload_control_information);
		break;

	case PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION:
		pfcp_msg_alloc_scheme(msg, (void **)&req->additional_usage_reports_information, cp, size);
		break;

	case PFCP_IE_PFCPSRREQ_FLAGS:
		pfcp_msg_alloc_scheme(msg, (void **)&req->pfcpsrreq_flags, cp, size);
		break;

	case PFCP_IE_F_SEID:
		pfcp_msg_alloc_scheme(msg, (void **)&req->old_cp_f_seid, cp, size);
		break;

	case PFCP_IE_PACKET_RATE_STATUS_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->packet_rate_status_report,
				    sizeof(*req->packet_rate_status_report),
				    pfcp_parse_ie_packet_rate_status_report);
		break;

	case PFCP_IE_SESSION_REPORT:
		pfcp_parse_alloc_ie(msg, cp, (void **)&req->session_report,
				    sizeof(*req->session_report), pfcp_parse_ie_session_report);
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
	[PFCP_ASSOCIATION_SETUP_RESPONSE]	= { 7,
						    pfcp_parse_association_setup_response
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
static void
pfcp_msg_reset(struct pfcp_msg *msg)
{
	mpool_reset(&msg->mp);
	msg->heartbeat_request = NULL;
}

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
	msg->h = pfcph;

	pfcp_msg_reset(msg);
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
pfcp_msg_alloc(int scheme)
{
	struct pfcp_msg *new;

	new = mpool_new(sizeof(*new), MPOOL_DEFAULT_SIZE);
	if (!new)
		return NULL;
	new->m_scheme = scheme;

	return new;
}

void
pfcp_msg_free(struct pfcp_msg *msg)
{
	if (!msg)
		return;

	mpool_delete(msg);
}
