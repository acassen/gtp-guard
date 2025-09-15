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
#pragma once

#include <stdint.h>
#include "rbtree_types.h"
#include "pfcp_ie.h"
#include "pkt_buffer.h"

/*
 *	PFCP Message indexation
 */
struct pfcp_msg_ie {
	struct pfcp_ie		*h;
	void const		*data;

	struct rb_node		n;
};

struct pfcp_msg {
	struct pfcp_hdr		*h;

	struct rb_root_cached	ie;
};




/*
 *	PFCP Messages structures
 */

/* PFCP Heartbeat */
struct pfcp_heartbeat_request {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_recovery_time_stamp *recovery_time_stamp;
	/* Optional IEs */
	struct pfcp_ie_source_ip_address *source_ip_address;
};

struct pfcp_heartbeat_response {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_recovery_time_stamp *recovery_time_stamp;
};

/* PFCP PFD Management */
struct pfcp_pfd_management_request {
	struct pfcp_hdr *h;
	/* Optional IEs */
	struct pfcp_ie_node_id *node_id;
	/* Grouped IEs */
	struct pfcp_ie_application_id_pfds *application_id_pfds;
};

struct pfcp_pfd_management_response {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_cause *cause;
	/* Optional IEs */
	struct pfcp_ie_offending *offending_ie;
	struct pfcp_ie_node_id *node_id;
};

/* PFCP Association Setup */
struct pfcp_association_setup_request {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
	struct pfcp_ie_recovery_time_stamp *recovery_time_stamp;
	/* Optional IEs */
	struct pfcp_ie_up_function_features *up_function_features;
	struct pfcp_ie_cp_function_features *cp_function_features;
	struct pfcp_ie_user_plane_ip_resource_information *user_plane_ip_resource_info;
	struct pfcp_ie_alternative_smf_ip_address *alternative_smf_ip_address;
	struct pfcp_ie_smf_set_id *smf_set_id;
	struct pfcp_ie_pfcpasreq_flags *pfcpasreq_flags;
	/* Grouped IEs */
	struct pfcp_ie_session_retention_information *session_retention_info;
	struct pfcp_ie_ue_ip_address_pool_information *ue_ip_address_pool_info;
};

struct pfcp_association_setup_response {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
	struct pfcp_ie_cause *cause;
	struct pfcp_ie_recovery_time_stamp *recovery_time_stamp;
	/* Optional IEs */
	struct pfcp_ie_up_function_features *up_function_features;
	struct pfcp_ie_cp_function_features *cp_function_features;
	struct pfcp_ie_user_plane_ip_resource_information *user_plane_ip_resource_info;
	struct pfcp_ie_alternative_smf_ip_address *alternative_smf_ip_address;
	struct pfcp_ie_smf_set_id *smf_set_id;
	struct pfcp_ie_pfcpasrsp_flags *pfcpasrsp_flags;
	struct pfcp_ie_nf_instance_id *upf_instance_id;
	/* Grouped IEs */
	struct pfcp_ie_ue_ip_address_pool_information *ue_ip_address_pool_info;
};

/* PFCP Association Update */
struct pfcp_association_update_request {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
	/* Optional IEs */
	struct pfcp_ie_up_function_features *up_function_features;
	struct pfcp_ie_cp_function_features *cp_function_features;
	struct pfcp_ie_pfcp_association_release_request *association_release_request;
	struct pfcp_ie_graceful_release_period *graceful_release_period;
	struct pfcp_ie_pfcpaureq_flags *pfcpaureq_flags;
	struct pfcp_ie_alternative_smf_ip_address *alternative_smf_ip_address;
	struct pfcp_ie_smf_set_id *smf_set_id;
	struct pfcp_ie_clock_drift_control_information *clock_drift_control_information;
	/* Grouped IEs */
	struct pfcp_ie_ue_ip_address_pool_information *ue_ip_address_pool_information;
	struct pfcp_ie_gtp_u_path_qos_control_information *gtp_u_path_qos_control_information;
	struct pfcp_ie_ue_ip_address_usage_information *ue_ip_address_usage_information;
};

struct pfcp_association_update_response {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
	struct pfcp_ie_cause *cause;
	/* Optional IEs */
	struct pfcp_ie_up_function_features *up_function_features;
	struct pfcp_ie_cp_function_features *cp_function_features;
	/* Grouped IEs */
	struct pfcp_ie_ue_ip_address_usage_information *ue_ip_address_usage_information;
};

/* PFCP Association Release */
struct pfcp_association_release_request {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
};

struct pfcp_association_release_response {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
	struct pfcp_ie_cause *cause;
};

/* PFCP Node Report */
struct pfcp_node_report_request {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
	struct pfcp_ie_node_report_type *node_report_type;
	/* Grouped IEs */
	struct pfcp_ie_user_plane_path_failure_report *user_plane_path_failure_report;
	struct pfcp_ie_user_plane_path_recovery_report *user_plane_path_recovery_report;
	struct pfcp_ie_peer_up_restart_report *peer_up_restart_report;
};

struct pfcp_node_report_response {
	struct pfcp_hdr *h;
	/* Mandatory IEs */
	struct pfcp_ie_node_id *node_id;
	struct pfcp_ie_cause *cause;
	/* Optional IEs */
	struct pfcp_ie_offending *offending_ie;
};

/* Prototypes */
size_t pfcp_msg_hlen(struct pfcp_hdr *h);
void pfcp_msg_ie_dump(const char *prefix, const struct pfcp_msg_ie *msg_ie);
struct pfcp_msg_ie *pfcp_msg_ie_get(struct pfcp_msg *msg, uint16_t type);
struct pfcp_msg *pfcp_msg_alloc(const struct pkt_buffer *pbuff);
void pfcp_msg_destroy(struct pfcp_msg *msg);
void pfcp_msg_dump(const char *prefix, struct pfcp_msg *msg);
int pfcp_msg_parse(struct pkt_buffer *pbuff, void *arg);

