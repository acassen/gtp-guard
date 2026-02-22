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

#include "pfcp.h"
#include "pfcp_utils.h"
#include "pfcp_ie.h"


static const struct pfcp_msg_type_map pfcp_msg_type2str[1 << 8] = {
	[PFCP_HEARTBEAT_REQUEST] = {
		.name = "Heartbeat Request",
		.description = "Sent by any PFCP entity to check the availability of another PFCP entity"
	},
	[PFCP_HEARTBEAT_RESPONSE] = {
		.name = "Heartbeat Response",
		.description = "Response to a Heartbeat Request"
	},
	[PFCP_PFD_MANAGEMENT_REQUEST] = {
		.name = "PFD Management Request",
		.description = "Sent by the CPF to manage Packet Flow Description (PFD) at the UPF"
	},
	[PFCP_PFD_MANAGEMENT_RESPONSE] = {
		.name = "PFD Management Response",
		.description = "Response to a PFD Management Request"
	},
	[PFCP_ASSOCIATION_SETUP_REQUEST] = {
		.name = "Association Setup Request",
		.description = "Sent to establish a PFCP association between CPF and UPF"
	},
	[PFCP_ASSOCIATION_SETUP_RESPONSE] = {
		.name = "Association Setup Response",
		.description = "Response to an Association Setup Request"
	},
	[PFCP_ASSOCIATION_UPDATE_REQUEST] = {
		.name = "Association Update Request",
		.description = "Sent to update parameters of an existing PFCP association"
	},
	[PFCP_ASSOCIATION_UPDATE_RESPONSE] = {
		.name = "Association Update Response",
		.description = "Response to an Association Update Request"
	},
	[PFCP_ASSOCIATION_RELEASE_REQUEST] = {
		.name = "Association Release Request",
		.description = "Sent to release a PFCP association"
	},
	[PFCP_ASSOCIATION_RELEASE_RESPONSE] = {
		.name = "Association Release Response",
		.description = "Response to an Association Release Request"
	},
	[PFCP_VERSION_NOT_SUPPORTED_RESPONSE] = {
		.name = "Version Not Supported Response",
		.description = "Sent when the PFCP version in the request is not supported"
	},
	[PFCP_NODE_REPORT_REQUEST] = {
		.name = "Node Report Request",
		.description = "Sent by the UPF to report node-level information to the CPF"
	},
	[PFCP_NODE_REPORT_RESPONSE] = {
		.name = "Node Report Response",
		.description = "Response to a Node Report Request"
	},
	[PFCP_SESSION_SET_DELETION_REQUEST] = {
		.name = "Session Set Deletion Request",
		.description = "Sent to delete a set of PFCP sessions"
	},
	[PFCP_SESSION_SET_DELETION_RESPONSE] = {
		.name = "Session Set Deletion Response",
		.description = "Response to a Session Set Deletion Request"
	},
	[PFCP_SESSION_SET_MODIFICATION_REQUEST] = {
		.name = "Session Set Modification Request",
		.description = "Sent to modify parameters of a set of PFCP sessions"
	},
	[PFCP_SESSION_SET_MODIFICATION_RESPONSE] = {
		.name = "Session Set Modification Response",
		.description = "Response to a Session Set Modification Request"
	},
	[PFCP_SESSION_ESTABLISHMENT_REQUEST] = {
		.name = "Session Establishment Request",
		.description = "Sent by the CPF to establish a PFCP session at the UPF"
	},
	[PFCP_SESSION_ESTABLISHMENT_RESPONSE] = {
		.name = "Session Establishment Response",
		.description = "Response to a Session Establishment Request"
	},
	[PFCP_SESSION_MODIFICATION_REQUEST] = {
		.name = "Session Modification Request",
		.description = "Sent by the CPF to modify an existing PFCP session"
	},
	[PFCP_SESSION_MODIFICATION_RESPONSE] = {
		.name = "Session Modification Response",
		.description = "Response to a Session Modification Request"
	},
	[PFCP_SESSION_DELETION_REQUEST] = {
		.name = "Session Deletion Request",
		.description = "Sent by the CPF to delete an existing PFCP session"
	},
	[PFCP_SESSION_DELETION_RESPONSE] = {
		.name = "Session Deletion Response",
		.description = "Response to a Session Deletion Request"
	},
	[PFCP_SESSION_REPORT_REQUEST] = {
		.name = "Session Report Request",
		.description = "Sent by the UPF to report session-level information to the CPF"
	},
	[PFCP_SESSION_REPORT_RESPONSE] = {
		.name = "Session Report Response",
		.description = "Response to a Session Report Request"
	},
};

static const struct pfcp_msg_type_map pfcp_msg_cause2str[1 << 8] = {
	[PFCP_CAUSE_REQUEST_ACCEPTED] = {
		.name = "Request accepted",
		.description = "The request was accepted",
	},
	[PFCP_CAUSE_MORE_USAGE_REPORT_TO_SEND] = {
		.name = "More usage report to send",
		.description = "The UPF has more usage reports to send for the session",
	},
	[PFCP_CAUSE_REQUEST_PARTIALLY_ACCEPTED] = {
		.name = "Request partially accepted",
		.description = "The request was partially accepted",
	},
	[PFCP_CAUSE_REQUEST_REJECTED] = {
		.name = "Request rejected",
		.description = "The request was rejected for unspecified reasons",
	},
	[PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND] = {
		.name = "Session context not found",
		.description = "The specified PFCP session context was not found",
	},
	[PFCP_CAUSE_MANDATORY_IE_MISSING] = {
		.name = "Mandatory IE missing",
		.description = "A mandatory Information Element is missing from the message",
	},
	[PFCP_CAUSE_CONDITIONAL_IE_MISSING] = {
		.name = "Conditional IE missing",
		.description = "A conditionally mandatory Information Element is missing",
	},
	[PFCP_CAUSE_INVALID_LENGTH] = {
		.name = "Invalid length",
		.description = "The length of an Information Element is invalid",
	},
	[PFCP_CAUSE_MANDATORY_IE_INCORRECT] = {
		.name = "Mandatory IE incorrect",
		.description = "A mandatory Information Element contains incorrect information",
	},
	[PFCP_CAUSE_INVALID_FORWARDING_POLICY] = {
		.name = "Invalid Forwarding Policy",
		.description = "The forwarding policy identifier is invalid",
	},
	[PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION] = {
		.name = "Invalid F-TEID allocation option",
		.description = "The F-TEID allocation option is invalid",
	},
	[PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION] = {
		.name = "No established PFCP Association",
		.description = "No PFCP association has been established with the peer",
	},
	[PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE] = {
		.name = "Rule creation/modification Failure",
		.description = "Failed to create or modify packet detection, forwarding or QoS enforcement rules",
	},
	[PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION] = {
		.name = "PFCP entity in congestion",
		.description = "The PFCP entity is experiencing congestion",
	},
	[PFCP_CAUSE_NO_RESOURCES_AVAILABLE] = {
		.name = "No resources available",
		.description = "No resources are available to process the request",
	},
	[PFCP_CAUSE_SERVICE_NOT_SUPPORTED] = {
		.name = "Service not supported",
		.description = "The requested service is not supported",
	},
	[PFCP_CAUSE_SYSTEM_FAILURE] = {
		.name = "System failure",
		.description = "A system failure has occurred",
	},
	[PFCP_CAUSE_REDIRECTION_REQUESTED] = {
		.name = "Redirection Requested",
		.description = "Redirection to another PFCP entity is requested",
	},
	[PFCP_CAUSE_ALL_DYNAMIC_ADDRESS_ARE_OCCUPIED] = {
		.name = "All dynamic addresses are occupied",
		.description = "All available dynamic addresses are currently in use",
	},
	[PFCP_CAUSE_UNKNOWN_PRE_DEFINED_RULE] = {
		.name = "Unknown Pre-defined Rule",
		.description = "The specified pre-defined rule is unknown",
	},
	[PFCP_CAUSE_UNKNOWN_APPLICATION_ID] = {
		.name = "Unknown Application ID",
		.description = "The specified Application ID is unknown",
	},
};

const char *
pfcp_msgtype2str(int type)
{
	if (pfcp_msg_type2str[type].name)
		return pfcp_msg_type2str[type].name;

	return "unknown msg type";
}

const char *
pfcp_cause2str(int cause)
{
	if (pfcp_msg_cause2str[cause].name)
		return pfcp_msg_cause2str[cause].name;

	return "unknown cause";
}

const char *
pfcp_3GPP_interface2str(int type)
{
	switch (type) {
	case PFCP_3GPP_INTERFACE_S1U:
		return "S1-U";
	case PFCP_3GPP_INTERFACE_S5U:
		return "S5/S8-U";
	case PFCP_3GPP_INTERFACE_SGI:
		return "SGi";
	case PFCP_3GPP_INTERFACE_S8U:
		return "S8-U";
	case PFCP_3GPP_INTERFACE_N9:
		return "N9-U";
	}

	return "unknown";
}
