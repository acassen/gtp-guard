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

#include <arpa/inet.h>
#include <string.h>
#include "pfcp.h"
#include "pfcp_msg.h"
#include "pfcp_utils.h"
#include "pfcp_server.h"
#include "pfcp_proto_dump.h"
#include "pkt_buffer.h"
#include "inet_utils.h"
#include "utils.h"
#include "vty.h"
#include "pfcp_ie.h"


/*
 *	Common formatting helpers
 */
static size_t
pfcp_recovery_ts_format(struct pfcp_ie_recovery_time_stamp *recovery_ts, char *buffer, size_t size)
{
	size_t pos = 0;
	time_t ts;

	ts = ntohl(recovery_ts->ts);
	pos += scnprintf(buffer + pos, size - pos, "Recovery Time Stamp:\n");
	pos += scnprintf(buffer + pos, size - pos, "  Value: %u (seconds since 1900-01-01)\n",
				(uint32_t) ts);
	ts -= 2208988800;
	pos += scnprintf(buffer + pos, size - pos, "  Time: %s", ctime(&ts));

	return pos;
}

static size_t
pfcp_node_id_format(struct pfcp_ie_node_id *node_id, char *buffer, size_t size)
{
	char addr_str[INET6_ADDRSTRLEN];
	size_t pos = 0;

	pos += scnprintf(buffer + pos, size - pos, "Node ID:\n");
	pos += scnprintf(buffer + pos, size - pos, "  Type: %u\n", node_id->type);
	switch (node_id->type) {
	case PFCP_NODE_ID_TYPE_IPV4:
		pos += scnprintf(buffer + pos, size - pos, "  IPv4: %d.%d.%d.%d\n",
				 NIPQUAD(node_id->ipv4));
		break;

	case PFCP_NODE_ID_TYPE_IPV6:
		if (inet_ntop(AF_INET6, &node_id->ipv6, addr_str, INET6_ADDRSTRLEN))
			pos += scnprintf(buffer + pos, size - pos, "  IPv6: %s\n", addr_str);
		break;

	case PFCP_NODE_ID_TYPE_FQDN:
		if (inet_fqdn2str(addr_str, INET6_ADDRSTRLEN, node_id->fqdn,
				  ntohs(node_id->h.length) - 1))
			pos += scnprintf(buffer + pos, size - pos, "  FQDN: %s\n", addr_str);
		break;

	default:
		pos += scnprintf(buffer + pos, size - pos, "  !!!invalid type!!!\n");
		break;
	}

	return pos;
}

static size_t
pfcp_seid_format(struct pfcp_ie_f_seid *f_seid, char *buffer, size_t size)
{
	char addr_str[INET6_ADDRSTRLEN];
	size_t pos = 0;

	pos += scnprintf(buffer + pos, size - pos, "CP F-SEID:\n");
	pos += scnprintf(buffer + pos, size - pos, "  SEID: 0x%.16lx\n",
			 be64toh(f_seid->seid));

	if (f_seid->v4) {
		pos += scnprintf(buffer + pos, size - pos, "  IPv4: %d.%d.%d.%d\n",
				 NIPQUAD(f_seid->ipv4));
	}

	if (f_seid->v6) {
		if (inet_ntop(AF_INET6, &f_seid->ipv6, addr_str, INET6_ADDRSTRLEN))
			pos += scnprintf(buffer + pos, size - pos, "  IPv6: %s\n", addr_str);
	}

	return pos;
}


/*
 *	PFCP Heartbeat Dump
 */
static void
pfcp_heartbeat_req_format(struct pfcp_msg *msg, char *buffer, size_t size)
{
	struct pfcp_heartbeat_request *req = msg->heartbeat_request;
	char addr_str[INET6_ADDRSTRLEN];
	size_t pos = 0;

	if (!msg || !buffer || size == 0)
		return;

	if (req->recovery_time_stamp)
		pos += pfcp_recovery_ts_format(req->recovery_time_stamp, buffer + pos, size - pos);

	if (req->source_ip_address) {
		pos += scnprintf(buffer + pos, size - pos, "Source IP Address:\n");
		if (req->source_ip_address->v4) {
			pos += scnprintf(buffer + pos, size - pos, "  IPv4: %d.%d.%d.%d\n",
					 NIPQUAD(req->source_ip_address->ipv4));
		}
		if (req->source_ip_address->v6) {
			if (inet_ntop(AF_INET6, &req->source_ip_address->ipv6, addr_str,
				      INET6_ADDRSTRLEN))
				pos += scnprintf(buffer + pos, size - pos, "  IPv6: %s\n", addr_str);
			else
				pos += scnprintf(buffer + pos, size - pos, "IPv6 [!!! malformed !!!]\n");
		}
	}
}


/*
 *	PFCP Session Establishment Request Dump
 */
static size_t
pfcp_urr_id_format(struct pfcp_ie_urr_id **urr_id, int nr_urr_id, char *buffer, size_t size)
{
	size_t pos = 0;
	int i;

	for (i = 0; i < nr_urr_id; i++) {
		pos += scnprintf(buffer + pos, size - pos, "    URR ID: %u\n",
				 ntohl(urr_id[i]->value));
	}

	return pos;
}

static void
pfcp_session_establishment_req_format(struct pfcp_msg *msg, char *buffer, size_t size)
{
	struct pfcp_session_establishment_request *req = msg->session_establishment_request;
	size_t pos = 0;
	int i;

	if (!msg || !buffer || size == 0 || !req)
		return;

	if (req->node_id)
		pos += pfcp_node_id_format(req->node_id, buffer + pos, size - pos);

	if (req->cp_f_seid)
		pos += pfcp_seid_format(req->cp_f_seid, buffer + pos, size - pos);

	if (req->pdn_type) {
		pos += scnprintf(buffer + pos, size - pos, "PDN Type:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Value: %u\n", req->pdn_type->pdn_type);
	}

	if (req->user_plane_inactivity_timer) {
		pos += scnprintf(buffer + pos, size - pos, "User Plane Inactivity Timer:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Value: %u seconds\n",
				 ntohl(req->user_plane_inactivity_timer->timer));
	}

	if (req->apn_dnn) {
		pos += scnprintf(buffer + pos, size - pos, "APN/DNN:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Length: %u\n",
				 ntohs(req->apn_dnn->h.length));
	}

	if (req->rat_type) {
		pos += scnprintf(buffer + pos, size - pos, "RAT Type:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Value: %u\n", req->rat_type->value);
	}

	if (req->nr_create_pdr) {
		pos += scnprintf(buffer + pos, size - pos, "Create PDR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_pdr);
		for (i = 0; i < req->nr_create_pdr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  PDR[%d]:\n", i);
			if (req->create_pdr[i]->pdr_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    PDR ID: %u\n",
						 ntohs(req->create_pdr[i]->pdr_id->rule_id));
			if (req->create_pdr[i]->precedence)
				pos += scnprintf(buffer + pos, size - pos,
						 "    Precedence: %u\n",
						 ntohl(req->create_pdr[i]->precedence->value));
			if (req->create_pdr[i]->far_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    FAR ID: %u\n",
						 ntohl(req->create_pdr[i]->far_id->value));
			if (req->create_pdr[i]->qer_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    QER ID: %u\n",
						 ntohl(req->create_pdr[i]->qer_id->value));
			if (req->create_pdr[i]->urr_id)
				pos += pfcp_urr_id_format(req->create_pdr[i]->urr_id,
							  req->create_pdr[i]->nr_urr_id,
							  buffer + pos, size - pos);
		}
	}

	if (req->nr_create_far) {
		pos += scnprintf(buffer + pos, size - pos, "Create FAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_far);
		for (i = 0; i < req->nr_create_far; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  FAR[%d]:\n", i);
			if (req->create_far[i]->far_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    FAR ID: %u\n",
						 ntohl(req->create_far[i]->far_id->value));
			if (req->create_far[i]->apply_action)
				pos += scnprintf(buffer + pos, size - pos,
						 "    Apply Action: 0x%02x\n",
						 req->create_far[i]->apply_action->flags);
		}
	}

	if (req->nr_create_urr) {
		pos += scnprintf(buffer + pos, size - pos, "Create URR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_urr);
		for (i = 0; i < req->nr_create_urr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  URR[%d]:\n", i);
			pos += scnprintf(buffer + pos, size - pos, "    URR ID: %u\n",
					 ntohl(req->create_urr[i]->urr_id->value));
		}
	}

	if (req->nr_create_qer) {
		pos += scnprintf(buffer + pos, size - pos, "Create QER:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_qer);
		for (i = 0; i < req->nr_create_qer; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  QER[%d]:\n", i);
			pos += scnprintf(buffer + pos, size - pos, "    QER ID: %u\n",
					 ntohl(req->create_qer[i]->qer_id->value));
		}
	}

	if (req->nr_create_bar) {
		pos += scnprintf(buffer + pos, size - pos, "Create BAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_bar);
	}

	if (req->nr_create_traffic_endpoint) {
		pos += scnprintf(buffer + pos, size - pos, "Create Traffic Endpoint:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n",
				 req->nr_create_traffic_endpoint);
	}

	if (req->nr_create_mar) {
		pos += scnprintf(buffer + pos, size - pos, "Create MAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_mar);
	}

	if (req->nr_create_srr) {
		pos += scnprintf(buffer + pos, size - pos, "Create SRR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_srr);
	}
}

static void
pfcp_session_modification_req_format(struct pfcp_msg *msg, char *buffer, size_t size)
{
	struct pfcp_session_modification_request *req = msg->session_modification_request;
	size_t pos = 0;
	int i;

	if (!msg || !buffer || size == 0 || !req)
		return;

	if (req->node_id)
		pos += pfcp_node_id_format(req->node_id, buffer + pos, size - pos);

	if (req->cp_f_seid)
		pos += pfcp_seid_format(req->cp_f_seid, buffer + pos, size - pos);

	/* Remove IEs */
	if (req->nr_remove_pdr) {
		pos += scnprintf(buffer + pos, size - pos, "Remove PDR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_remove_pdr);
		for (i = 0; i < req->nr_remove_pdr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  PDR[%d]:\n", i);
			if (req->remove_pdr[i]->pdr_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    PDR ID: %u\n",
						 ntohs(req->remove_pdr[i]->pdr_id->rule_id));
		}
	}

	if (req->nr_remove_far) {
		pos += scnprintf(buffer + pos, size - pos, "Remove FAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_remove_far);
		for (i = 0; i < req->nr_remove_far; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  FAR[%d]:\n", i);
			if (req->remove_far[i]->far_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    FAR ID: %u\n",
						 ntohl(req->remove_far[i]->far_id->value));
		}
	}

	if (req->nr_remove_urr) {
		pos += scnprintf(buffer + pos, size - pos, "Remove URR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_remove_urr);
		for (i = 0; i < req->nr_remove_urr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  URR[%d]:\n", i);
			if (req->remove_urr[i]->urr_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    URR ID: %u\n",
						 ntohl(req->remove_urr[i]->urr_id->value));
		}
	}

	if (req->nr_remove_qer) {
		pos += scnprintf(buffer + pos, size - pos, "Remove QER:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_remove_qer);
	}

	if (req->nr_remove_bar) {
		pos += scnprintf(buffer + pos, size - pos, "Remove BAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_remove_bar);
	}

	if (req->nr_remove_traffic_endpoint) {
		pos += scnprintf(buffer + pos, size - pos, "Remove Traffic Endpoint:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n",
				 req->nr_remove_traffic_endpoint);
	}

	if (req->nr_remove_mar) {
		pos += scnprintf(buffer + pos, size - pos, "Remove MAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_remove_mar);
	}

	if (req->nr_remove_srr) {
		pos += scnprintf(buffer + pos, size - pos, "Remove SRR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_remove_srr);
	}

	/* Create IEs */
	if (req->nr_create_pdr) {
		pos += scnprintf(buffer + pos, size - pos, "Create PDR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_pdr);
		for (i = 0; i < req->nr_create_pdr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  PDR[%d]:\n", i);
			if (req->create_pdr[i]->pdr_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    PDR ID: %u\n",
						 ntohs(req->create_pdr[i]->pdr_id->rule_id));
			if (req->create_pdr[i]->precedence)
				pos += scnprintf(buffer + pos, size - pos,
						 "    Precedence: %u\n",
						 ntohl(req->create_pdr[i]->precedence->value));
			if (req->create_pdr[i]->far_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    FAR ID: %u\n",
						 ntohl(req->create_pdr[i]->far_id->value));
			if (req->create_pdr[i]->qer_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    QER ID: %u\n",
						 ntohl(req->create_pdr[i]->qer_id->value));
			if (req->create_pdr[i]->urr_id)
				pos += pfcp_urr_id_format(req->create_pdr[i]->urr_id,
							  req->create_pdr[i]->nr_urr_id,
							  buffer + pos, size - pos);
		}
	}

	if (req->nr_create_far) {
		pos += scnprintf(buffer + pos, size - pos, "Create FAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_far);
		for (i = 0; i < req->nr_create_far; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  FAR[%d]:\n", i);
			if (req->create_far[i]->far_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    FAR ID: %u\n",
						 ntohl(req->create_far[i]->far_id->value));
			if (req->create_far[i]->apply_action)
				pos += scnprintf(buffer + pos, size - pos,
						 "    Apply Action: 0x%02x\n",
						 req->create_far[i]->apply_action->flags);
		}
	}

	if (req->nr_create_urr) {
		pos += scnprintf(buffer + pos, size - pos, "Create URR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_urr);
		for (i = 0; i < req->nr_create_urr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  URR[%d]:\n", i);
			pos += scnprintf(buffer + pos, size - pos, "    URR ID: %u\n",
					 ntohl(req->create_urr[i]->urr_id->value));
		}
	}

	if (req->nr_create_qer) {
		pos += scnprintf(buffer + pos, size - pos, "Create QER:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_qer);
		for (i = 0; i < req->nr_create_qer; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  QER[%d]:\n", i);
			pos += scnprintf(buffer + pos, size - pos, "    QER ID: %u\n",
					 ntohl(req->create_qer[i]->qer_id->value));
		}
	}

	if (req->nr_create_bar) {
		pos += scnprintf(buffer + pos, size - pos, "Create BAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_bar);
	}

	if (req->nr_create_traffic_endpoint) {
		pos += scnprintf(buffer + pos, size - pos, "Create Traffic Endpoint:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n",
				 req->nr_create_traffic_endpoint);
	}

	if (req->nr_create_mar) {
		pos += scnprintf(buffer + pos, size - pos, "Create MAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_mar);
	}

	if (req->nr_create_srr) {
		pos += scnprintf(buffer + pos, size - pos, "Create SRR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_create_srr);
	}

	/* Update IEs */
	if (req->nr_update_pdr) {
		pos += scnprintf(buffer + pos, size - pos, "Update PDR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_update_pdr);
		for (i = 0; i < req->nr_update_pdr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  PDR[%d]:\n", i);
			if (req->update_pdr[i]->pdr_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    PDR ID: %u\n",
						 ntohs(req->update_pdr[i]->pdr_id->rule_id));
		}
	}

	if (req->nr_update_far) {
		pos += scnprintf(buffer + pos, size - pos, "Update FAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_update_far);
		for (i = 0; i < req->nr_update_far; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  FAR[%d]:\n", i);
			if (req->update_far[i]->far_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    FAR ID: %u\n",
						 ntohl(req->update_far[i]->far_id->value));
		}
	}

	if (req->nr_update_urr) {
		pos += scnprintf(buffer + pos, size - pos, "Update URR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_update_urr);
		for (i = 0; i < req->nr_update_urr; i++) {
			pos += scnprintf(buffer + pos, size - pos, "  URR[%d]:\n", i);
			if (req->update_urr[i]->urr_id)
				pos += scnprintf(buffer + pos, size - pos,
						 "    URR ID: %u\n",
						 ntohl(req->update_urr[i]->urr_id->value));
		}
	}

	if (req->nr_update_qer) {
		pos += scnprintf(buffer + pos, size - pos, "Update QER:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_update_qer);
	}

	if (req->nr_update_bar) {
		pos += scnprintf(buffer + pos, size - pos, "Update BAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_update_bar);
	}

	if (req->nr_update_traffic_endpoint) {
		pos += scnprintf(buffer + pos, size - pos, "Update Traffic Endpoint:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n",
				 req->nr_update_traffic_endpoint);
	}

	if (req->nr_update_mar) {
		pos += scnprintf(buffer + pos, size - pos, "Update MAR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_update_mar);
	}

	if (req->nr_update_srr) {
		pos += scnprintf(buffer + pos, size - pos, "Update SRR:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Count: %d\n", req->nr_update_srr);
	}

	if (req->rat_type) {
		pos += scnprintf(buffer + pos, size - pos, "RAT Type:\n");
		pos += scnprintf(buffer + pos, size - pos, "  Value: %u\n", req->rat_type->value);
	}
}


/*
 *	PFCP Dump
 */
static const struct {
	void (*fmt) (struct pfcp_msg *msg, char *buffer, size_t size);
} pfcp_dump_msg[1 << 8] = {
	/* PFCP Node related */
	[PFCP_HEARTBEAT_REQUEST]                = { pfcp_heartbeat_req_format },
        [PFCP_PFD_MANAGEMENT_REQUEST]           = { NULL },
        [PFCP_ASSOCIATION_SETUP_REQUEST]        = { NULL },
        [PFCP_ASSOCIATION_UPDATE_REQUEST]       = { NULL },
        [PFCP_ASSOCIATION_RELEASE_REQUEST]      = { NULL },
        [PFCP_NODE_REPORT_REQUEST]              = { NULL },
        [PFCP_SESSION_SET_DELETION_REQUEST]     = { NULL },
        [PFCP_SESSION_SET_MODIFICATION_REQUEST] = { NULL },

	/* PFCP Session related */
        [PFCP_SESSION_ESTABLISHMENT_REQUEST]    = { pfcp_session_establishment_req_format },
        [PFCP_SESSION_MODIFICATION_REQUEST]     = { pfcp_session_modification_req_format },
        [PFCP_SESSION_DELETION_REQUEST]         = { NULL },
        [PFCP_SESSION_REPORT_REQUEST]           = { NULL },
};

static void
pfcp_proto_buffer_format(struct sockaddr_storage *addr, struct pkt_buffer *pbuff,
		         char *buffer, size_t size, enum pfcp_direction dir)
{
	int width = 73, padding_left, padding_right, text_len;
	const char *truncated = " Truncated ";
	char title[80] = {};
	size_t pos = 0;
	int i;

	snprintf(title, sizeof(title), " %s packet %s [%s]:%d len:%d ",
		 (dir == PFCP_DIR_INGRESS) ? "ingress" : "egress",
		 (dir == PFCP_DIR_INGRESS) ? "from" : "to",
		 inet_sockaddrtos(addr), ntohs(inet_sockaddrport(addr)),
		 pkt_buffer_len(pbuff));
	text_len = strlen(title) + 2;
	padding_left = (width - text_len) / 2;
	padding_right = width - text_len - padding_left;
	for (i = 0; i < padding_left; i++)
		pos += scnprintf(buffer + pos, size - pos, "━");
	pos += scnprintf(buffer + pos, size - pos, "┫");
	pos += scnprintf(buffer + pos, size - pos, "%s", title);
	pos += scnprintf(buffer + pos, size - pos, "┣");
	for (i = 0; i < padding_right; i++)
		pos += scnprintf(buffer + pos, size - pos, "━");
	pos += scnprintf(buffer + pos, size - pos, "\n");
	pos += hexdump_format("", (unsigned char *) buffer + pos, size - pos - 256,
			      pbuff->head, pkt_buffer_len(pbuff));
	pos += scnprintf(buffer + pos, size - pos, "\n");

	/* Truncate ? */
	if (pos >= size - 256) {
		text_len = strlen(truncated);
		padding_left = (width - text_len) / 2;
		padding_right = width - text_len - padding_left;
		for (i = 0; i < padding_left; i++)
			pos += scnprintf(buffer + pos, size - pos, "─");
		pos += scnprintf(buffer + pos, size - pos, "%s", truncated);
		for (i = 0; i < padding_right; i++)
			pos += scnprintf(buffer + pos, size - pos, "─");
		return;
	}

	/* Footer */
	for (i = 0; i < width; i++)
		pos += scnprintf(buffer + pos, size - pos, "─");
}

static void
pfcp_proto_header_format(struct pkt_buffer *pbuff, char *buffer, size_t size)
{
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	size_t pos = 0;

	/* PFCP Header */
	pos += scnprintf(buffer + pos, size - pos, "Header:\n");
	pos += scnprintf(buffer + pos, size - pos, "  Version: %d\n", pfcph->version);
	pos += scnprintf(buffer + pos, size - pos, "  Message Type: %s (%d)\n",
			 pfcp_msgtype2str(pfcph->type), pfcph->type);
	pos += scnprintf(buffer + pos, size - pos, "  Length: %d\n", ntohs(pfcph->length));
	if (pfcph->s) {
		pos += scnprintf(buffer + pos, size - pos, "  SEID: 0x%.8lx\n",
				 pfcph->seid);
		pos += scnprintf(buffer + pos, size - pos, "  Sequence Number: %u\n",
				 PFCP_SQN(pfcph->sqn));
	} else {
		pos += scnprintf(buffer + pos, size - pos, "  Sequence Number: %u\n",
				 PFCP_SQN(pfcph->sqn_only));
	}
}

void
pfcp_proto_dump(struct pfcp_server *srv, struct pfcp_msg *msg, struct sockaddr_storage *addr,
		enum pfcp_direction dir)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	char buffer[8192];
	size_t size = sizeof(buffer);

	pfcp_proto_buffer_format(addr, pbuff, buffer, size, dir);
	vty_brd_out("%s\n", buffer);
	pfcp_proto_header_format(pbuff, buffer, size);
	vty_brd_out("%s", buffer);

	if (!msg || !*(pfcp_dump_msg[pfcph->type].fmt))
		return;

	(*(pfcp_dump_msg[pfcph->type].fmt)) (msg, buffer, size);
	vty_brd_out("%s\n", buffer);
}
