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


/*
 *	PFCP Heartbeat Dump
 */
static void
pfcp_heartbeat_req_format(struct pkt_buffer *pbuff, char *buffer, size_t size)
{
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_heartbeat_request req = {};
	char addr_str[INET6_ADDRSTRLEN];
	size_t pos = 0;
	int err;

	if (!pbuff || !buffer || size == 0)
		return;

	err = pfcp_msg_parse(pbuff, &req);
	if (err) {
		scnprintf(buffer, size, "!!! Error while parsing [%s] Request !!!",
			  pfcp_msgtype2str(pfcph->type));
		return;
	}

	/* Recovery Time Stamp (Mandatory) */
	if (req.recovery_time_stamp)
		pos += pfcp_recovery_ts_format(req.recovery_time_stamp, buffer + pos, size - pos);

	/* Source IP Address (Optional) */
	if (req.source_ip_address) {
		pos += scnprintf(buffer + pos, size - pos, "Source IP Address:\n");
		if (req.source_ip_address->v4) {
			pos += scnprintf(buffer + pos, size - pos, "  IPv4: %d.%d.%d.%d\n",
					 NIPQUAD(req.source_ip_address->ipv4));
		}
		if (req.source_ip_address->v6) {
			if (inet_ntop(AF_INET6, &req.source_ip_address->ipv6, addr_str,
				      INET6_ADDRSTRLEN))
				pos += scnprintf(buffer + pos, size - pos, "  IPv6: %s\n", addr_str);
			else
				pos += scnprintf(buffer + pos, size - pos, "IPv6 [!!! malformed !!!]\n");
		}
	}
}


/*
 *	PFCP Dump
 */
static const struct {
	void (*fmt) (struct pkt_buffer *pbuff, char *buffer, size_t size);
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
        [PFCP_SESSION_ESTABLISHMENT_REQUEST]    = { NULL },
        [PFCP_SESSION_MODIFICATION_REQUEST]     = { NULL },
        [PFCP_SESSION_DELETION_REQUEST]         = { NULL },
        [PFCP_SESSION_REPORT_REQUEST]           = { NULL },
};

static void
pfcp_proto_buffer_format(struct sockaddr_storage *addr, struct pkt_buffer *pbuff,
		         char *buffer, size_t size, enum pfcp_direction dir)
{
	int width = 73, padding_left, padding_right, text_len;
	char title[80] = {};
	size_t pos = 0;
	int i;

	snprintf(title, sizeof(title), " %s packet %s [%s]:%d len:%d ",
		 (dir == PFCP_DIRECTION_INGRESS) ? "ingress" : "egress",
		 (dir == PFCP_DIRECTION_INGRESS) ? "from" : "to",
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
	pos += hexdump_format("", (unsigned char *) buffer + pos, size - pos,
			      pbuff->head, pkt_buffer_len(pbuff));
	pos += scnprintf(buffer + pos, size - pos, "\n");
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
pfcp_proto_dump(struct pfcp_server *srv, struct sockaddr_storage *addr,
		enum pfcp_direction dir)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	char buffer[4096];
	size_t size = sizeof(buffer);

	pfcp_proto_buffer_format(addr, pbuff, buffer, size, dir);
	vty_brd_out("%s\n", buffer);
	pfcp_proto_header_format(pbuff, buffer, size);
	vty_brd_out("%s", buffer);

	if (*(pfcp_dump_msg[pfcph->type].fmt)) {
		(*(pfcp_dump_msg[pfcph->type].fmt)) (pbuff, buffer, size);
		vty_brd_out("%s\n", buffer);
	}
}
