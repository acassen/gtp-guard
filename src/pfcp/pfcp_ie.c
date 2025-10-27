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
#include "pfcp.h"


/*
 *	PFCP Pkt IE Factory
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
pfcp_ie_put_cause(struct pkt_buffer *pbuff, uint8_t cause)
{
	struct pfcp_ie_cause *ie;
	unsigned int length = sizeof(*ie);

	if (pfcp_ie_put(pbuff, PFCP_IE_CAUSE, sizeof(*ie)) < 0)
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


