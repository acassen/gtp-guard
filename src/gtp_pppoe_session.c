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
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Local data */


/*
 *	PPPoE Protocol datagram
 */
static int
pppoe_send_padi(gtp_pppoe_session_t *s, struct ether_addr *s_eth)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	struct ether_header *eth;
	gtp_pkt_t *pkt;
	int len, l1 = 0, l2 = 0;
	uint8_t *p;

	/* service name tag is required, host unique is sent too */
	len = sizeof(pppoe_tag_t) + sizeof(pppoe_tag_t) + sizeof(s->unique);
	if (pppoe->service_name[0]) {
		l1 = strlen(pppoe->service_name);
		len += l1;
	}

	if (pppoe->ac_name[0]) {
		l2 = strlen(pppoe->ac_name);
		len += sizeof(pppoe_tag_t) + l2;
	}

	/* allocate a buffer */
	pkt = gtp_pkt_get(&pppoe->pkt_q);

	/* fill in pkt */
	eth = (struct ether_header *) pkt->pbuff->head;
	memset(eth->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eth->ether_shost, s_eth->ether_addr_octet, ETH_ALEN);
	eth->ether_type = htons(ETH_PPPOE_DISCOVERY);
	pkt_buffer_put_data(pkt->pbuff, sizeof(struct ether_header));

	p = pkt->pbuff->data;
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADI, 0, len);
	PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
	if (pppoe->service_name[0]) {
		PPPOE_ADD_16(p, l1);
		memcpy(p, pppoe->service_name, l1);
		p += l1;
	} else {
		PPPOE_ADD_16(p, 0);
	}
	if (pppoe->ac_name[0]) {
		PPPOE_ADD_16(p, PPPOE_TAG_ACNAME);
		PPPOE_ADD_16(p, l2);
		memcpy(p, pppoe->ac_name, l2);
		p += l2;
	}
	PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
	PPPOE_ADD_16(p, sizeof(s->unique));
	memcpy(p, &s->unique, sizeof(s->unique));
	p += sizeof(s->unique);
	pkt_buffer_put_data(pkt->pbuff, p - pkt->pbuff->data);
	pkt_buffer_set_end_pointer(pkt->pbuff, p - pkt->pbuff->head);

	/* send pkt */
	return gtp_pkt_send(pppoe->fd_disc, &pppoe->pkt_q, pkt);
}


/*
 *	PPPoE Sessions related
 */
int
gtp_pppoe_create_session(gtp_server_worker_t *w, ip_vrf_t *vrf, gtp_session_t *s)
{
	gtp_conn_t *conn = s->conn;
	gtp_pppoe_t *pppoe = vrf->pppoe;
	gtp_pppoe_session_t *s_pppoe;

	if (!pppoe)
		return -1;

	PMALLOC(s_pppoe);
	/* FIXME: make it really unique over global session tracking */
	s_pppoe->unique = poor_prng(&w->seed) ^ (uint32_t) conn->imsi;
	s_pppoe->session_time = time(NULL);
	s_pppoe->pppoe = vrf->pppoe;

	return pppoe_send_padi(s_pppoe, &conn->veth_addr);
}