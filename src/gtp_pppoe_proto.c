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

static const struct ether_addr hw_brd = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};


/*
 *	PPPoE Protocol.
 *
 * 	This code is derivated from OpenBSD kernel source code which was originally
 *	contributed to The NetBSD Foundation by Martin Husemann <martin@NetBSD.org>.
 */


pkt_t *
pppoe_eth_pkt_get(spppoe_t *s, const struct ether_addr *hw_dst, const uint16_t proto)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	struct ether_header *eh;
	pkt_t *pkt;

	/* allocate a buffer */
	pkt = pkt_queue_get(&pppoe->pkt_q);
	if (!pkt)
		return NULL;

	/* fill in ethernet header */
	eh = (struct ether_header *) pkt->pbuff->head;
	memcpy(eh->ether_dhost, hw_dst, ETH_ALEN);
	memcpy(eh->ether_shost, &s->hw_src, ETH_ALEN);
	eh->ether_type = htons(proto);
	pkt_buffer_put_data(pkt->pbuff, sizeof(struct ether_header));

	return pkt;
}

static int
pppoe_vendor_specific_rate_append(uint8_t *p, uint8_t type, uint32_t rate)
{
	pppoe_vendor_tag_t *vendor_tag;
	uint32_t *value;
	int offset = 0;

	vendor_tag = (pppoe_vendor_tag_t *) p;
	vendor_tag->tag = type;
	vendor_tag->len = sizeof(uint32_t);
	offset += sizeof(pppoe_vendor_tag_t);
	value = (uint32_t *) (p + offset);
	*value = rate;
	offset += sizeof(uint32_t);

	return offset;
}

static int
pppoe_vendor_specific_tag_append(uint8_t *p, uint8_t type, uint8_t *value, uint8_t len)
{
	pppoe_vendor_tag_t *vendor_tag;
	int offset = 0;

	vendor_tag = (pppoe_vendor_tag_t *) p ;
	vendor_tag->tag = type;
	vendor_tag->len = len;
	offset += sizeof(pppoe_vendor_tag_t);
	memcpy(p + offset, value, len);
	offset += len;

	return offset;
}

static int
pppoe_vendor_specific_append(spppoe_t *s, uint8_t *p, bool rate_append)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	pppoe_tag_t *vendor_spec_tag;
	uint32_t *value;
	int offset = 0;

	if (!__test_bit(PPPOE_FL_VENDOR_SPECIFIC_BBF_BIT, &pppoe->flags))
		return 0;

	vendor_spec_tag = (pppoe_tag_t *) p;
	vendor_spec_tag->tag = htons(PPPOE_TAG_VENDOR);
	offset += sizeof(pppoe_tag_t);

	value = (uint32_t *) (p + offset);
	*value = htonl(PPPOE_VENDOR_ID_BBF);
	offset += sizeof(uint32_t);

	if (s->circuit_id[0])
		offset += pppoe_vendor_specific_tag_append(p + offset,
							   PPPOE_VENDOR_TAG_CIRCUIT_ID,
							   (uint8_t *) s->circuit_id,
							   strlen(s->circuit_id));
	if (s->remote_id[0])
		offset += pppoe_vendor_specific_tag_append(p + offset,
							   PPPOE_VENDOR_TAG_REMOTE_ID,
							   (uint8_t *) s->remote_id,
							   strlen(s->remote_id));
	if (rate_append) {
		offset += pppoe_vendor_specific_rate_append(p + offset,
							    PPPOE_VENDOR_TAG_UPSTREAM,
							    s->ambr_uplink);
		offset += pppoe_vendor_specific_rate_append(p + offset,
							    PPPOE_VENDOR_TAG_DOWNSTREAM,
							    s->ambr_downlink);
	}

	/* Update vendor tag header len */
	vendor_spec_tag->len = htons(offset - sizeof(pppoe_tag_t));
	return offset;
}

static int
pppoe_eth_pkt_pad(pkt_buffer_t *b, uint8_t *p)
{
	pkt_buffer_put_data(b, p - b->data);
	pkt_buffer_set_end_pointer(b, p - b->head);
	pkt_buffer_pad(b, ETH_ZLEN);
	return 0;
}

int
pppoe_send_padi(spppoe_t *s)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	pppoe_hdr_t *pppoeh;
	pkt_t *pkt;
	uint32_t *hunique;
	int len, l1 = 0, l2 = 0, vendor_spec_len = 0;
	uint8_t *p;

	/* service name tag is required, host unique is sent too */
	len = 2*sizeof(pppoe_tag_t) + sizeof(s->unique);	/* service name, host unique */
	if (pppoe->service_name[0]) {				/* service name tag maybe empty */
		l1 = strlen(pppoe->service_name);
		len += l1;
	}

	if (pppoe->ac_name[0]) {				/* Access-Concentrator*/
		l2 = strlen(pppoe->ac_name);
		len += sizeof(pppoe_tag_t) + l2;
	}

	/* get ethernet pkt buffer */
	pkt = pppoe_eth_pkt_get(s, &hw_brd, ETH_P_PPP_DISC);
	if (!pkt)
		return -1;

	/* fill in pkt */
	p = pkt->pbuff->data;
	pppoeh = (pppoe_hdr_t *) p;
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
	hunique = (uint32_t *) p;
	*hunique = htonl(s->unique);
	p += sizeof(s->unique);
	vendor_spec_len = pppoe_vendor_specific_append(s, p, false);
	pppoeh->plen = htons(len + vendor_spec_len);
	p += vendor_spec_len;
	pppoe_eth_pkt_pad(pkt->pbuff, p);

	/* send pkt */
	return gtp_pppoe_disc_send(pppoe, pkt);
}

static int
pppoe_send_padr(spppoe_t *s)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	pppoe_hdr_t *pppoeh;
	pkt_t *pkt;
	uint8_t *p;
	uint32_t *hunique;
	size_t len, l1 = 0, vendor_spec_len = 0;

	if (s->state != PPPOE_STATE_PADR_SENT)
		return -1;

	len = 2*sizeof(pppoe_tag_t) + sizeof(s->unique);	/* service name, host unique */
	if (pppoe->service_name[0]) {				/* service name tag maybe empty */
		l1 = strlen(pppoe->service_name);
		len += l1;
	}
	if (s->ac_cookie_len > 0)
		len += sizeof(pppoe_tag_t) + s->ac_cookie_len;	/* AC cookie */
	if (s->relay_sid_len > 0)
		len += sizeof(pppoe_tag_t) + s->relay_sid_len;	/* Relay SID */

	/* get ethernet pkt buffer */
	pkt = pppoe_eth_pkt_get(s, &s->hw_dst, ETH_P_PPP_DISC);
	if (!pkt)
		return -1;

	/* fill in pkt */
	p = pkt->pbuff->data;
	pppoeh = (pppoe_hdr_t *) p;
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADR, 0, len);

	PPPOE_ADD_16(p, PPPOE_TAG_SNAME);
	if (pppoe->service_name[0]) {
		PPPOE_ADD_16(p, l1);
		memcpy(p, pppoe->service_name, l1);
		p += l1;
	} else {
		PPPOE_ADD_16(p, 0);
	}
	if (s->ac_cookie_len > 0) {
		PPPOE_ADD_16(p, PPPOE_TAG_ACCOOKIE);
		PPPOE_ADD_16(p, s->ac_cookie_len);
		memcpy(p, s->ac_cookie, s->ac_cookie_len);
		p += s->ac_cookie_len;
	}
	if (s->relay_sid_len > 0) {
		PPPOE_ADD_16(p, PPPOE_TAG_RELAYSID);
		PPPOE_ADD_16(p, s->relay_sid_len);
		memcpy(p, s->relay_sid, s->relay_sid_len);
		p += s->relay_sid_len;
	}
	PPPOE_ADD_16(p, PPPOE_TAG_HUNIQUE);
	PPPOE_ADD_16(p, sizeof(s->unique));
	hunique = (uint32_t *) p;
	*hunique = htonl(s->unique);
	p += sizeof(s->unique);
	vendor_spec_len = pppoe_vendor_specific_append(s, p, true);
	pppoeh->plen = htons(len + vendor_spec_len);
	p += vendor_spec_len;
	pppoe_eth_pkt_pad(pkt->pbuff, p);

	/* send pkt */
	return gtp_pppoe_disc_send(pppoe, pkt);
}

static int
pppoe_send_padt(spppoe_t *s)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	pkt_t *pkt;
	uint8_t *p;

	/* get ethernet pkt buffer */
	pkt = pppoe_eth_pkt_get(s, &s->hw_dst, ETH_P_PPP_DISC);
	if (!pkt)
		return -1;

	/* fill in pkt */
	p = pkt->pbuff->data;
	PPPOE_ADD_HEADER(p, PPPOE_CODE_PADT, s->session_id, 0);
	pppoe_eth_pkt_pad(pkt->pbuff, p);

	/* send pkt */
	return gtp_pppoe_disc_send(pppoe, pkt);
}

int
pppoe_connect(spppoe_t *s)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	timer_thread_t *session_timer;
	int err, retry_wait = 2;

	if (s->state != PPPOE_STATE_INITIAL)
		return -1;

	s->state = PPPOE_STATE_PADI_SENT;
	s->padr_retried = 0;
	err = pppoe_send_padi(s);
	if (err < 0) {
		log_message(LOG_INFO, "%s(): Error sending padi (%m)"
				    , __FUNCTION__);
		return -1;
	}

	/* register timer */
	if (!__test_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags))
		retry_wait = PPPOE_DISC_TIMEOUT;
	session_timer = gtp_pppoe_get_session_timer(pppoe);
	timer_node_add(session_timer, &s->t_node, retry_wait);
	return 0;
}

int
pppoe_abort_connect(spppoe_t *s)
{
	PPPDEBUG(("%s: pppoe could not establish connection\n", s->pppoe->ifname));
	s->state = PPPOE_STATE_CLOSING;

	/* Notify ppp upper layer */
	sppp_down(s);
	return 0;
}

int
pppoe_disconnect(spppoe_t *s)
{
	timer_thread_t *session_timer;
	gtp_pppoe_t *pppoe = s->pppoe;
	int ret;

	PPPDEBUG(("%s: pppoe disconnect hunique:0x%.8x\n", s->pppoe->ifname, s->unique));

	/* Release pending session timer */
	session_timer = gtp_pppoe_get_session_timer(pppoe);
	timer_node_del(session_timer, &s->t_node);

	/* Send PADT if session is running */
	if (s->state >= PPPOE_STATE_SESSION) {
		ret = pppoe_send_padt(s);
		if (ret < 0) {
			log_message(LOG_INFO, "%s(): Error sending padt (%m)"
					, __FUNCTION__);
			return -1;
		}
	}

	/* Notify ppp upper layer */
	sppp_down(s);
	return 0;
}

int
pppoe_timeout(void *arg)
{
	spppoe_t *s = (spppoe_t *) arg;
	gtp_pppoe_t *pppoe = s->pppoe;
	timer_thread_t *session_timer;
	int retry_wait = 2;

	PPPDEBUG(("%s: pppoe hunique:0x%.8x\n", pppoe->ifname, s->unique));

	session_timer = gtp_pppoe_get_session_timer(pppoe);

	switch (s->state) {
	case PPPOE_STATE_PADI_SENT:
		if (++s->padi_retried >= PPPOE_DISC_MAXPADI) {
			pppoe_abort_connect(s);
			break;
		}

		if (pppoe_send_padi(s) < 0) {
			s->padi_retried--;
			PPPDEBUG(("%s: pppoe hunique:0x%.8x failed to transmit PADI\n",
				 pppoe->ifname, s->unique));
		}
		if (!__test_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags))
			retry_wait = PPPOE_DISC_TIMEOUT * (1 + s->padi_retried);
		timer_node_add(session_timer , &s->t_node, retry_wait);
		break;

	case PPPOE_STATE_PADR_SENT:
		if (++s->padr_retried >= PPPOE_DISC_MAXPADR) {
			s->state = PPPOE_STATE_PADI_SENT;
			s->padr_retried = 0;
			if (pppoe_send_padi(s) < 0) {
				PPPDEBUG(("%s: pppoe hunique:0x%.8x failed to send PADI\n",
					 pppoe->ifname, s->unique));
			}
			if (!__test_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags))
				retry_wait = PPPOE_DISC_TIMEOUT * (1 + s->padi_retried);
			timer_node_add(session_timer , &s->t_node, retry_wait);
			break;
		}

		if (pppoe_send_padr(s) < 0) {
			s->padr_retried--;
			PPPDEBUG(("%s: pppoe hunique:0x%.8x failed to send PADR\n",
				 pppoe->ifname, s->unique));
		}
		if (!__test_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags))
			retry_wait = PPPOE_DISC_TIMEOUT * (1 + s->padi_retried);
		timer_node_add(session_timer , &s->t_node, retry_wait);
		break;

	case PPPOE_STATE_CLOSING:
		pppoe_disconnect(s);
		break;

	default:
		break;	/* all done, work in peace */
	}

	return 0;
}

static int
pppoe_sanitize_pkt(gtp_pppoe_t *pppoe, pkt_t *pkt,
		   int *off, uint16_t *session, uint16_t *plen, uint8_t *code)
{
	struct ether_header *eh;
	pppoe_hdr_t *ph;

	eh = (struct ether_header *) pkt->pbuff->head;
	*off += sizeof(*eh);
	if (pkt_buffer_len(pkt->pbuff) - *off <= PPPOE_HEADERLEN) {
		log_message(LOG_INFO, "%s(): %s: packet too short: %d"
				    , __FUNCTION__, pppoe->ifname
				    , pkt_buffer_len(pkt->pbuff));
		return -1;
	}

	ph = (pppoe_hdr_t *) (pkt->pbuff->head + *off);
	if (ph->vertype != PPPOE_VERTYPE) {
		log_message(LOG_INFO, "%s(): %s: unknown version/type packet: 0x%.x"
				    , __FUNCTION__, pppoe->ifname
				    , ph->vertype);
		return -1;
	}
	*off += sizeof(*ph);

	*session = ntohs(ph->session);
	*plen = ntohs(ph->plen);
	*code = ph->code;
	if (*plen + *off > pkt_buffer_len(pkt->pbuff)) {
		log_message(LOG_INFO, "%s(): %s: packet content does not fit: "
				      "data available = %d, packet size = %u"
				    , __FUNCTION__, pppoe->ifname
				    , pkt_buffer_len(pkt->pbuff) - *off, plen);
		return -1;
	}

	return 0;
}

void
pppoe_dispatch_disc_pkt(gtp_pppoe_t *pppoe, pkt_t *pkt)
{
	spppoe_t *s = NULL;
	struct ether_header *eh;
	pppoe_tag_t *pt;
	const char *err_msg = NULL;
	size_t ac_cookie_len = 0;
	size_t relay_sid_len = 0;
	int i, off = 0, errortag = 0, max_payloadtag = 0, ret;
	uint16_t max_payload = 0;
	uint16_t tag = 0, len = 0;
	uint16_t session = 0, plen = 0;
	uint8_t *ac_cookie = NULL;
	uint8_t *relay_sid = NULL;
	uint32_t *hunique;
	uint8_t code = 0;
	uint8_t tmp[PPPOE_BUFSIZE];
	gtp_htab_t *session_tab, *unique_tab;
	timer_thread_t *session_timer;
	int retry_wait = 2;

	ret = pppoe_sanitize_pkt(pppoe, pkt, &off, &session, &plen, &code);
	if (ret < 0)
		return;
	eh = (struct ether_header *) pkt->pbuff->head;
	session_tab = gtp_pppoe_get_session_tab(pppoe);
	unique_tab = gtp_pppoe_get_unique_tab(pppoe);
	session_timer = gtp_pppoe_get_session_timer(pppoe);

	while (off + sizeof(*pt) <= pkt_buffer_len(pkt->pbuff)) {
		pt = (pppoe_tag_t *) (pkt->pbuff->head + off);
		tag = ntohs(pt->tag);
		len = ntohs(pt->len);
		off += sizeof(*pt);
		if (off + len > pkt_buffer_len(pkt->pbuff)) {
			log_message(LOG_INFO, "%s(): %s: tag 0x%.4x len 0x%.4x is too long\n"
					    , __FUNCTION__, pppoe->ifname
					    , tag, len);
			return;
		}
		switch (tag) {
		case PPPOE_TAG_EOL:
			goto breakbreak;
		case PPPOE_TAG_SNAME:
			break;	/* ignored */
		case PPPOE_TAG_ACNAME:
			break;	/* ignored */
		case PPPOE_TAG_HUNIQUE:
			/* Keep the first hunique */
			if (s != NULL)
				break;

			/* Make it 32bit strict parsing */
			if (len != sizeof(*hunique)) {
				log_message(LOG_INFO, "%s(): %s: hunique len 0x%.4x is too long\n"
						, __FUNCTION__, pppoe->ifname
						, len);
				return;
			}

			hunique = (uint32_t *) (pkt->pbuff->head + off);
			s = spppoe_get_by_unique(unique_tab, ntohl(*hunique));
			break;
		case PPPOE_TAG_ACCOOKIE:
			if (ac_cookie == NULL) {
				ac_cookie_len = len;
				ac_cookie = (uint8_t *) (pkt->pbuff->head + off);
			}
			break;
		case PPPOE_TAG_RELAYSID:
			if (relay_sid == NULL) {
				relay_sid_len = len;
				relay_sid = (uint8_t *) (pkt->pbuff->head + off);
			}
			break;
		case PPPOE_TAG_MAX_PAYLOAD:
			if (!max_payloadtag) {
				memcpy(&max_payload, pkt->pbuff->head + off, sizeof(max_payload));
				max_payloadtag = 1;
			}
			break;
		case PPPOE_TAG_SNAME_ERR:
			err_msg = "SERVICE NAME ERROR";
			errortag = 1;
			break;
		case PPPOE_TAG_ACSYS_ERR:
			err_msg = "AC SYSTEM ERROR";
			errortag = 1;
			break;
		case PPPOE_TAG_GENERIC_ERR:
			err_msg = "GENERIC ERROR";
			errortag = 1;
			break;
		}
		if (err_msg) {
			if (errortag && len) {
				uint8_t *cp = (uint8_t *) (pkt->pbuff->head + off);
				for (i = 0; i < len && i < PPPOE_BUFSIZE - 1; i++)
					tmp[i] = *cp++;
				tmp[i] = '\0';
				log_message(LOG_INFO, "%s(): %s: %s: %s"
						, __FUNCTION__, pppoe->ifname
						, err_msg, tmp);
			}
			return;
		}
		off += len;
	}
breakbreak:
	/* Using PPPoE bundle, PPP frames could be broadcasted to every interfaces
	 * part of the bundle. if "ignore-ingress-ppp-brd" feature is used then
	 * only take care of pkt on the same interface as the one used during
	 * session init */
	if (s && s->pppoe->bundle &&
	    __test_bit(PPPOE_FL_IGNORE_INGRESS_PPP_BRD_BIT, &s->pppoe->bundle->flags) &&
	    (s->pppoe->ifindex != pppoe->ifindex)) {
		PPPDEBUG(("%s: pppoe brd filtering..."
			  " s->pppoe->ifindex(%d)!=pppoe->ifindex(%d)"
			  " for %.2x:%.2x:%.2x:%.2x:%.2x:%.2x session = 0x%.4x\n",
			  pppoe->ifname, s->pppoe->ifindex, pppoe->ifindex,
			  ETHER_BYTES(eh->ether_dhost), session));
		return;
	}

	switch (code) {
	case PPPOE_CODE_PADI:
	case PPPOE_CODE_PADR:
		/* ignore, we are no access concentrator */
		return;
	case PPPOE_CODE_PADO:
		if (s == NULL) {
			log_message(LOG_INFO, "%s(): %s: received PADO but could not find request for it"
					    , __FUNCTION__, pppoe->ifname);
			return;
		}
		if (s->state != PPPOE_STATE_PADI_SENT) {
			log_message(LOG_INFO, "%s(): %s: received unexpected PADO (state:%d)"
					    , __FUNCTION__, pppoe->ifname, s->state);
			return;
		}
		if (ac_cookie) {
			if (s->ac_cookie)
				FREE(s->ac_cookie);
			s->ac_cookie = MALLOC(ac_cookie_len);
			if (s->ac_cookie == NULL) {
				s->ac_cookie_len = 0;
				return;
			}
			s->ac_cookie_len = ac_cookie_len;
			memcpy(s->ac_cookie, ac_cookie, ac_cookie_len);
		} else if (s->ac_cookie) {
			FREE(s->ac_cookie);
			s->ac_cookie = NULL;
			s->ac_cookie_len = 0;
		}
		if (relay_sid) {
			if (s->relay_sid)
				FREE(s->relay_sid);
			s->relay_sid = MALLOC(relay_sid_len);
			if (s->relay_sid == NULL) {
				s->relay_sid_len = 0;
				return;
			}
			s->relay_sid_len = relay_sid_len;
			memcpy(s->relay_sid, relay_sid, relay_sid_len);
		} else if (s->relay_sid) {
			FREE(s->relay_sid);
			s->relay_sid = NULL;
			s->relay_sid_len = 0;
		}

		memcpy(&s->hw_dst, eh->ether_shost, sizeof(s->hw_dst));
		s->padr_retried = 0;
		s->state = PPPOE_STATE_PADR_SENT;
		if (pppoe_send_padr(s) < 0) {
			PPPDEBUG(("%s: pppoe hunique:0x%.8x failed to send PADR (%m)\n",
				 pppoe->ifname, s->unique));
		}
		if (!__test_bit(PPPOE_FL_PADI_FAST_RETRY_BIT, &pppoe->flags))
			retry_wait = PPPOE_DISC_TIMEOUT * (1 + s->padr_retried);
		timer_node_add(session_timer, &s->t_node, retry_wait);
		break;
	case PPPOE_CODE_PADS:
		if (s == NULL)
			return;

		s->session_id = session;
		spppoe_session_hash(session_tab, s, &s->hw_src, s->session_id);
		timer_node_del(session_timer, &s->t_node);
		PPPDEBUG(("%s: pppoe hunique:0x%.8x session:0x%.4x hw:" ETHER_FMT " connected\n",
			 pppoe->ifname, s->unique, session,
			 ETHER_BYTES(s->hw_src.ether_addr_octet)));
		s->state = PPPOE_STATE_SESSION;
		s->session_time = time(NULL);

		/* Notify ppp layer */
		sppp_up(s);
		break;
	case PPPOE_CODE_PADT:
		if (s == NULL) {
			/* Some AC implementation doesnt tag PADT with Host-Uniq...
			 * At least that's the way it is with Cisco implementation.
			 * So try to find PPPoE session by session-id */
			s = spppoe_get_by_session(session_tab,
						  (struct ether_addr *) eh->ether_dhost, session);
			if (s == NULL)
				return;
		}

		/* stop timer (we might be about to transmit a PADT ourself) */
		timer_node_del(session_timer, &s->t_node);
		PPPDEBUG(("%s: pppoe hunique:0x%.8x session:0x%.4x terminated, received PADT\n",
			 pppoe->ifname, s->unique, session));
		sppp_down(s);
		break;
	default:
		log_message(LOG_INFO, "%s(): %s: unknown code (0x%04x) session = 0x%.4x"
				    , __FUNCTION__, pppoe->ifname
				    , code, session);
		break;
	}
}

void
pppoe_dispatch_session_pkt(gtp_pppoe_t *pppoe, pkt_t *pkt)
{
	struct ether_header *eh;
	spppoe_t *sp;
	int off = 0, ret;
	uint16_t session = 0, plen = 0;
	uint8_t code = 0;
	gtp_htab_t *session_tab;

	ret = pppoe_sanitize_pkt(pppoe, pkt, &off, &session, &plen, &code);
	if (ret < 0)
		return;
	eh = (struct ether_header *) pkt->pbuff->head;

	session_tab = gtp_pppoe_get_session_tab(pppoe);
	sp = spppoe_get_by_session(session_tab, (struct ether_addr *) eh->ether_dhost, session);
	if (!sp) {
		log_message(LOG_INFO, "%s(): %s: unknown pppoe session for "
				      "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x session = 0x%.4x"
				    , __FUNCTION__, pppoe->ifname
				    , ETHER_BYTES(eh->ether_shost), session);
		return;
	}

	if (code) {
		log_message(LOG_INFO, "%s(): %s: pppoe session invalid code:0x..2x for "
				      "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x session = 0x%.4x"
				    , __FUNCTION__, pppoe->ifname
				    , ETHER_BYTES(eh->ether_shost), session);
		return;
	}

	pkt_buffer_put_data(pkt->pbuff, off);

	/* Using PPPoE bundle, PPP frames could be broadcasted to every interfaces
	 * part of the bundle. if "ignore-ingress-ppp-brd" feature is used then
	 * only take care of pkt on the same interface as the one used during
	 * session init */
	if (sp->pppoe->bundle &&
	    __test_bit(PPPOE_FL_IGNORE_INGRESS_PPP_BRD_BIT, &sp->pppoe->bundle->flags) &&
	    (sp->pppoe->ifindex != pppoe->ifindex)) {
		PPPDEBUG(("%s: pppoe brd filtering..."
			  " sp->pppoe->ifindex(%d)!=pppoe->ifindex(%d)"
			  " for %.2x:%.2x:%.2x:%.2x:%.2x:%.2x session = 0x%.4x\n",
			  pppoe->ifname, sp->pppoe->ifindex, pppoe->ifindex,
			  ETHER_BYTES(eh->ether_dhost), session));
		return;
	}

	sppp_input(sp->s_ppp, pkt);
}
