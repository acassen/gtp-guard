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
#include <netinet/ip.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"



/*
 *	PPP Protocol.
 *
 * 	This code is derivated from OpenBSD kernel source code which was originally
 *	contributed to The NetBSD Foundation by Martin Husemann <martin@NetBSD.org>.
 */



/* a dummy, used to drop uninteresting events */
static void
sppp_null(__attribute__((unused)) sppp_t *unused)
{
	/* do just nothing */
}

/*
 * We follow the spelling and capitalization of RFC 1661 here, to make
 * it easier comparing with the standard.  Please refer to this RFC in
 * case you can't make sense out of these abbreviation; it will also
 * explain the semantics related to the various events and actions.
 */
struct cp {
	uint16_t	proto;		/* PPP control protocol number */
	uint8_t		protoidx;	/* index into state table in struct sppp */
	uint8_t		flags;
#define CP_LCP	0x01	/* this is the LCP */
#define CP_AUTH	0x02	/* this is an authentication protocol */
#define CP_NCP	0x04	/* this is a NCP */
#define CP_QUAL	0x08	/* this is a quality reporting protocol */
	const char	*name;	/* name of this control protocol */
	/* event handlers */
	void	(*Up) (sppp_t *);
	void	(*Down) (sppp_t *);
	void	(*Open) (sppp_t *);
	void	(*Close) (sppp_t *);
	int	(*TO) (void *);
	int	(*RCR) (sppp_t *, lcp_hdr_t *, int);
	void	(*RCN_rej) (sppp_t *, lcp_hdr_t *, int);
	void	(*RCN_nak) (sppp_t *, lcp_hdr_t *, int);
	/* actions */
	void	(*tlu) (sppp_t *);
	void	(*tld) (sppp_t *);
	void	(*tls) (sppp_t *);
	void	(*tlf) (sppp_t *);
	void	(*scr) (sppp_t *);
};

/* our control protocol descriptors */
static const struct cp lcp = {
	PPP_LCP, IDX_LCP, CP_LCP, "lcp",
	sppp_lcp_up, sppp_lcp_down, sppp_lcp_open, sppp_lcp_close,
	sppp_lcp_TO, sppp_lcp_RCR, sppp_lcp_RCN_rej, sppp_lcp_RCN_nak,
	sppp_lcp_tlu, sppp_lcp_tld, sppp_lcp_tls, sppp_lcp_tlf,
	sppp_lcp_scr
};

static const struct cp ipcp = {
	PPP_IPCP, IDX_IPCP, CP_NCP, "ipcp",
	sppp_ipcp_up, sppp_ipcp_down, sppp_ipcp_open, sppp_ipcp_close,
	sppp_ipcp_TO, sppp_ipcp_RCR, sppp_ipcp_RCN_rej, sppp_ipcp_RCN_nak,
	sppp_ipcp_tlu, sppp_null, sppp_ipcp_tls, sppp_ipcp_tlf,
	sppp_ipcp_scr
};

static const struct cp ipv6cp = {
	PPP_IPV6CP, IDX_IPV6CP,	CP_NCP,	"ipv6cp",
	sppp_ipv6cp_up, sppp_ipv6cp_down, sppp_ipv6cp_open, sppp_ipv6cp_close,
	sppp_ipv6cp_TO, sppp_ipv6cp_RCR, sppp_ipv6cp_RCN_rej, sppp_ipv6cp_RCN_nak,
	sppp_ipv6cp_tlu, sppp_null, sppp_ipv6cp_tls, sppp_ipv6cp_tlf,
	sppp_ipv6cp_scr
};

static const struct cp pap = {
	PPP_PAP, IDX_PAP, CP_AUTH, "pap",
	sppp_null, sppp_null, sppp_pap_open, sppp_pap_close,
	sppp_pap_TO, 0, 0, 0,
	sppp_pap_tlu, sppp_pap_tld, sppp_null, sppp_null,
	sppp_pap_scr
};

static const struct cp *cps[IDX_COUNT] = {
	&lcp,			/* IDX_LCP */
	&ipcp,			/* IDX_IPCP */
	&ipv6cp,		/* IDX_IPV6CP */
	&pap,			/* IDX_PAP */
};


/*
 *	Utilities
 */
const char *
sppp_cp_type_name(uint8_t type)
{
	switch (type) {
	case CONF_REQ:   return "conf-req";
	case CONF_ACK:   return "conf-ack";
	case CONF_NAK:   return "conf-nak";
	case CONF_REJ:   return "conf-rej";
	case TERM_REQ:   return "term-req";
	case TERM_ACK:   return "term-ack";
	case CODE_REJ:   return "code-rej";
	case PROTO_REJ:  return "proto-rej";
	case ECHO_REQ:   return "echo-req";
	case ECHO_REPLY: return "echo-reply";
	case DISC_REQ:   return "discard-req";
	}
	return "unknown";
}

const char *
sppp_auth_type_name(uint16_t proto, uint8_t type)
{
	switch (proto) {
	case PPP_CHAP:
		switch (type) {
		case CHAP_CHALLENGE:	return "challenge";
		case CHAP_RESPONSE:	return "response";
		case CHAP_SUCCESS:	return "success";
		case CHAP_FAILURE:	return "failure";
		}
	case PPP_PAP:
		switch (type) {
		case PAP_REQ:		return "req";
		case PAP_ACK:		return "ack";
		case PAP_NAK:		return "nak";
		}
	}
	return "unknown";
}

const char *
sppp_lcp_opt_name(uint8_t opt)
{
	switch (opt) {
	case LCP_OPT_MRU:		return "mru";
	case LCP_OPT_ASYNC_MAP:		return "async-map";
	case LCP_OPT_AUTH_PROTO:	return "auth-proto";
	case LCP_OPT_QUAL_PROTO:	return "qual-proto";
	case LCP_OPT_MAGIC:		return "magic";
	case LCP_OPT_PROTO_COMP:	return "proto-comp";
	case LCP_OPT_ADDR_COMP:		return "addr-comp";
	}
	return "unknown";
}

const char *
sppp_ipcp_opt_name(uint8_t opt)
{
	switch (opt) {
	case IPCP_OPT_ADDRESSES:	return "addresses";
	case IPCP_OPT_COMPRESSION:	return "compression";
	case IPCP_OPT_ADDRESS:		return "address";
	case IPCP_OPT_PRIMDNS:		return "primdns";
	case IPCP_OPT_SECDNS:		return "secdns";
	}
	return "unknown";
}

const char *
sppp_ipv6cp_opt_name(uint8_t opt)
{
	switch (opt) {
	case IPV6CP_OPT_IFID:		return "ifid";
	case IPV6CP_OPT_COMPRESSION:	return "compression";
	}
	return "unknown";
}

const char *
sppp_state_name(int state)
{
	switch (state) {
	case STATE_INITIAL:	return "initial";
	case STATE_STARTING:	return "starting";
	case STATE_CLOSED:	return "closed";
	case STATE_STOPPED:	return "stopped";
	case STATE_CLOSING:	return "closing";
	case STATE_STOPPING:	return "stopping";
	case STATE_REQ_SENT:	return "req-sent";
	case STATE_ACK_RCVD:	return "ack-rcvd";
	case STATE_ACK_SENT:	return "ack-sent";
	case STATE_OPENED:	return "opened";
	}
	return "illegal";
}

const char *
sppp_phase_name(enum ppp_phase phase)
{
	switch (phase) {
	case PHASE_DEAD:	return "dead";
	case PHASE_ESTABLISH:	return "establish";
	case PHASE_TERMINATE:	return "terminate";
	case PHASE_AUTHENTICATE: return "authenticate";
	case PHASE_NETWORK:	return "network";
	}
	return "illegal";
}

const char *
sppp_proto_name(uint16_t proto)
{
	static char buf[12];
	switch (proto) {
	case PPP_LCP:	return "lcp";
	case PPP_IPCP:	return "ipcp";
	case PPP_IPV6CP: return "ipv6cp";
	case PPP_PAP:	return "pap";
	case PPP_CHAP:	return "chap";
	}
	snprintf(buf, sizeof buf, "0x%x", (unsigned)proto);
	return buf;
}

static void
sppp_print_bytes(const uint8_t *p, uint16_t len)
{
	printf(" %02x", *p++);
	while (--len > 0)
		printf("-%02x", *p++);
}

void
sppp_print_string(const char *p, uint8_t len)
{
	uint8_t c;

	while (len-- > 0) {
		c = *p++;
		/*
		 * Print only ASCII chars directly.  RFC 1994 recommends
		 * using only them, but we don't rely on it.  */
		if (c < ' ' || c > '~')
			printf("\\x%x", c);
		else
			printf("%c", c);
	}
}

static void
sppp_log_error(sppp_t *sp, const char *errmsg)
{
	spppoe_t *s = sp->s_pppoe;
	log_message(LOG_INFO, "PPP-Error:={Host-Uniq:0x%.8x errmsg:%s}"
			    , s->unique
			    , errmsg);
}

/*
 *	PPP protocol implementation.
 */

void
sppp_increasing_timeout(const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timer_thread_t *ppp_timer;
	int timo;

	timo = sp->lcp.max_configure - sp->rst_counter[cp->protoidx];
	if (timo < 1)
		timo = 1;
	ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);
	timer_node_add(ppp_timer, &sp->ch[cp->protoidx], timo * sp->lcp.timeout);
}

/*
 * Change the state of a control protocol in the state automaton.
 * Takes care of starting/stopping the restart timer.
 */
void
sppp_cp_change_state(const struct cp *cp, sppp_t *sp, int newstate)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timer_thread_t *ppp_timer;

	if (debug & 8 && sp->state[cp->protoidx] != newstate)
		printf("%s: %s %s->%s\n",
		       pppoe->ifname, cp->name,
		       sppp_state_name(sp->state[cp->protoidx]),
		       sppp_state_name(newstate));
	sp->state[cp->protoidx] = newstate;
	ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);

	switch (newstate) {
	case STATE_INITIAL:
	case STATE_STARTING:
	case STATE_CLOSED:
	case STATE_STOPPED:
	case STATE_OPENED:
		timer_node_del(ppp_timer, &sp->ch[cp->protoidx]);
		break;
	case STATE_CLOSING:
	case STATE_STOPPING:
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
		if (!timer_node_pending(&sp->ch[cp->protoidx]))
			sppp_increasing_timeout(cp, sp);
		break;
	}
}

/*
 * Send PPP control protocol packet.
 */
int
sppp_cp_send(sppp_t *sp, uint16_t proto, uint8_t type,
	     uint8_t ident, uint16_t len, void *data)
{
	spppoe_t *s = sp->s_pppoe;
	gtp_pppoe_t *pppoe = s->pppoe;
	lcp_hdr_t *lh;
	uint8_t *p;
	pkt_t *pkt;
	int plen;

	/* get ethernet pkt buffer */
	pkt = pppoe_eth_pkt_get(s, &s->hw_dst, ETH_P_PPP_SES);

	/* PPPoE header*/
	p = pkt->pbuff->data;
	plen = sizeof(uint16_t) + sizeof(lcp_hdr_t) + len;
	PPPOE_ADD_HEADER(p, PPPOE_CODE_SESSION, s->session_id, plen);
	pkt_buffer_put_data(pkt->pbuff, sizeof(pppoe_hdr_t));

	/* PPP LCP TAG */
	p = pkt->pbuff->data;
	PPPOE_ADD_16(p, proto);
	pkt_buffer_put_data(pkt->pbuff, sizeof(uint16_t));

	/* LCP header */
	lh = (lcp_hdr_t *) pkt->pbuff->data;
	lh->type = type;
	lh->ident = ident;
	lh->len = htons(LCP_HEADER_LEN + len);
	if (len)
		bcopy(data, lh+1, len);
	pkt_buffer_put_data(pkt->pbuff, sizeof(lcp_hdr_t) + len);

	PPPDEBUG(("%s: %s output <%s id=0x%x len=%d",
		 pppoe->ifname,
		 sppp_proto_name(proto),
		 sppp_cp_type_name(lh->type), lh->ident,
		 ntohs(lh->len)));
	if (debug & 8 && len)
		sppp_print_bytes((uint8_t *) (lh+1), len);
	PPPDEBUG((">\n"));

	/* send pkt */
	pkt_buffer_set_end_pointer(pkt->pbuff, pkt->pbuff->data - pkt->pbuff->head);
	pkt_buffer_pad(pkt->pbuff, ETH_ZLEN);
	return gtp_pppoe_ses_send(pppoe, pkt);
}

/*
 * Handle incoming PPP control protocol packets.
 */
static void
sppp_cp_input(const struct cp *cp, sppp_t *sp, pkt_t *pkt)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	pkt_buffer_t *pbuff = pkt->pbuff;
	int rv, len = pbuff->end - pbuff->data;
	lcp_hdr_t *h;
	uint32_t nmagic;
	uint8_t *p;

	if (len < LCP_HEADER_LEN) {
		PPPDEBUG(("%s: %s invalid packet length: %d bytes\n",
			 pppoe->ifname, cp->name, len));
		return;
	}

	h = (lcp_hdr_t *) pbuff->data;
	PPPDEBUG(("%s: %s input(%s): <%s id=0x%x len=%d",
	         pppoe->ifname, cp->name,
	         sppp_state_name(sp->state[cp->protoidx]),
	         sppp_cp_type_name(h->type), h->ident, ntohs(h->len)));
	if (debug & 8 && len > 4)
		sppp_print_bytes((uint8_t *) (h+1), len-4);
	PPPDEBUG((">\n"));

	if (len > ntohs(h->len))
		len = ntohs(h->len);
	p = (uint8_t *) (h + 1);
	switch (h->type) {
	case CONF_REQ:
		if (len < 4) {
			PPPDEBUG(("%s: %s invalid conf-req length %d\n",
				 pppoe->ifname, cp->name, len));
			break;
		}
		/* handle states where RCR doesn't get a SCA/SCN */
		switch (sp->state[cp->protoidx]) {
		case STATE_CLOSING:
		case STATE_STOPPING:
			return;
		case STATE_CLOSED:
			sppp_cp_send(sp, cp->proto, TERM_ACK, h->ident, 0, 0);
			return;
		}
		rv = (cp->RCR)(sp, h, len);
		/* silently drop illegal packets */
		if (rv == -1)
			return;
		switch (sp->state[cp->protoidx]) {
		case STATE_OPENED:
			sppp_cp_change_state(cp, sp, rv ? STATE_ACK_SENT : STATE_REQ_SENT);
			(cp->tld)(sp);
			(cp->scr)(sp);
			break;
		case STATE_ACK_SENT:
		case STATE_REQ_SENT:
			sppp_cp_change_state(cp, sp, rv ? STATE_ACK_SENT : STATE_REQ_SENT);
			break;
		case STATE_STOPPED:
			sp->rst_counter[cp->protoidx] = sp->lcp.max_configure;
			sppp_cp_change_state(cp, sp, rv ? STATE_ACK_SENT : STATE_REQ_SENT);
			(cp->scr)(sp);
			break;
		case STATE_ACK_RCVD:
			if (rv) {
				sppp_cp_change_state(cp, sp, STATE_OPENED);
				PPPDEBUG(("%s: %s tlu\n", pppoe->ifname, cp->name));
				(cp->tlu)(sp);
			} else
				sppp_cp_change_state(cp, sp, STATE_ACK_RCVD);
			break;
		default:
			PPPDEBUG(("%s: %s illegal %s in state %s\n",
				 pppoe->ifname, cp->name,
				 sppp_cp_type_name(h->type),
				 sppp_state_name(sp->state[cp->protoidx])));
		}
		break;
	case CONF_ACK:
		if (h->ident != sp->confid[cp->protoidx]) {
			PPPDEBUG(("%s: %s id mismatch 0x%x != 0x%x\n",
				 pppoe->ifname, cp->name,
				 h->ident, sp->confid[cp->protoidx]));
			break;
		}
		switch (sp->state[cp->protoidx]) {
		case STATE_CLOSED:
		case STATE_STOPPED:
			sppp_cp_send(sp, cp->proto, TERM_ACK, h->ident, 0, 0);
			break;
		case STATE_CLOSING:
		case STATE_STOPPING:
			break;
		case STATE_REQ_SENT:
			sp->rst_counter[cp->protoidx] = sp->lcp.max_configure;
			sppp_cp_change_state(cp, sp, STATE_ACK_RCVD);
			break;
		case STATE_OPENED:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			(cp->tld)(sp);
			(cp->scr)(sp);
			break;
		case STATE_ACK_RCVD:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			(cp->scr)(sp);
			break;
		case STATE_ACK_SENT:
			sp->rst_counter[cp->protoidx] = sp->lcp.max_configure;
			sppp_cp_change_state(cp, sp, STATE_OPENED);
			PPPDEBUG(("%s: %s tlu\n", pppoe->ifname, cp->name));
			(cp->tlu)(sp);
			break;
		default:
			PPPDEBUG(("%s: %s illegal %s in state %s\n",
				 pppoe->ifname, cp->name,
				 sppp_cp_type_name(h->type),
				 sppp_state_name(sp->state[cp->protoidx])));
		}
		break;
	case CONF_NAK:
	case CONF_REJ:
		if (h->ident != sp->confid[cp->protoidx]) {
			PPPDEBUG(("%s: %s id mismatch 0x%x != 0x%x\n",
				 pppoe->ifname, cp->name,
				 h->ident, sp->confid[cp->protoidx]));
			break;
		}
		if (h->type == CONF_NAK)
			(cp->RCN_nak)(sp, h, len);
		else /* CONF_REJ */
			(cp->RCN_rej)(sp, h, len);

		switch (sp->state[cp->protoidx]) {
		case STATE_CLOSED:
		case STATE_STOPPED:
			sppp_cp_send(sp, cp->proto, TERM_ACK, h->ident, 0, 0);
			break;
		case STATE_REQ_SENT:
		case STATE_ACK_SENT:
			sp->rst_counter[cp->protoidx] = sp->lcp.max_configure;
			(cp->scr)(sp);
			break;
		case STATE_OPENED:
			sppp_cp_change_state(cp, sp, STATE_ACK_SENT);
			(cp->tld)(sp);
			(cp->scr)(sp);
			break;
		case STATE_ACK_RCVD:
			sppp_cp_change_state(cp, sp, STATE_ACK_SENT);
			(cp->scr)(sp);
			break;
		case STATE_CLOSING:
		case STATE_STOPPING:
			break;
		default:
			PPPDEBUG(("%s: %s illegal %s in state %s\n",
				 pppoe->ifname, cp->name,
				 sppp_cp_type_name(h->type),
				 sppp_state_name(sp->state[cp->protoidx])));
		}
		break;

	case TERM_REQ:
		switch (sp->state[cp->protoidx]) {
		case STATE_ACK_RCVD:
		case STATE_ACK_SENT:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			/* FALLTHROUGH */
		case STATE_CLOSED:
		case STATE_STOPPED:
		case STATE_CLOSING:
		case STATE_STOPPING:
		case STATE_REQ_SENT:
		  sta:
			/* Send Terminate-Ack packet. */
			PPPDEBUG(("%s: %s send terminate-ack\n",
				 pppoe->ifname, cp->name));
			sppp_cp_send(sp, cp->proto, TERM_ACK, h->ident, 0, 0);
			break;
		case STATE_OPENED:
			sp->rst_counter[cp->protoidx] = 0;
			sppp_cp_change_state(cp, sp, STATE_STOPPING);
			(cp->tld)(sp);
			goto sta;
			break;
		default:
			PPPDEBUG(("%s: %s illegal %s in state %s\n",
				 pppoe->ifname, cp->name,
				 sppp_cp_type_name(h->type),
				 sppp_state_name(sp->state[cp->protoidx])));
		}
		break;
	case TERM_ACK:
		switch (sp->state[cp->protoidx]) {
		case STATE_CLOSED:
		case STATE_STOPPED:
		case STATE_REQ_SENT:
		case STATE_ACK_SENT:
			break;
		case STATE_CLOSING:
			sppp_cp_change_state(cp, sp, STATE_CLOSED);
			(cp->tlf)(sp);
			break;
		case STATE_STOPPING:
			sppp_cp_change_state(cp, sp, STATE_STOPPED);
			(cp->tlf)(sp);
			break;
		case STATE_ACK_RCVD:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			break;
		case STATE_OPENED:
			sppp_cp_change_state(cp, sp, STATE_ACK_RCVD);
			(cp->tld)(sp);
			(cp->scr)(sp);
			break;
		default:
			PPPDEBUG(("%s: %s illegal %s in state %s\n",
				 pppoe->ifname, cp->name,
				 sppp_cp_type_name(h->type),
				 sppp_state_name(sp->state[cp->protoidx])));
		}
		break;
	case CODE_REJ:
	case PROTO_REJ:
	    {
		int catastrophic = 0;
		const struct cp *upper = NULL;
		int i;
		u_int16_t proto;

		if (len < 2) {
			PPPDEBUG(("%s: invalid proto-rej length\n", pppoe->ifname));
			break;
		}

		proto = ntohs(*((u_int16_t *)p));
		for (i = 0; i < IDX_COUNT; i++) {
			if (cps[i]->proto == proto) {
				upper = cps[i];
				break;
			}
		}
		if (upper == NULL)
			catastrophic++;

		if (catastrophic)
			log_message(LOG_INFO, "%s: RXJ%c (%s) for proto 0x%x (%s/%s)\n"
					    , pppoe->ifname, cp->name, catastrophic ? '-' : '+'
					    , sppp_cp_type_name(h->type), proto
					    , upper ? upper->name : "unknown"
					    , upper ? sppp_state_name(sp->state[upper->protoidx]) : "?");

		/*
		 * if we got RXJ+ against conf-req, the peer does not implement
		 * this particular protocol type.  terminate the protocol.
		 */
		if (upper) {
			if (sp->state[upper->protoidx] == STATE_REQ_SENT) {
				upper->Close(sp);
				break;
			}
		}

		/* XXX catastrophic rejects (RXJ-) aren't handled yet. */
		switch (sp->state[cp->protoidx]) {
		case STATE_CLOSED:
		case STATE_STOPPED:
		case STATE_REQ_SENT:
		case STATE_ACK_SENT:
		case STATE_CLOSING:
		case STATE_STOPPING:
		case STATE_OPENED:
			break;
		case STATE_ACK_RCVD:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			break;
		default:
			PPPDEBUG(("%s: %s illegal %s in state %s\n",
				 pppoe->ifname, cp->name,
				 sppp_cp_type_name(h->type),
				 sppp_state_name(sp->state[cp->protoidx])));
		}
		break;
	    }
	case DISC_REQ:
		if (cp->proto != PPP_LCP)
			goto illegal;
		/* Discard the packet. */
		break;
	case ECHO_REQ:
		if (cp->proto != PPP_LCP)
			goto illegal;
		if (sp->state[cp->protoidx] != STATE_OPENED) {
			PPPDEBUG(("%s: lcp echo req but lcp closed\n",
				 pppoe->ifname));
			break;
		}
		if (len < 8) {
			PPPDEBUG(("%s: invalid lcp echo request "
				  "packet length: %d bytes\n",
				 pppoe->ifname, len));
			break;
		}

		nmagic = (uint32_t)p[0] << 24 |
			 (uint32_t)p[1] << 16 | p[2] << 8 | p[3];

		if (nmagic == sp->lcp.magic) {
			/* Line loopback mode detected. */
			sppp_log_error(sp, "loopback_detected");
			/* Shut down the PPP link. */
			lcp.Close(sp);
			break;
		}

		p[0] = sp->lcp.magic >> 24;
		p[1] = sp->lcp.magic >> 16;
		p[2] = sp->lcp.magic >> 8;
		p[3] = sp->lcp.magic;

		PPPDEBUG(("%s: got lcp echo req, sending echo rep\n",
			 pppoe->ifname));
		sppp_cp_send(sp, PPP_LCP, ECHO_REPLY, h->ident, len-4, h+1);
		break;
	case ECHO_REPLY:
		if (cp->proto != PPP_LCP)
			goto illegal;
		if (h->ident != sp->lcp.echoid) {
			break;
		}
		if (len < 8) {
			PPPDEBUG(("%s: lcp invalid echo reply "
				  "packet length: %d bytes\n",
				 pppoe->ifname, len));
			break;
		}
		if (debug & 8)
			printf("%s: lcp got echo rep\n", pppoe->ifname);

		nmagic = (uint32_t)p[0] << 24 |
			 (uint32_t)p[1] << 16 | p[2] << 8 | p[3];

		if (nmagic != sp->lcp.magic)
			sp->pp_alivecnt = 0;
		break;
	default:
		/* Unknown packet type -- send Code-Reject packet. */
	  illegal:
		PPPDEBUG(("%s: %s send code-rej for 0x%x\n",
			 pppoe->ifname, cp->name, h->type));
		sppp_cp_send(sp, cp->proto, CODE_REJ, ++sp->pp_seq, len, h);
	}
}

void
sppp_input(sppp_t *sp, pkt_t *pkt)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	ppp_hdr_t ht;
	timeval_t tv;

	gettimeofday(&tv, NULL);
	sp->pp_last_receive = tv.tv_sec;

	ht.address = PPP_ALLSTATIONS;
	ht.control = PPP_UI;
	ht.protocol = *(uint16_t *) pkt->pbuff->data;
	pkt_buffer_put_data(pkt->pbuff, sizeof(uint16_t));

	switch (ntohs(ht.protocol)) {
	case PPP_LCP:
		sppp_cp_input(&lcp, sp, pkt);
		break;
	case PPP_PAP:
		if (sp->pp_phase >= PHASE_AUTHENTICATE)
			sppp_pap_input(sp, pkt);
		break;
	case PPP_IPCP:
		if (sp->pp_phase == PHASE_NETWORK)
			sppp_cp_input(&ipcp, sp, pkt);
		break;
	case PPP_IPV6CP:
		if (sp->pp_phase == PHASE_NETWORK)
			sppp_cp_input(&ipv6cp, sp, pkt);
		return;
	case PPP_IP:
	case PPP_IPV6:
		/* data-plane offloaded: if not: ignore */
		break;
	default:
		if (sp->state[IDX_LCP] == STATE_OPENED)
			sppp_cp_send(sp, PPP_LCP, PROTO_REJ,
				     ++sp->pp_seq, 2, &ht.protocol);
		PPPDEBUG(("%s: invalid input protocol "
			  "<addr=0x%x ctrl=0x%x proto=0x%x>\n",
			 pppoe->ifname,
			 ht.address, ht.control, ntohs(ht.protocol)));
		break;
	}
}

/*
 * The generic part of all Up/Down/Open/Close/TO event handlers.
 * Basically, the state transition handling in the automaton.
 */
void
sppp_up_event(const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	PPPDEBUG(("%s: %s up(%s)\n",
		 pppoe->ifname, cp->name,
		 sppp_state_name(sp->state[cp->protoidx])));

	switch (sp->state[cp->protoidx]) {
	case STATE_INITIAL:
		sppp_cp_change_state(cp, sp, STATE_CLOSED);
		break;
	case STATE_STARTING:
		sp->rst_counter[cp->protoidx] = sp->lcp.max_configure;
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		(cp->scr)(sp);
		break;
	default:
		/* printf(SPP_FMT "%s illegal up in state %s\n",
		       SPP_ARGS(ifp), cp->name,
		       sppp_state_name(sp->state[cp->protoidx])); */
		break;
	}
}

void
sppp_down_event(const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	PPPDEBUG(("%s: %s down(%s)\n",
		 pppoe->ifname, cp->name,
		 sppp_state_name(sp->state[cp->protoidx])));

	switch (sp->state[cp->protoidx]) {
	case STATE_CLOSED:
	case STATE_CLOSING:
		sppp_cp_change_state(cp, sp, STATE_INITIAL);
		break;
	case STATE_STOPPED:
		sppp_cp_change_state(cp, sp, STATE_STARTING);
		(cp->tls)(sp);
		break;
	case STATE_STOPPING:
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
		sppp_cp_change_state(cp, sp, STATE_STARTING);
		break;
	case STATE_OPENED:
		sppp_cp_change_state(cp, sp, STATE_STARTING);
		(cp->tld)(sp);
		break;
	default:
		/* printf(SPP_FMT "%s illegal down in state %s\n",
		       SPP_ARGS(ifp), cp->name,
		       sppp_state_name(sp->state[cp->protoidx])); */
		break;
	}
}


void
sppp_open_event(const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	PPPDEBUG(("%s: %s open(%s)\n",
		 pppoe->ifname, cp->name,
		 sppp_state_name(sp->state[cp->protoidx])));

	switch (sp->state[cp->protoidx]) {
	case STATE_INITIAL:
		sppp_cp_change_state(cp, sp, STATE_STARTING);
		(cp->tls)(sp);
		break;
	case STATE_STARTING:
		break;
	case STATE_CLOSED:
		sp->rst_counter[cp->protoidx] = sp->lcp.max_configure;
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		(cp->scr)(sp);
		break;
	case STATE_STOPPED:
	case STATE_STOPPING:
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
	case STATE_OPENED:
		break;
	case STATE_CLOSING:
		sppp_cp_change_state(cp, sp, STATE_STOPPING);
		break;
	}
}


void
sppp_close_event(const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	PPPDEBUG(("%s: %s close(%s)\n",
		 pppoe->ifname, cp->name,
		 sppp_state_name(sp->state[cp->protoidx])));

	switch (sp->state[cp->protoidx]) {
	case STATE_INITIAL:
	case STATE_CLOSED:
	case STATE_CLOSING:
		break;
	case STATE_STARTING:
		sppp_cp_change_state(cp, sp, STATE_INITIAL);
		(cp->tlf)(sp);
		break;
	case STATE_STOPPED:
		sppp_cp_change_state(cp, sp, STATE_CLOSED);
		break;
	case STATE_STOPPING:
		sppp_cp_change_state(cp, sp, STATE_CLOSING);
		break;
	case STATE_OPENED:
		sppp_cp_change_state(cp, sp, STATE_CLOSING);
		sp->rst_counter[cp->protoidx] = sp->lcp.max_terminate;
		sppp_cp_send(sp, cp->proto, TERM_REQ, ++sp->pp_seq, 0, 0);
		(cp->tld)(sp);
		break;
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
		sp->rst_counter[cp->protoidx] = sp->lcp.max_terminate;
		sppp_cp_send(sp, cp->proto, TERM_REQ, ++sp->pp_seq, 0, 0);
		sppp_cp_change_state(cp, sp, STATE_CLOSING);
		break;
	}
}

void
sppp_to_event(const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	PPPDEBUG(("%s: %s TO(%s) rst_counter = %d\n",
		 pppoe->ifname, cp->name,
		 sppp_state_name(sp->state[cp->protoidx]),
		 sp->rst_counter[cp->protoidx]));

	if (--sp->rst_counter[cp->protoidx] < 0) {
		/* TO- event */
		switch (sp->state[cp->protoidx]) {
		case STATE_CLOSING:
			sppp_cp_change_state(cp, sp, STATE_CLOSED);
			(cp->tlf)(sp);
			break;
		case STATE_STOPPING:
			sppp_cp_change_state(cp, sp, STATE_STOPPED);
			(cp->tlf)(sp);
			break;
		case STATE_REQ_SENT:
		case STATE_ACK_RCVD:
		case STATE_ACK_SENT:
			sppp_cp_change_state(cp, sp, STATE_STOPPED);
			(cp->tlf)(sp);
			break;
		}
	} else {
		/* TO+ event */
		switch (sp->state[cp->protoidx]) {
		case STATE_CLOSING:
		case STATE_STOPPING:
			sppp_cp_send(sp, cp->proto, TERM_REQ, ++sp->pp_seq,
				     0, 0);
			sppp_increasing_timeout (cp, sp);
			break;
		case STATE_REQ_SENT:
		case STATE_ACK_RCVD:
			/* sppp_cp_change_state() will restart the timer */
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			(cp->scr)(sp);
			break;
		case STATE_ACK_SENT:
			sppp_increasing_timeout (cp, sp);
			(cp->scr)(sp);
			break;
		}
	}
}

void
sppp_phase_network(sppp_t *sp)
{
	int i;
	uint32_t mask;

	sp->pp_phase = PHASE_NETWORK;

	/* Notify NCPs now. */
	for (i = 0; i < IDX_COUNT; i++)
		if ((cps[i])->flags & CP_NCP)
			(cps[i])->Open(sp);

	/* Send Up events to all NCPs. */
	for (i = 0, mask = 1; i < IDX_COUNT; i++, mask <<= 1)
		if (sp->lcp.protos & mask && ((cps[i])->flags & CP_NCP))
			(cps[i])->Up(sp);

	/* if no NCP is starting, all this was in vain, close down */
	sppp_lcp_check_and_close(sp);
}


/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                         The LCP implementation.                          *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */
void
sppp_lcp_init(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	__set_bit(LCP_OPT_MAGIC, &sp->lcp.opts);
	sp->lcp.magic = 0;
	sp->state[IDX_LCP] = STATE_INITIAL;
	sp->fail_counter[IDX_LCP] = 0;
	sp->lcp.protos = 0;
	sp->lcp.mru = sp->s_pppoe->pppoe->mru;
	sp->lcp.their_mru = 0;

	/*
	 * Initialize counters and timeout values.  Note that we don't
	 * use the 3 seconds suggested in RFC 1661 since we are likely
	 * running on a fast link.  XXX We should probably implement
	 * the exponential backoff option.  Note that these values are
	 * relevant for all control protocols, not just LCP only.
	 */
	sp->lcp.timeout = pppoe->lcp_timeout;
	sp->lcp.max_terminate = pppoe->lcp_max_terminate;
	sp->lcp.max_configure = pppoe->lcp_max_configure;
	sp->lcp.max_failure = pppoe->lcp_max_failure;
}

void
sppp_lcp_up(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timeval_t tv;

	sp->pp_alivecnt = 0;
	__set_bit(LCP_OPT_MAGIC, &sp->lcp.opts);
	sp->lcp.magic = 0;
	sp->lcp.protos = 0;
	sp->lcp.mru = (pppoe->mru && pppoe->mru != PP_MTU) ? pppoe->mru : PP_MTU;
	sp->lcp.their_mru = PP_MTU;

	gettimeofday(&tv, NULL);
	sp->pp_last_receive = sp->pp_last_activity = tv.tv_sec;

	if (sp->state[IDX_LCP] == STATE_INITIAL) {
		PPPDEBUG(("%s: UP event: incoming call\n", pppoe->ifname));
		lcp.Open(sp);
	}

	sppp_up_event(&lcp, sp);
}

void
sppp_lcp_down(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	sppp_down_event(&lcp, sp);

	PPPDEBUG(("%s: Down event (carrier loss)\n", pppoe->ifname));

	if (sp->state[IDX_LCP] != STATE_INITIAL)
		lcp.Close(sp);
	sp->lcp.their_mru = 0;
	sp->pp_flags &= ~PP_CALLIN;
}

void
sppp_lcp_open(sppp_t *sp)
{
	/*
	 * If we are authenticator, negotiate LCP_AUTH
	 */
	if (sp->hisauth.proto != 0)
		__set_bit(LCP_OPT_AUTH_PROTO, &sp->lcp.opts);
	else
		__clear_bit(LCP_OPT_AUTH_PROTO, &sp->lcp.opts);
	sp->pp_flags &= ~PP_NEEDAUTH;
	sppp_open_event(&lcp, sp);
}

void
sppp_lcp_close(sppp_t *sp)
{
	sppp_close_event(&lcp, sp);
}

int
sppp_lcp_TO(void *cookie)
{
	sppp_to_event(&lcp, (sppp_t *)cookie);
	return 0;
}

/*
 * Analyze a configure request.  Return true if it was agreeable, and
 * caused action sca, false if it has been rejected or nak'ed, and
 * caused action scn.  (The return value is used to make the state
 * transition decision in the state automaton.)
 */
int
sppp_lcp_RCR(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *buf, *r, *p;
	int origlen, rlen;
	uint32_t nmagic;
	uint16_t authproto;

	len -= 4;
	origlen = len;
	buf = r = MALLOC(origlen);
	if (!buf)
		return 0;

	PPPDEBUG(("%s: lcp parse opts: ", pppoe->ifname));

	/* pass 1: check for things that need to be rejected */
	p = (void *) (h + 1);
	for (rlen = 0; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len) {
			FREE(buf);
			return -1;
		}
		PPPDEBUG(("%s ", sppp_lcp_opt_name(*p)));
		switch (*p) {
		case LCP_OPT_MAGIC:
			/* Magic number. */
			/* FALLTHROUGH, both are same length */
		case LCP_OPT_ASYNC_MAP:
			/* Async control character map. */
			if (len >= 6 && p[1] == 6)
				continue;
			PPPDEBUG(("[invalid] "));
			break;
		case LCP_OPT_MRU:
			/* Maximum receive unit. */
			if (len >= 4 && p[1] == 4)
				continue;
			PPPDEBUG(("[invalid] "));
			break;
		case LCP_OPT_AUTH_PROTO:
			if (len < 4) {
				PPPDEBUG(("[invalid] "));
				break;
			}
			authproto = (p[2] << 8) + p[3];
			if (authproto == PPP_CHAP && p[1] != 5) {
				PPPDEBUG(("[invalid chap len] "));
				break;
			}
			if (sp->myauth.proto == 0) {
				/* we are not configured to do auth */
				PPPDEBUG(("[not configured] "));
				break;
			}
			/*
			 * Remote want us to authenticate, remember this,
			 * so we stay in PHASE_AUTHENTICATE after LCP got
			 * up.
			 */
			sp->pp_flags |= PP_NEEDAUTH;
			continue;
		default:
			/* Others not supported. */
			PPPDEBUG(("[rej] "));
			break;
		}
		/* Add the option to rejected list. */
		bcopy (p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		PPPDEBUG((" send conf-rej\n"));
		sppp_cp_send(sp, PPP_LCP, CONF_REJ, h->ident, rlen, buf);
		goto end;
	} else if (debug & 8)
		printf("\n");

	/*
	 * pass 2: check for option values that are unacceptable and
	 * thus require to be nak'ed.
	 */
	PPPDEBUG(("%s: lcp parse opt values: ", pppoe->ifname));

	p = (void *) (h + 1);
	len = origlen;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		PPPDEBUG(("%s ", sppp_lcp_opt_name(*p)));
		switch (*p) {
		case LCP_OPT_MAGIC:
			/* Magic number -- extract. */
			nmagic = (uint32_t)p[2] << 24 |
				 (uint32_t)p[3] << 16 | p[4] << 8 | p[5];
			if (nmagic != sp->lcp.magic) {
				PPPDEBUG(("0x%.8x ", nmagic));
				continue;
			}
			PPPDEBUG(("[glitch] "));
			++sp->pp_loopcnt;
			/*
			 * We negate our magic here, and NAK it.  If
			 * we see it later in an NAK packet, we
			 * suggest a new one.
			 */
			nmagic = ~sp->lcp.magic;
			/* Gonna NAK it. */
			p[2] = nmagic >> 24;
			p[3] = nmagic >> 16;
			p[4] = nmagic >> 8;
			p[5] = nmagic;
			break;

		case LCP_OPT_ASYNC_MAP:
			/* Async control character map -- check to be zero. */
			if (! p[2] && ! p[3] && ! p[4] && ! p[5]) {
				PPPDEBUG(("[empty] "));
				continue;
			}
			PPPDEBUG(("[non-empty] "));
			/* suggest a zero one */
			p[2] = p[3] = p[4] = p[5] = 0;
			break;

		case LCP_OPT_MRU:
			/*
			 * Maximum receive unit.  Always agreeable,
			 * but ignored by now.
			 */
			sp->lcp.their_mru = p[2] * 256 + p[3];
			PPPDEBUG(("%d ", sp->lcp.their_mru));
			continue;

		case LCP_OPT_AUTH_PROTO:
			authproto = (p[2] << 8) + p[3];
			if (sp->myauth.proto != authproto) {
				/* not agreed, nak */
				PPPDEBUG(("[mine %s != his %s] ",
					 sppp_proto_name(sp->hisauth.proto),
					 sppp_proto_name(authproto)));
				p[2] = sp->myauth.proto >> 8;
				p[3] = sp->myauth.proto;
				break;
			}
			if (authproto == PPP_CHAP && p[4] != CHAP_MD5) {
				PPPDEBUG(("[chap not MD5] "));
				p[4] = CHAP_MD5;
				break;
			}
			continue;
		}
		/* Add the option to nak'ed list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		if (++sp->fail_counter[IDX_LCP] >= sp->lcp.max_failure) {
			PPPDEBUG((" max_failure (%d) exceeded, "
				  "send conf-rej\n",
				 sp->lcp.max_failure));
			sppp_cp_send(sp, PPP_LCP, CONF_REJ, h->ident, rlen, buf);
		} else {
			PPPDEBUG((" send conf-nak\n"));
			sppp_cp_send(sp, PPP_LCP, CONF_NAK, h->ident, rlen, buf);
		}
		goto end;
	} else {
		PPPDEBUG(("send conf-ack\n"));
		sp->fail_counter[IDX_LCP] = 0;
		sp->pp_loopcnt = 0;
		sppp_cp_send(sp, PPP_LCP, CONF_ACK, h->ident, origlen, h+1);
	}

 end:
	FREE(buf);
	return (rlen == 0);
}

/*
 * Analyze the LCP Configure-Reject option list, and adjust our
 * negotiation.
 */
void
sppp_lcp_RCN_rej(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *p;

	len -= 4;

	PPPDEBUG(("%s: lcp rej opts: ", pppoe->ifname));

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		PPPDEBUG(("%s ", sppp_lcp_opt_name(*p)));
		switch (*p) {
		case LCP_OPT_MAGIC:
			/* Magic number -- can't use it, use 0 */
			sp->lcp.opts &= ~(1 << LCP_OPT_MAGIC);
			sp->lcp.magic = 0;
			break;
		case LCP_OPT_MRU:
			/*
			 * Should not be rejected anyway, since we only
			 * negotiate a MRU if explicitly requested by
			 * peer.
			 */
			sp->lcp.opts &= ~(1 << LCP_OPT_MRU);
			break;
		case LCP_OPT_AUTH_PROTO:
			/*
			 * Peer doesn't want to authenticate himself,
			 * deny unless this is a dialout call, and
			 * AUTHFLAG_NOCALLOUT is set.
			 */
			if ((sp->pp_flags & PP_CALLIN) == 0 &&
			    (sp->hisauth.flags & AUTHFLAG_NOCALLOUT) != 0) {
				PPPDEBUG(("[don't insist on auth "
					       "for callout]"));
				sp->lcp.opts &= ~(1 << LCP_OPT_AUTH_PROTO);
				break;
			}
			PPPDEBUG(("[access denied]\n"));
			lcp.Close(sp);
			break;
		}
	}
	PPPDEBUG(("\n"));
}

/*
 * Analyze the LCP Configure-NAK option list, and adjust our
 * negotiation.
 */
void
sppp_lcp_RCN_nak(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *p;
	uint32_t magic;

	len -= 4;

	PPPDEBUG(("%s: lcp nak opts: ", pppoe->ifname));

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		PPPDEBUG(("%s ", sppp_lcp_opt_name(*p)));
		switch (*p) {
		case LCP_OPT_MAGIC:
			/* Magic number -- renegotiate */
			if ((sp->lcp.opts & (1 << LCP_OPT_MAGIC)) &&
			    len >= 6 && p[1] == 6) {
				magic = (uint32_t)p[2] << 24 |
					(uint32_t)p[3] << 16 | p[4] << 8 | p[5];
				/*
				 * If the remote magic is our negated one,
				 * this looks like a loopback problem.
				 * Suggest a new magic to make sure.
				 */
				if (magic == ~sp->lcp.magic) {
					PPPDEBUG(("magic glitch "));
					sp->lcp.magic = poor_prng(&pppoe->seed);
				} else {
					sp->lcp.magic = magic;
					PPPDEBUG(("0x%.8x ", magic));
				}
			}
			break;
		case LCP_OPT_MRU:
			/*
			 * Peer wants to advise us to negotiate an MRU.
			 * Agree on it if it's reasonable, or use
			 * default otherwise.
			 */
			if (len >= 4 && p[1] == 4) {
				int mru = p[2] * 256 + p[3];
				PPPDEBUG(("%d ", mru));
				if (mru < PP_MIN_MRU)
					mru = PP_MIN_MRU;
				if (mru > PP_MAX_MRU)
					mru = PP_MAX_MRU;
				sp->lcp.mru = mru;
				sp->lcp.opts |= (1 << LCP_OPT_MRU);
			}
			break;
		case LCP_OPT_AUTH_PROTO:
			/*
			 * Peer doesn't like our authentication method,
			 * deny.
			 */
			PPPDEBUG(("[access denied]\n"));
			lcp.Close(sp);
			break;
		}
	}
	if (debug & 8)
		printf("\n");
}

void
sppp_lcp_tlu(sppp_t *sp)
{
	int i;
	uint32_t mask;

	for (i = 0; i < IDX_COUNT; i++)
		if ((cps[i])->flags & CP_QUAL)
			(cps[i])->Open(sp);

	if ((sp->lcp.opts & (1 << LCP_OPT_AUTH_PROTO)) != 0 ||
	    (sp->pp_flags & PP_NEEDAUTH) != 0)
		sp->pp_phase = PHASE_AUTHENTICATE;
	else
		sp->pp_phase = PHASE_NETWORK;

	/*
	 * Open all authentication protocols.  This is even required
	 * if we already proceeded to network phase, since it might be
	 * that remote wants us to authenticate, so we might have to
	 * send a PAP request.  Undesired authentication protocols
	 * don't do anything when they get an Open event.
	 */
	for (i = 0; i < IDX_COUNT; i++)
		if ((cps[i])->flags & CP_AUTH)
			(cps[i])->Open(sp);

	if (sp->pp_phase == PHASE_NETWORK) {
		/* Notify all NCPs. */
		for (i = 0; i < IDX_COUNT; i++)
			if ((cps[i])->flags & CP_NCP)
				(cps[i])->Open(sp);
	}

	/* Send Up events to all started protos. */
	for (i = 0, mask = 1; i < IDX_COUNT; i++, mask <<= 1)
		if (sp->lcp.protos & mask && ((cps[i])->flags & CP_LCP) == 0)
			(cps[i])->Up(sp);

	/* notify low-level driver of state change */
	if (sp->pp_chg)
		sp->pp_chg(sp, (int)sp->pp_phase);

	if (sp->pp_phase == PHASE_NETWORK)
		/* if no NCP is starting, close down */
		sppp_lcp_check_and_close(sp);
}

void
sppp_lcp_tld(sppp_t *sp)
{
	int i;
	uint32_t mask;

	sp->pp_phase = PHASE_TERMINATE;

	/*
	 * Take upper layers down.  We send the Down event first and
	 * the Close second to prevent the upper layers from sending
	 * ``a flurry of terminate-request packets'', as the RFC
	 * describes it.
	 */
	for (i = 0, mask = 1; i < IDX_COUNT; i++, mask <<= 1) {
		if (sp->lcp.protos & mask && ((cps[i])->flags & CP_LCP) == 0) {
			(cps[i])->Down(sp);
			(cps[i])->Close(sp);
		}
	}
}

void
sppp_lcp_tls(sppp_t *sp)
{
	sp->pp_phase = PHASE_ESTABLISH;

	/* Notify lower layer if desired. */
	if (sp->pp_tls)
		(sp->pp_tls)(sp);
}

void
sppp_lcp_tlf(sppp_t *sp)
{
	sp->pp_phase = PHASE_DEAD;

	/* Notify lower layer if desired. */
	if (sp->pp_tlf)
		(sp->pp_tlf)(sp);
}

void
sppp_lcp_scr(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	char opt[6 /* magicnum */ + 4 /* mru */ + 5 /* chap */];
	int i = 0;
	uint16_t authproto;

	if (__test_bit(LCP_OPT_MAGIC, &sp->lcp.opts)) {
		if (!sp->lcp.magic)
			sp->lcp.magic = poor_prng(&pppoe->seed);
		opt[i++] = LCP_OPT_MAGIC;
		opt[i++] = 6;
		opt[i++] = sp->lcp.magic >> 24;
		opt[i++] = sp->lcp.magic >> 16;
		opt[i++] = sp->lcp.magic >> 8;
		opt[i++] = sp->lcp.magic;
	}

	if (__test_bit(LCP_OPT_MRU, &sp->lcp.opts)) {
		opt[i++] = LCP_OPT_MRU;
		opt[i++] = 4;
		opt[i++] = sp->lcp.mru >> 8;
		opt[i++] = sp->lcp.mru;
	}

	if (__test_bit(LCP_OPT_AUTH_PROTO, &sp->lcp.opts)) {
		authproto = sp->hisauth.proto;
		opt[i++] = LCP_OPT_AUTH_PROTO;
		opt[i++] = authproto == PPP_CHAP ? 5: 4;
		opt[i++] = authproto >> 8;
		opt[i++] = authproto;
		if (authproto == PPP_CHAP)
			opt[i++] = CHAP_MD5;
	}

	sp->confid[IDX_LCP] = ++sp->pp_seq;
	sppp_cp_send(sp, PPP_LCP, CONF_REQ, sp->confid[IDX_LCP], i, opt);
}


/*
 * Check the open NCPs, return true if at least one NCP is open.
 */
int
sppp_ncp_check(sppp_t *sp)
{
	int i, mask;

	for (i = 0, mask = 1; i < IDX_COUNT; i++, mask <<= 1) {
		if (sp->lcp.protos & mask && (cps[i])->flags & CP_NCP) {
			return 1;
		}
	}
	return 0;
}

/*
 * Re-check the open NCPs and see if we should terminate the link.
 * Called by the NCPs during their tlf action handling.
 */
void
sppp_lcp_check_and_close(sppp_t *sp)
{

	if (sp->pp_phase < PHASE_NETWORK)
		/* don't bother, we are already going down */
		return;

	if (sppp_ncp_check(sp))
		return;

	lcp.Close(sp);
}


/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                        The IPCP implementation.                          *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */

void
sppp_ipcp_init(sppp_t *sp)
{
	sp->ipcp.opts = 0;
	sp->ipcp.flags = 0;
	sp->state[IDX_IPCP] = STATE_INITIAL;
	sp->fail_counter[IDX_IPCP] = 0;
}

void
sppp_ipcp_destroy(sppp_t *sp)
{
}

void
sppp_ipcp_up(sppp_t *sp)
{
	sppp_up_event(&ipcp, sp);
}

void
sppp_ipcp_down(sppp_t *sp)
{
	sppp_down_event(&ipcp, sp);
}

void
sppp_ipcp_open(sppp_t *sp)
{
	sppp_open_event(&ipcp, sp);
}

void
sppp_ipcp_close(sppp_t *sp)
{
	sppp_close_event(&ipcp, sp);
}

int
sppp_ipcp_TO(void *cookie)
{
	sppp_to_event(&ipcp, (sppp_t *)cookie);
	return 0;
}

/*
 * Analyze a configure request.  Return true if it was agreeable, and
 * caused action sca, false if it has been rejected or nak'ed, and
 * caused action scn.  (The return value is used to make the state
 * transition decision in the state automaton.)
 */
int
sppp_ipcp_RCR(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *buf, *r, *p;
	int rlen, origlen, buflen;
	uint32_t hisaddr = 0, desiredaddr;

	len -= 4;
	origlen = len;
	/*
	 * Make sure to allocate a buf that can at least hold a
	 * conf-nak with an `address' option.  We might need it below.
	 */
	buflen = len < 6? 6: len;
	buf = r = MALLOC(buflen);
	if (!buf)
		return 0;

	/* pass 1: see if we can recognize them */
	PPPDEBUG(("%s: ipcp parse opts: ", pppoe->ifname));
	p = (void *) (h + 1);
	for (rlen = 0; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len) {
			FREE(buf);
			return -1;
		}
		PPPDEBUG(("%s ", sppp_ipcp_opt_name(*p)));
		switch (*p) {
		case IPCP_OPT_ADDRESS:
			if (len >= 6 && p[1] == 6) {
				/* correctly formed address option */
				continue;
			}
			PPPDEBUG(("[invalid] "));
			break;
		default:
			/* Others not supported. */
			PPPDEBUG(("[rej] "));
			break;
		}
		/* Add the option to rejected list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		PPPDEBUG((" send conf-rej\n"));
		sppp_cp_send(sp, PPP_IPCP, CONF_REJ, h->ident, rlen, buf);
		goto end;
	}
	PPPDEBUG(("\n"));

	/* pass 2: parse option values */
	if (sp->ipcp.flags & IPCP_HISADDR_SEEN)
		hisaddr = sp->ipcp.req_hisaddr; /* we already agreed on that */
	PPPDEBUG(("%s: ipcp parse opt values: ", pppoe->ifname));
	p = (void *) (h + 1);
	len = origlen;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		PPPDEBUG((" %s ", sppp_ipcp_opt_name(*p)));
		switch (*p) {
		case IPCP_OPT_ADDRESS:
			desiredaddr = p[2] << 24 | p[3] << 16 |
				p[4] << 8 | p[5];
			if (desiredaddr == hisaddr ||
			    ((sp->ipcp.flags & IPCP_HISADDR_DYN) &&
			    desiredaddr != 0)) {
				/*
				 * Peer's address is same as our value,
				 * or we have set it to 0.0.0.1 to
				 * indicate that we do not really care,
				 * this is agreeable.  Gonna conf-ack
				 * it.
				 */
				uint32_t ndesiredaddr = htonl(desiredaddr);
				PPPDEBUG(("%u.%u.%u.%u [ack] ",
					 NIPQUAD(ndesiredaddr)));
				/* record that we've seen it already */
				sp->ipcp.flags |= IPCP_HISADDR_SEEN;
				sp->ipcp.req_hisaddr = desiredaddr;
				hisaddr = desiredaddr;
				continue;
			}
			/*
			 * The address wasn't agreeable.  This is either
			 * he sent us 0.0.0.0, asking to assign him an
			 * address, or he send us another address not
			 * matching our value.  Either case, we gonna
			 * conf-nak it with our value.
			 */
			uint32_t ndesiredaddr = htonl(desiredaddr);
			if (desiredaddr == 0)
				PPPDEBUG(("[addr requested] "));
			else
				PPPDEBUG(("%u.%u.%u.%u [not agreed] ",
					 NIPQUAD(ndesiredaddr)));

			p[2] = hisaddr >> 24;
			p[3] = hisaddr >> 16;
			p[4] = hisaddr >> 8;
			p[5] = hisaddr;
			break;
		}
		/* Add the option to nak'ed list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}

	/*
	 * If we are about to conf-ack the request, but haven't seen
	 * his address so far, gonna conf-nak it instead, with the
	 * `address' option present and our idea of his address being
	 * filled in there, to request negotiation of both addresses.
	 *
	 * XXX This can result in an endless req - nak loop if peer
	 * doesn't want to send us his address.  Q: What should we do
	 * about it?  XXX  A: implement the max-failure counter.
	 */
	if (rlen == 0 && !(sp->ipcp.flags & IPCP_HISADDR_SEEN)) {
		buf[0] = IPCP_OPT_ADDRESS;
		buf[1] = 6;
		buf[2] = hisaddr >> 24;
		buf[3] = hisaddr >> 16;
		buf[4] = hisaddr >> 8;
		buf[5] = hisaddr;
		rlen = 6;
		PPPDEBUG(("still need hisaddr "));
	}

	if (rlen) {
		PPPDEBUG((" send conf-nak\n"));
		sppp_cp_send(sp, PPP_IPCP, CONF_NAK, h->ident, rlen, buf);
	} else {
		PPPDEBUG((" send conf-ack\n"));
		sppp_cp_send(sp, PPP_IPCP, CONF_ACK, h->ident, origlen, h+1);
	}

 end:
	FREE(buf);
	return (rlen == 0);
}

/*
 * Analyze the IPCP Configure-Reject option list, and adjust our
 * negotiation.
 */
void
sppp_ipcp_RCN_rej(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *p;

	len -= 4;

	PPPDEBUG(("%s: ipcp rej opts: ", pppoe->ifname));

	p = (void*) (h+1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		PPPDEBUG(("%s ", sppp_ipcp_opt_name(*p)));
		switch (*p) {
		case IPCP_OPT_ADDRESS:
			/*
			 * Peer doesn't grok address option.  This is
			 * bad.  XXX  Should we better give up here?
			 */
			sp->ipcp.opts &= ~(1 << SPPP_IPCP_OPT_ADDRESS);
			break;
		case IPCP_OPT_PRIMDNS:
			sp->ipcp.opts &= ~(1 << SPPP_IPCP_OPT_PRIMDNS);
			break;
		case IPCP_OPT_SECDNS:
			sp->ipcp.opts &= ~(1 << SPPP_IPCP_OPT_SECDNS);
			break;
		}
	}
	PPPDEBUG(("\n"));
}

/*
 * Analyze the IPCP Configure-NAK option list, and adjust our
 * negotiation.
 */
void
sppp_ipcp_RCN_nak(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *p;
	uint32_t wantaddr;

	len -= 4;

	PPPDEBUG(("%s: ipcp nak opts: ", pppoe->ifname));

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		PPPDEBUG(("%s ", sppp_ipcp_opt_name(*p)));
		switch (*p) {
		case IPCP_OPT_ADDRESS:
			/*
			 * Peer doesn't like our local IP address.  See
			 * if we can do something for him.  We'll drop
			 * him our address then.
			 */
			if (len >= 6 && p[1] == 6) {
				wantaddr = p[2] << 24 | p[3] << 16 | p[4] << 8 | p[5];
				sp->ipcp.opts |= (1 << SPPP_IPCP_OPT_ADDRESS);
				uint32_t nwantaddr = htonl(wantaddr);
				PPPDEBUG(("[Xwantaddr %u.%u.%u.%u] ", NIPQUAD(nwantaddr)));
				/*
				 * When doing dynamic address assignment,
				 * we accept his offer.  Otherwise, we
				 * ignore it and thus continue to negotiate
				 * our already existing value.
				 */
				if (sp->ipcp.flags & IPCP_MYADDR_DYN) {
					PPPDEBUG(("[agree] "));
					sp->ipcp.flags |= IPCP_MYADDR_SEEN;
					sp->ipcp.req_myaddr = wantaddr;
				}
			}
			break;
		case IPCP_OPT_PRIMDNS:
			if (len >= 6 && p[1] == 6) {
				memcpy(&sp->ipcp.dns[0].s_addr, p + 2, sizeof(sp->ipcp.dns[0]));
				PPPDEBUG(("[pri dns addr %u.%u.%u.%u] ", NIPQUAD(sp->ipcp.dns[0].s_addr)));
			}
			break;
		case IPCP_OPT_SECDNS:
			if (len >= 6 && p[1] == 6) {
				memcpy(&sp->ipcp.dns[1].s_addr, p + 2, sizeof(sp->ipcp.dns[1]));
				PPPDEBUG(("[sec dns addr %u.%u.%u.%u] ", NIPQUAD(sp->ipcp.dns[1].s_addr)));
			}
			break;
		}
	}
	PPPDEBUG(("\n"));
}

void
sppp_ipcp_tlu(sppp_t *sp)
{
	if (sp->pp_con)
		(sp->pp_con)(sp);
}

void
sppp_ipcp_tls(sppp_t *sp)
{
	sp->ipcp.flags &= ~(IPCP_HISADDR_SEEN|IPCP_MYADDR_SEEN|IPCP_MYADDR_DYN|IPCP_HISADDR_DYN);
	sp->ipcp.req_myaddr = 0;
	sp->ipcp.req_hisaddr = 0;
	memset(&sp->ipcp.dns, 0, sizeof(sp->ipcp.dns));

	/*
	 * I don't have an assigned address, so i need to
	 * negotiate my address.
	 */
	sp->ipcp.flags |= IPCP_MYADDR_DYN;
	sp->ipcp.opts |= (1 << SPPP_IPCP_OPT_ADDRESS);

	/*
	 * remote has no valid address, we need to get one assigned.
	 */
	sp->ipcp.flags |= IPCP_HISADDR_DYN;

	/* negotiate name server addresses */
	sp->ipcp.opts |= (1 << SPPP_IPCP_OPT_PRIMDNS);
	sp->ipcp.opts |= (1 << SPPP_IPCP_OPT_SECDNS);

	/* indicate to LCP that it must stay alive */
	sp->lcp.protos |= (1 << IDX_IPCP);
}

void
sppp_ipcp_tlf(sppp_t *sp)
{
	/* we no longer need LCP */
	sp->lcp.protos &= ~(1 << IDX_IPCP);
	sppp_lcp_check_and_close(sp);
}

void
sppp_ipcp_scr(sppp_t *sp)
{
	uint8_t opt[6 /* compression */ + 6 /* address */ + 12 /* dns addrs */];
	u_int32_t ouraddr = 0;
	int i = 0;

	if (sp->ipcp.opts & (1 << SPPP_IPCP_OPT_ADDRESS)) {
		if (sp->ipcp.flags & IPCP_MYADDR_SEEN)
			ouraddr = sp->ipcp.req_myaddr;
		opt[i++] = IPCP_OPT_ADDRESS;
		opt[i++] = 6;
		opt[i++] = ouraddr >> 24;
		opt[i++] = ouraddr >> 16;
		opt[i++] = ouraddr >> 8;
		opt[i++] = ouraddr;
	}

	if (sp->ipcp.opts & (1 << SPPP_IPCP_OPT_PRIMDNS)) {
		opt[i++] = IPCP_OPT_PRIMDNS;
		opt[i++] = 6;
		memcpy(&opt[i], &sp->ipcp.dns[0].s_addr, sizeof(sp->ipcp.dns[0]));
		i += sizeof(sp->ipcp.dns[0]);
	}

	if (sp->ipcp.opts & (1 << SPPP_IPCP_OPT_SECDNS)) {
		opt[i++] = IPCP_OPT_SECDNS;
		opt[i++] = 6;
		memcpy(&opt[i], &sp->ipcp.dns[1].s_addr, sizeof(sp->ipcp.dns[1]));
		i += sizeof(sp->ipcp.dns[1]);
	}

	sp->confid[IDX_IPCP] = ++sp->pp_seq;
	sppp_cp_send(sp, PPP_IPCP, CONF_REQ, sp->confid[IDX_IPCP], i, opt);
}


/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                      The IPv6CP implementation.                          *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */

void
sppp_ipv6cp_init(sppp_t *sp)
{
	spppoe_t *s = sp->s_pppoe;

	sp->ipv6cp.opts = 0;
	sp->ipv6cp.flags = IPV6CP_MYIFID_DYN;
	sp->state[IDX_IPV6CP] = STATE_INITIAL;
	sp->fail_counter[IDX_IPV6CP] = 0;

	/* Build Interface ID from Ethernet Address */
	gtp_ifid_from_ether_build(&s->hw_src, &sp->ipv6cp.req_ifid);
}

void
sppp_ipv6cp_destroy(sppp_t *sp)
{
}

void
sppp_ipv6cp_up(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	if (__test_bit(PPPOE_FL_IPV6CP_DISABLE_BIT, &pppoe->flags))
		return;
	sppp_up_event(&ipv6cp, sp);
}

void
sppp_ipv6cp_down(sppp_t *sp)
{
	sppp_down_event(&ipv6cp, sp);
}

void
sppp_ipv6cp_open(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	if (__test_bit(PPPOE_FL_IPV6CP_DISABLE_BIT, &pppoe->flags))
		return;
	sp->ipv6cp.opts |= (1 << IPV6CP_OPT_IFID);
	sppp_open_event(&ipv6cp, sp);
}

void
sppp_ipv6cp_close(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	if (__test_bit(PPPOE_FL_IPV6CP_DISABLE_BIT, &pppoe->flags))
		return;
	sppp_close_event(&ipv6cp, sp);
}

int
sppp_ipv6cp_TO(void *cookie)
{
	sppp_to_event(&ipv6cp, (sppp_t *)cookie);
	return 0;
}

int
sppp_ipv6cp_RCR(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *buf, *r, *p;
	int rlen, origlen, buflen;
	struct in6_addr myaddr, desiredaddr, suggestaddr = IN6ADDR_ANY_INIT;
	int ifidcount;
	int type;
	int collision, nohisaddr;
	char addr[INET6_ADDRSTRLEN];

	len -= 4;
	origlen = len;
	/*
	 * Make sure to allocate a buf that can at least hold a
	 * conf-nak with an `address' option.  We might need it below.
	 */
	buflen = len < 6? 6: len;
	buf = r = MALLOC(buflen);
	if (!buf)
		return (0);

	/* pass 1: see if we can recognize them */
	PPPDEBUG(("%s: ipv6cp parse opts: ", pppoe->ifname));
	p = (void *) (h + 1);
	ifidcount = 0;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		/* Sanity check option length */
		if (p[1] < 2 || p[1] > len) {
			FREE(buf);
			return -1;
		}
		PPPDEBUG(("%s ", sppp_ipv6cp_opt_name(*p)));
		switch (*p) {
		case IPV6CP_OPT_IFID:
			if (len >= 10 && p[1] == 10 && ifidcount == 0) {
				/* correctly formed address option */
				ifidcount++;
				continue;
			}
			PPPDEBUG(("[invalid] "));
			break;
		default:
			/* Others not supported. */
			PPPDEBUG(("[rej] "));
			break;
		}
		/* Add the option to rejected list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		PPPDEBUG(("send conf-rej\n"));
		sppp_cp_send(sp, PPP_IPV6CP, CONF_REJ, h->ident, rlen, buf);
		goto end;
	}
	PPPDEBUG(("\n"));

	/* pass 2: parse option values */
	if (sp->ipv6cp.flags & IPV6CP_MYIFID_DYN)
		myaddr = sp->ipv6cp.req_ifid;
	PPPDEBUG(("%s: ipv6cp parse opt values: ", pppoe->ifname));
	p = (void *) (h + 1);
	len = origlen;
	type = CONF_ACK;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		PPPDEBUG((" %s", sppp_ipv6cp_opt_name(*p)));
		switch (*p) {
		case IPV6CP_OPT_IFID:
			memset(&desiredaddr, 0, sizeof(desiredaddr));
			bcopy(&p[2], &desiredaddr.s6_addr[8], 8);
			collision = (memcmp(&desiredaddr.s6_addr[8],
					&myaddr.s6_addr[8], 8) == 0);
			nohisaddr = IN6_IS_ADDR_UNSPECIFIED(&desiredaddr);

			desiredaddr.s6_addr16[0] = htons(0xfe80);

			if (!collision && !nohisaddr) {
				/* no collision, hisaddr known - Conf-Ack */
				type = CONF_ACK;

				PPPDEBUG((" %s [%s]",
					 inet_ntop(AF_INET6, &desiredaddr,
					 addr, sizeof(addr)),
					 sppp_cp_type_name(type)));
				continue;
			}

			memset(&suggestaddr, 0, sizeof(suggestaddr));
			if (collision && nohisaddr) {
				/* collision, hisaddr unknown - Conf-Rej */
				type = CONF_REJ;
				memset(&p[2], 0, 8);
			} else {
				/*
				 * - no collision, hisaddr unknown, or
				 * - collision, hisaddr known
				 * Conf-Nak, suggest hisaddr
				 */
				type = CONF_NAK;
				//sppp_suggest_ip6_addr(sp, &suggestaddr);
				bcopy(&suggestaddr.s6_addr[8], &p[2], 8);
			}
			PPPDEBUG((" %s [%s]",
				 inet_ntop(AF_INET6, &desiredaddr, addr, sizeof(addr)),
				 sppp_cp_type_name(type)));
			break;
		}
		/* Add the option to nak'ed list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}

	if (rlen == 0 && type == CONF_ACK) {
		PPPDEBUG((" send %s\n", sppp_cp_type_name(type)));
		sppp_cp_send(sp, PPP_IPV6CP, type, h->ident, origlen, h + 1);
	} else {
		PPPDEBUG((" send %s suggest %s\n", sppp_cp_type_name(type),
			 inet_ntop(AF_INET6, &suggestaddr, addr, sizeof(addr))));
		sppp_cp_send(sp, PPP_IPV6CP, type, h->ident, rlen, buf);
	}

end:
	FREE(buf);
	return (rlen == 0);
}

void
sppp_ipv6cp_RCN_rej(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *p;

	len -= 4;

	PPPDEBUG(("%s: ipv6cp rej opts: ", pppoe->ifname));

	p = (void *) (h + 1);
	for (; len > 1 && p[1]; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		PPPDEBUG(("%s ", sppp_ipv6cp_opt_name(*p)));
		switch (*p) {
		case IPV6CP_OPT_IFID:
			/*
			 * Peer doesn't grok address option.  This is
			 * bad.  XXX  Should we better give up here?
			 */
			sp->ipv6cp.opts &= ~(1 << IPV6CP_OPT_IFID);
			break;
		}
	}
	PPPDEBUG(("\n"));
	return;
}

void
sppp_ipv6cp_RCN_nak(sppp_t *sp, lcp_hdr_t *h, int len)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	uint8_t *p;
	struct in6_addr suggestaddr = IN6ADDR_ANY_INIT;
	char addr[INET6_ADDRSTRLEN];

	len -= 4;

	PPPDEBUG(("%s: ipv6cp nak opts: ", pppoe->ifname));

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		PPPDEBUG(("%s ", sppp_ipv6cp_opt_name(*p)));
		switch (*p) {
		case IPV6CP_OPT_IFID:
			/*
			 * Peer doesn't like our local ifid.  See
			 * if we can do something for him.  We'll drop
			 * him our address then.
			 */
			if (len < 10 || p[1] != 10)
				break;
			sp->ipv6cp.flags |= IPV6CP_MYIFID_DYN;
			bcopy(&p[2], &suggestaddr.s6_addr[8], 8);
			if (IN6_IS_ADDR_UNSPECIFIED(&suggestaddr) ||
			    (sp->ipv6cp.flags & IPV6CP_MYIFID_SEEN)) {
				/*
				 * The peer didn't suggest anything,
				 * or wants us to change a previously
				 * suggested address.
				 * Configure a new address for us.
				 */
				//sppp_suggest_ip6_addr(sp, &suggestaddr);
				sp->ipv6cp.flags &= ~IPV6CP_MYIFID_SEEN;
			} else {
				/* Configure address suggested by peer. */
				suggestaddr.s6_addr16[0] = htons(0xfe80);
				sp->ipv6cp.opts |= (1 << IPV6CP_OPT_IFID);
				PPPDEBUG((" [suggestaddr %s] [agree]",
					 inet_ntop(AF_INET6, &suggestaddr,
						   addr, sizeof(addr))));
				sp->ipv6cp.flags |= IPV6CP_MYIFID_SEEN;
			}
			break;
		}
	}
	PPPDEBUG(("\n"));
}

void
sppp_ipv6cp_tlu(sppp_t *sp)
{
}

void
sppp_ipv6cp_tls(sppp_t *sp)
{
	/* indicate to LCP that it must stay alive */
	sp->lcp.protos |= (1 << IDX_IPV6CP);
}

void
sppp_ipv6cp_tlf(sppp_t *sp)
{
	/* we no longer need LCP */
	sp->lcp.protos &= ~(1 << IDX_IPV6CP);
	sppp_lcp_check_and_close(sp);
}

void
sppp_ipv6cp_scr(sppp_t *sp)
{
	char opt[10 /* ifid */ + 4 /* compression, minimum */];
	struct in6_addr ouraddr = IN6ADDR_ANY_INIT;
	int i = 0;

	if (sp->ipv6cp.opts & (1 << IPV6CP_OPT_IFID)) {
		if (sp->ipv6cp.flags & IPV6CP_MYIFID_DYN)
			ouraddr = sp->ipv6cp.req_ifid;
		opt[i++] = IPV6CP_OPT_IFID;
		opt[i++] = 10;
		bcopy(&ouraddr.s6_addr[8], &opt[i], 8);
		i += 8;
	}


	sp->confid[IDX_IPV6CP] = ++sp->pp_seq;
	sppp_cp_send(sp, PPP_IPV6CP, CONF_REQ, sp->confid[IDX_IPV6CP], i, opt);
}


/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                        The PAP implementation.                           *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */
/*
 * For PAP, we need to keep a little state also if we are the peer, not the
 * authenticator.  This is since we don't get a request to authenticate, but
 * have to repeatedly authenticate ourself until we got a response (or the
 * retry counter is expired).
 */

void
sppp_auth_send(const struct cp *cp, sppp_t *sp, unsigned int type, int id, ...)
{
	spppoe_t *s = sp->s_pppoe;
	gtp_pppoe_t *pppoe = s->pppoe;
	pppoe_hdr_t *ph;
	lcp_hdr_t *lh;
	pkt_t *pkt;
	uint8_t *p;
	int len = 0;
	unsigned int mlen;
	const char *msg;
	uint16_t *proto;
	va_list ap;

	/* get ethernet pkt buffer */
	pkt = pppoe_eth_pkt_get(s, &s->hw_dst, ETH_P_PPP_SES);

	/* PPPoE header */
	ph = (pppoe_hdr_t *) pkt->pbuff->data;
	p = pkt->pbuff->data;
	PPPOE_ADD_HEADER(p, PPPOE_CODE_SESSION, s->session_id, 0);
	pkt_buffer_put_data(pkt->pbuff, sizeof(pppoe_hdr_t));

	/* PPP Auth TAG */
	proto = (uint16_t *) pkt->pbuff->data;
	*proto = htons(cp->proto);
	pkt_buffer_put_data(pkt->pbuff, sizeof(uint16_t));

	/* LCP header */
	lh = (lcp_hdr_t *) pkt->pbuff->data;
	lh->type = type;
	lh->ident = id;
	pkt_buffer_put_data(pkt->pbuff, LCP_HEADER_LEN);

	/* Data */
	p = (uint8_t *) pkt->pbuff->data;
	va_start(ap, id);
	while ((mlen = (unsigned int)va_arg(ap, size_t)) != 0) {
		msg = va_arg(ap, const char *);
		len += mlen;
		if (len > DEFAULT_PKT_BUFFER_SIZE - PKTHDRLEN - LCP_HEADER_LEN) {
			va_end(ap);
			return;
		}

		bcopy(msg, p, mlen);
		p += mlen;
	}
	va_end(ap);
	pkt_buffer_put_data(pkt->pbuff, len);

	/* Adjust header len */
	lh->len = htons(LCP_HEADER_LEN + len);
	ph->plen = htons(LCP_HEADER_LEN + len + 2);

	PPPDEBUG(("%s: %s output <%s id=0x%x len=%d",
		 pppoe->ifname, cp->name,
		 sppp_auth_type_name(cp->proto, lh->type),
		 lh->ident, ntohs(lh->len)));
	if (debug & 8 && len)
		sppp_print_bytes((uint8_t *) (lh + 1), len);
	PPPDEBUG((">\n"));

	/* send pkt */
	pkt_buffer_set_end_pointer(pkt->pbuff, pkt->pbuff->data - pkt->pbuff->head);
	pkt_buffer_pad(pkt->pbuff, ETH_ZLEN);
	gtp_pppoe_ses_send(pppoe, pkt);
}

/*
 * Handle incoming PAP packets.  */
void
sppp_pap_input(sppp_t *sp, pkt_t *pkt)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	pkt_buffer_t *pbuff = pkt->pbuff;
	int len = pbuff->end - pbuff->data;
	timer_thread_t *ppp_timer;
	lcp_hdr_t *h;
	uint8_t *name, *passwd, mlen;
	int name_len, passwd_len;

	if (len < 5) {
		PPPDEBUG(("%s: pap invalid packet length: %d bytes\n",
			 pppoe->ifname, len));
		return;
	}

	ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);
	h = (lcp_hdr_t *) pbuff->data;
	if (len > ntohs(h->len))
		len = ntohs(h->len);
	switch (h->type) {
	/* PAP request is my authproto */
	case PAP_REQ:
		name = 1 + (uint8_t *) (h + 1);
		name_len = name[-1];
		passwd = name + name_len + 1;
		if (name_len > len - 6 ||
		    (passwd_len = passwd[-1]) > len - 6 - name_len) {
			PPPDEBUG(("%s: pap corrupted input <%s id=0x%x len=%d",
				 pppoe->ifname,
				 sppp_auth_type_name(PPP_PAP, h->type),
				 h->ident, ntohs(h->len)));
			if (debug & 8 && len > 4)
				sppp_print_bytes((uint8_t *) (h + 1), len - 4);
			PPPDEBUG((">\n"));
			break;
		}

		PPPDEBUG(("%s: pap input(%s) <%s id=0x%x len=%d name=",
		       pppoe->ifname,
		       sppp_state_name(sp->state[IDX_PAP]),
		       sppp_auth_type_name(PPP_PAP, h->type),
		       h->ident, ntohs(h->len)));
		if (debug & 8)
			sppp_print_string((char*)name, name_len);
		PPPDEBUG((" passwd="));
		if (debug & 8)
			sppp_print_string((char*)passwd, passwd_len);
		PPPDEBUG((">\n"));

		if (name_len > AUTHMAXLEN ||
		    passwd_len > AUTHMAXLEN ||
		    bcmp(name, sp->hisauth.name, name_len) != 0 ||
		    bcmp(passwd, sp->hisauth.secret, passwd_len) != 0) {
			/* action scn, tld */
			mlen = sizeof(FAILMSG) - 1;
			sppp_auth_send(&pap, sp, PAP_NAK, h->ident,
				       sizeof mlen, (const char *)&mlen,
				       sizeof(FAILMSG) - 1, (uint8_t *)FAILMSG,
				       0);
			pap.tld(sp);
			break;
		}
		/* action sca, perhaps tlu */
		if (sp->state[IDX_PAP] == STATE_REQ_SENT ||
		    sp->state[IDX_PAP] == STATE_OPENED) {
			mlen = sizeof(SUCCMSG) - 1;
			sppp_auth_send(&pap, sp, PAP_ACK, h->ident,
				       sizeof mlen, (const char *)&mlen,
				       sizeof(SUCCMSG) - 1, (uint8_t *)SUCCMSG,
				       0);
		}
		if (sp->state[IDX_PAP] == STATE_REQ_SENT) {
			sppp_cp_change_state(&pap, sp, STATE_OPENED);
			pap.tlu(sp);
		}
		break;

	/* ack and nak are his authproto */
	case PAP_ACK:
		timer_node_del(ppp_timer, &sp->pap_my_to_ch);
		if (debug & 8) {
			PPPDEBUG(("%s: pap success", pppoe->ifname));
			name_len = *((char *)h);
			if (len > 5 && name_len) {
				PPPDEBUG((": "));
				if (debug & 8)
					sppp_print_string((char *)(h + 1), name_len);
			}
			PPPDEBUG(("\n"));
		}
		sp->pp_flags &= ~PP_NEEDAUTH;
		if (sp->myauth.proto == PPP_PAP &&
		    (sp->lcp.opts & (1 << LCP_OPT_AUTH_PROTO)) &&
		    (sp->lcp.protos & (1 << IDX_PAP)) == 0) {
			/*
			 * We are authenticator for PAP but didn't
			 * complete yet.  Leave it to tlu to proceed
			 * to network phase.
			 */
			break;
		}
		sppp_phase_network(sp);
		break;

	case PAP_NAK:
		timer_node_del(ppp_timer, &sp->pap_my_to_ch);
		if (debug & 8) {
			PPPDEBUG(("%s: pap failure", pppoe->ifname));
			name_len = *((char *)h);
			if (len > 5 && name_len) {
				PPPDEBUG((": "));
				if (debug & 8)
					sppp_print_string((char*)(h + 1), name_len);
			}
			PPPDEBUG(("\n"));
		}

		__set_bit(GTP_PPPOE_FL_AUTH_FAILED, &sp->s_pppoe->flags);
		sppp_log_error(sp, "pap_failure");
		/* await LCP shutdown by authenticator */
		break;

	default:
		/* Unknown PAP packet type -- ignore. */
		__set_bit(GTP_PPPOE_FL_AUTH_FAILED, &sp->s_pppoe->flags);
		PPPDEBUG(("%s: pap corrupted input <0x%x id=0x%x len=%d",
			 pppoe->ifname, h->type, h->ident, ntohs(h->len)));
		if (debug & 8 && len > 4)
			sppp_print_bytes((uint8_t *)(h + 1), len - 4);
		PPPDEBUG((">\n"));
		break;

	}
}

void
sppp_pap_init(sppp_t *sp)
{
	/* PAP doesn't have STATE_INITIAL at all. */
	sp->state[IDX_PAP] = STATE_CLOSED;
	sp->fail_counter[IDX_PAP] = 0;
}

void
sppp_pap_open(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timer_thread_t *ppp_timer;

	if (sp->hisauth.proto == PPP_PAP &&
	    (sp->lcp.opts & (1 << LCP_OPT_AUTH_PROTO)) != 0) {
		/* we are authenticator for PAP, start our timer */
		sp->rst_counter[IDX_PAP] = sp->lcp.max_configure;
		sppp_cp_change_state(&pap, sp, STATE_REQ_SENT);
	}
	if (sp->myauth.proto == PPP_PAP) {
		/* we are peer, send a request, and start a timer */
		pap.scr(sp);
		ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);
		timer_node_add(ppp_timer, &sp->pap_my_to_ch, sp->lcp.timeout);
	}
}

void
sppp_pap_close(sppp_t *sp)
{
	if (sp->state[IDX_PAP] != STATE_CLOSED)
		sppp_cp_change_state(&pap, sp, STATE_CLOSED);
}

/*
 * That's the timeout routine if we are authenticator.  Since the
 * authenticator is basically passive in PAP, we can't do much here.
 */
int
sppp_pap_TO(void *cookie)
{
	sppp_t *sp = (sppp_t *)cookie;
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	PPPDEBUG(("%s: pap TO(%s) rst_counter = %d\n",
		 pppoe->ifname,
		 sppp_state_name(sp->state[IDX_PAP]),
		 sp->rst_counter[IDX_PAP]));

	if (--sp->rst_counter[IDX_PAP] < 0) {
		/* TO- event */
		switch (sp->state[IDX_PAP]) {
		case STATE_REQ_SENT:
			pap.tld(sp);
			sppp_cp_change_state(&pap, sp, STATE_CLOSED);
			break;
		}
	} else {
		/* TO+ event, not very much we could do */
		switch (sp->state[IDX_PAP]) {
		case STATE_REQ_SENT:
			/* sppp_cp_change_state() will restart the timer */
			sppp_cp_change_state(&pap, sp, STATE_REQ_SENT);
			break;
		}
	}

	return 0;
}

/*
 * That's the timeout handler if we are peer.  Since the peer is active,
 * we need to retransmit our PAP request since it is apparently lost.
 * XXX We should impose a max counter.
 */
int
sppp_pap_my_TO(void *cookie)
{
	sppp_t *sp = (sppp_t *)cookie;
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	PPPDEBUG(("%s: pap peer TO\n", pppoe->ifname));
	pap.scr(sp);
	return 0;
}

void
sppp_pap_tlu(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	sp->rst_counter[IDX_PAP] = sp->lcp.max_configure;

	PPPDEBUG(("%s: %s tlu\n", pppoe->ifname, pap.name));

	/* indicate to LCP that we need to be closed down */
	sp->lcp.protos |= (1 << IDX_PAP);

	if (sp->pp_flags & PP_NEEDAUTH) {
		/*
		 * Remote is authenticator, but his auth proto didn't
		 * complete yet.  Defer the transition to network
		 * phase.
		 */
		return;
	}
	sppp_phase_network(sp);
}

void
sppp_pap_tld(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timer_thread_t *ppp_timer;

	PPPDEBUG(("%s: pap tld\n", pppoe->ifname));
	ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);
	timer_node_del(ppp_timer, &sp->ch[IDX_PAP]);
	timer_node_del(ppp_timer, &sp->pap_my_to_ch);
	sp->lcp.protos &= ~(1 << IDX_PAP);

	lcp.Close(sp);
}

void
sppp_pap_scr(sppp_t *sp)
{
	uint8_t idlen, pwdlen;

	sp->confid[IDX_PAP] = ++sp->pp_seq;
	pwdlen = strlen(sp->myauth.secret);
	idlen = strlen(sp->myauth.name);

	sppp_auth_send(&pap, sp, PAP_REQ, sp->confid[IDX_PAP],
		       sizeof idlen, (const char *)&idlen,
		       (size_t)idlen, sp->myauth.name,
		       sizeof pwdlen, (const char *)&pwdlen,
		       (size_t)pwdlen, sp->myauth.secret,
		       0);
}


/*
 *	PPP Timer related
 */
static int
sppp_keepalive(void *arg)
{
	sppp_t *sp = arg;
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timer_thread_t *ppp_timer;
	timeval_t tv;

	/* Keepalive mode disabled */
	if (!(sp->pp_flags & PP_KEEPALIVE))
		goto next_timer;

	/* No keepalive if LCP not opened yet. */
	if (sp->pp_phase < PHASE_AUTHENTICATE)
		goto next_timer;

	gettimeofday(&tv, NULL);
	/* No echo reply, but maybe user data passed through?
	 * We start sending echo-request when we just didnt
	 * see PPP traffic for NORECV_TIME. if remote AC
	 * is sending echo-request, we will not overload
	 * by sending our echo-request as peer. We are just
	 * sending it in case remote AC is no longer sending.
	 */
	if ((tv.tv_sec - sp->pp_last_receive) < NORECV_TIME) {
		sp->pp_alivecnt = 0;
		goto next_timer;
	}

	if (sp->pp_alivecnt++ >= MAXALIVECNT) {
		/* LCP Keepalive timeout */
		sppp_log_error(sp, "lcp_keepalive_timeout");
		sp->pp_alivecnt = 0;

		/* we are down, close all open protocols */
		lcp.Close(sp);

		/* And now prepare LCP to reestablish the link,
		* if configured to do so. */
		sppp_cp_change_state(&lcp, sp, STATE_STOPPED);

		/* Close connection immediately, completion of this
		* will summon the magic needed to reestablish it. */
		if (sp->pp_tlf)
			sp->pp_tlf(sp);
		goto next_timer;
	}

	if (sp->pp_phase >= PHASE_AUTHENTICATE) {
		uint32_t nmagic = htonl(sp->lcp.magic);
		sp->lcp.echoid = ++sp->pp_seq;
		sppp_cp_send(sp, PPP_LCP, ECHO_REQ, sp->lcp.echoid, 4, &nmagic);
	}

  next_timer:
	ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);
	timer_node_add(ppp_timer, &sp->keepalive, pppoe->keepalive);
	return 0;
}


/*
 *	PPP Sessions related
 */
int
sppp_up(spppoe_t *s)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	sppp_t *sp = s->s_ppp;
	timer_thread_t *ppp_timer;

	/* LCP layer */
	(sp->pp_up)(sp);

	/* Register keepalive timer */
	if (__test_bit(PPPOE_FL_KEEPALIVE_BIT, &pppoe->flags)) {
		sp->pp_flags |= PP_KEEPALIVE;
		ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);
		timer_node_add(ppp_timer, &sp->keepalive, pppoe->keepalive);
	}
	return 0;
}

int
sppp_down(spppoe_t *s)
{
	gtp_pppoe_t *pppoe = s->pppoe;
	sppp_t *sp = s->s_ppp;
	timer_thread_t *ppp_timer;
	int i;

	ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);

	/* LCP layer */
	(sp->pp_down)(sp);

	for (i = 0; i < IDX_COUNT; i++)
		timer_node_del(ppp_timer, &sp->ch[i]);
	timer_node_del(ppp_timer, &sp->pap_my_to_ch);

	/* Release keepalive timer */
	if (__test_bit(PPPOE_FL_KEEPALIVE_BIT, &pppoe->flags)) {
		sp->pp_flags &= ~PP_KEEPALIVE;
		timer_node_del(ppp_timer, &sp->keepalive);
	}
	return 0;
}

sppp_t *
sppp_init(spppoe_t *s, void (*pp_tls)(struct _sppp *), void (*pp_tlf)(sppp_t *)
		     , void (*pp_con)(sppp_t *), void (*pp_chg)(struct _sppp *, int))
{
	gtp_pppoe_t *pppoe = s->pppoe;
	sppp_t *sp;
	int i;

	PMALLOC(sp);
	sp->s_pppoe = s;
	sp->pp_loopcnt = 0;
	sp->pp_alivecnt = 0;
	sp->pp_last_activity = 0;
	sp->pp_last_receive = 0;
	sp->pp_seq = 0;
	sp->pp_rseq = 0;
	sp->pp_phase = PHASE_DEAD;
	sp->pp_up = lcp.Up;
	sp->pp_down = lcp.Down;
	sp->pp_tls = pp_tls;
	sp->pp_tlf = pp_tlf;
	sp->pp_con = pp_con;
	sp->pp_chg = pp_chg;

	if (pppoe->mru) {
		__set_bit(LCP_OPT_MRU, &sp->lcp.opts);
		sp->lcp.mru = pppoe->mru;
	}
	if (__test_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_0_BIT, &pppoe->flags) ||
	    __test_bit(PPPOE_FL_GTP_USERNAME_TEMPLATE_1_BIT, &pppoe->flags)) {
		sp->myauth.proto = PPP_PAP;
		sp->myauth.name = s->gtp_username;
	}
	if (__test_bit(PPPOE_FL_STATIC_USERNAME_BIT, &pppoe->flags)) {
		sp->myauth.proto = PPP_PAP;
		sp->myauth.name = pppoe->pap_username;
	}
	if (__test_bit(PPPOE_FL_STATIC_PASSWD_BIT, &pppoe->flags)) {
		sp->myauth.proto = PPP_PAP;
		sp->myauth.secret = pppoe->pap_passwd;
	}

	for (i = 0; i < IDX_COUNT; i++)
		timer_node_init(&sp->ch[i], (cps[i])->TO, sp);
	timer_node_init(&sp->pap_my_to_ch, sppp_pap_my_TO, sp);

	/* keepalive init */
	timer_node_init(&sp->keepalive, sppp_keepalive, sp);

	sppp_lcp_init(sp);
	sppp_ipcp_init(sp);
	sppp_ipv6cp_init(sp);
	sppp_pap_init(sp);

	return sp;
}

void
sppp_destroy(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timer_thread_t *ppp_timer;
	int i;

	ppp_timer = gtp_pppoe_get_ppp_timer(pppoe);
	sppp_ipcp_destroy(sp);
	sppp_ipv6cp_destroy(sp);

	/* Stop keepalive handler. */
	timer_node_del(ppp_timer, &sp->keepalive);

	for (i = 0; i < IDX_COUNT; i++)
		timer_node_del(ppp_timer, &sp->ch[i]);
	timer_node_del(ppp_timer, &sp->pap_my_to_ch);

	/* release authentication data */
	if (sp->hisauth.name != NULL)
		FREE(sp->hisauth.name);
	if (sp->hisauth.secret != NULL)
		FREE(sp->hisauth.secret);
	FREE(sp);
}


/*
 *	PPP service init
 */
static int
gtp_ppp_timer_init(gtp_pppoe_t *pppoe)
{
	char pname[128];

	snprintf(pname, 127, "ppp-timer-%s", pppoe->ifname);
	timer_thread_init(&pppoe->ppp_timer, pname, NULL);
	return 0;
}

static int
gtp_ppp_timer_destroy(gtp_pppoe_t *pppoe)
{
	timer_thread_destroy(&pppoe->ppp_timer);
	return 0;
}

int
gtp_ppp_init(gtp_pppoe_t *pppoe)
{
	gtp_ppp_timer_init(pppoe);

	/* Default value */
	pppoe->lcp_timeout = 1;		/* seconds */
	pppoe->lcp_max_terminate = 2;
	pppoe->lcp_max_configure = 10;
	pppoe->lcp_max_failure = 10;
	return 0;
}

int
gtp_ppp_destroy(gtp_pppoe_t *pppoe)
{
	gtp_ppp_timer_destroy(pppoe);
	return 0;
}
