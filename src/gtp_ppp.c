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
sppp_null(sppp_t *)
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
	sppp_null, sppp_null, sppp_ipcp_tls, sppp_ipcp_tlf,
	sppp_ipcp_scr
};

static const struct cp ipv6cp = {
	PPP_IPV6CP, IDX_IPV6CP,	CP_NCP,	"ipv6cp",
	sppp_ipv6cp_up, sppp_ipv6cp_down, sppp_ipv6cp_open, sppp_ipv6cp_close,
	sppp_ipv6cp_TO, sppp_ipv6cp_RCR, sppp_ipv6cp_RCN_rej, sppp_ipv6cp_RCN_nak,
	sppp_ipv6cp_tlu, sppp_ipv6cp_tld, sppp_ipv6cp_tls, sppp_ipv6cp_tlf,
	sppp_ipv6cp_scr
};

static const struct cp pap = {
	PPP_PAP, IDX_PAP, CP_AUTH, "pap",
	NULL, NULL, NULL, NULL,	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
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


/*
 *	PPP protocol implementation.
 */

/*
 * Send PPP control protocol packet.
 */
void
sppp_cp_send(sppp_t *sp, uint16_t proto, uint8_t type,
	     uint8_t ident, uint16_t len, void *data)
{
	/* TODO */
}

/*
 * Handle incoming PPP control protocol packets.
 */
void
sppp_cp_input(const struct cp *cp, sppp_t *sp, pkt_t *pkt)
{
	/* TODO */
}

void
sppp_increasing_timeout (const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	int timo;

	timo = sp->lcp.max_configure - sp->rst_counter[cp->protoidx];
	if (timo < 1)
		timo = 1;
	timer_node_add(&pppoe->ppp_timer, &sp->ch[cp->protoidx], timo * sp->lcp.timeout);
}


/*
 * Change the state of a control protocol in the state automaton.
 * Takes care of starting/stopping the restart timer.
 */
void
sppp_cp_change_state(const struct cp *cp, sppp_t *sp, int newstate)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	if (debug & 8 && sp->state[cp->protoidx] != newstate)
		printf("%s: %s %s->%s\n",
		       pppoe->ifname, cp->name,
		       sppp_state_name(sp->state[cp->protoidx]),
		       sppp_state_name(newstate));
	sp->state[cp->protoidx] = newstate;

	switch (newstate) {
	case STATE_INITIAL:
	case STATE_STARTING:
	case STATE_CLOSED:
	case STATE_STOPPED:
	case STATE_OPENED:
		timer_node_del(&pppoe->ppp_timer, &sp->ch[cp->protoidx]);
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
 * The generic part of all Up/Down/Open/Close/TO event handlers.
 * Basically, the state transition handling in the automaton.
 */
void
sppp_up_event(const struct cp *cp, sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	if (debug & 8)
		printf("%s: %s up(%s)\n",
		       pppoe->ifname, cp->name,
		       sppp_state_name(sp->state[cp->protoidx]));

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

	if (debug & 8)
		printf("%s: %s down(%s)\n",
		       pppoe->ifname, cp->name,
		       sppp_state_name(sp->state[cp->protoidx]));

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

	if (debug & 8)
		printf("%s: %s open(%s)\n",
		       pppoe->ifname, cp->name,
		       sppp_state_name(sp->state[cp->protoidx]));

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

	if (debug & 8)
		printf("%s: %s close(%s)\n",
		       pppoe->ifname, cp->name,
		       sppp_state_name(sp->state[cp->protoidx]));

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

	if (debug & 8)
		printf("%s: %s TO(%s) rst_counter = %d\n",
		       pppoe->ifname, cp->name,
		       sppp_state_name(sp->state[cp->protoidx]),
		       sp->rst_counter[cp->protoidx]);

	if (--sp->rst_counter[cp->protoidx] < 0)
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
	else
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
	sp->lcp.opts = (1 << LCP_OPT_MAGIC);
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
	sp->lcp.timeout = 1;	/* seconds */
	sp->lcp.max_terminate = 2;
	sp->lcp.max_configure = 10;
	sp->lcp.max_failure = 10;
}

void
sppp_lcp_up(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	timeval_t tv;

	sp->pp_alivecnt = 0;
	sp->lcp.opts = (1 << LCP_OPT_MAGIC);
	sp->lcp.magic = 0;
	sp->lcp.protos = 0;
	sp->lcp.mru = (pppoe->mru && pppoe->mru != PP_MTU) ? pppoe->mru : PP_MTU;
	sp->lcp.their_mru = PP_MTU;

	gettimeofday(&tv, NULL);
	sp->pp_last_receive = sp->pp_last_activity = tv.tv_sec;

	if (sp->state[IDX_LCP] == STATE_INITIAL) {
		if (debug & 8)
			printf("%s: UP event: incoming call\n", pppoe->ifname);
		lcp.Open(sp);
	}

	sppp_up_event(&lcp, sp);
}

void
sppp_lcp_down(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;

	sppp_down_event(&lcp, sp);

	if (debug & 8)
		printf("%s: Down event (carrier loss)\n", pppoe->ifname);

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
		sp->lcp.opts |= (1 << LCP_OPT_AUTH_PROTO);
	else
		sp->lcp.opts &= ~(1 << LCP_OPT_AUTH_PROTO);
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

	if (debug & 8)
		printf("%s: lcp parse opts: ", pppoe->ifname);

	/* pass 1: check for things that need to be rejected */
	p = (void *) (h + 1);
	for (rlen = 0; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len) {
			FREE(buf);
			return -1;
		}
		if (debug & 8)
			printf("%s ", sppp_lcp_opt_name(*p));
		switch (*p) {
		case LCP_OPT_MAGIC:
			/* Magic number. */
			/* FALLTHROUGH, both are same length */
		case LCP_OPT_ASYNC_MAP:
			/* Async control character map. */
			if (len >= 6 && p[1] == 6)
				continue;
			if (debug & 8)
				printf("[invalid] ");
			break;
		case LCP_OPT_MRU:
			/* Maximum receive unit. */
			if (len >= 4 && p[1] == 4)
				continue;
			if (debug & 8)
				printf("[invalid] ");
			break;
		case LCP_OPT_AUTH_PROTO:
			if (len < 4) {
				if (debug & 8)
					printf("[invalid] ");
				break;
			}
			authproto = (p[2] << 8) + p[3];
			if (authproto == PPP_CHAP && p[1] != 5) {
				if (debug & 8)
					printf("[invalid chap len] ");
				break;
			}
			if (sp->myauth.proto == 0) {
				/* we are not configured to do auth */
				if (debug & 8)
					printf("[not configured] ");
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
			if (debug & 8)
				printf("[rej] ");
			break;
		}
		/* Add the option to rejected list. */
		bcopy (p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		if (debug & 8)
			printf(" send conf-rej\n");
		sppp_cp_send(sp, PPP_LCP, CONF_REJ, h->ident, rlen, buf);
		goto end;
	} else if (debug & 8)
		printf("\n");

	/*
	 * pass 2: check for option values that are unacceptable and
	 * thus require to be nak'ed.
	 */
	if (debug & 8)
		printf("%s: lcp parse opt values: ", pppoe->ifname);

	p = (void *) (h + 1);
	len = origlen;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		if (debug & 8)
			printf("%s ", sppp_lcp_opt_name(*p));
		switch (*p) {
		case LCP_OPT_MAGIC:
			/* Magic number -- extract. */
			nmagic = (uint32_t)p[2] << 24 |
				 (uint32_t)p[3] << 16 | p[4] << 8 | p[5];
			if (nmagic != sp->lcp.magic) {
				if (debug & 8)
					printf("0x%.8x ", nmagic);
				continue;
			}
			if (debug & 8)
				printf("[glitch] ");
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
				if (debug & 8)
					printf("[empty] ");
				continue;
			}
			if (debug & 8)
				printf("[non-empty] ");
			/* suggest a zero one */
			p[2] = p[3] = p[4] = p[5] = 0;
			break;

		case LCP_OPT_MRU:
			/*
			 * Maximum receive unit.  Always agreeable,
			 * but ignored by now.
			 */
			sp->lcp.their_mru = p[2] * 256 + p[3];
			if (debug & 8)
				printf("%d ", sp->lcp.their_mru);
			continue;

		case LCP_OPT_AUTH_PROTO:
			authproto = (p[2] << 8) + p[3];
			if (sp->myauth.proto != authproto) {
				/* not agreed, nak */
				if (debug & 8)
					printf("[mine %s != his %s] ",
					       sppp_proto_name(sp->hisauth.proto),
					       sppp_proto_name(authproto));
				p[2] = sp->myauth.proto >> 8;
				p[3] = sp->myauth.proto;
				break;
			}
			if (authproto == PPP_CHAP && p[4] != CHAP_MD5) {
				if (debug & 8)
					printf("[chap not MD5] ");
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
			if (debug & 8)
				printf(" max_failure (%d) exceeded, "
				       "send conf-rej\n",
				       sp->lcp.max_failure);
			sppp_cp_send(sp, PPP_LCP, CONF_REJ, h->ident, rlen, buf);
		} else {
			if (debug & 8)
				printf(" send conf-nak\n");
			sppp_cp_send(sp, PPP_LCP, CONF_NAK, h->ident, rlen, buf);
		}
		goto end;
	} else {
		if (debug & 8)
			printf("send conf-ack\n");
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

	if (debug & 8)
		printf("%s: lcp rej opts: ", pppoe->ifname);

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		if (debug & 8)
			printf("%s ", sppp_lcp_opt_name(*p));
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
				if (debug & 8)
					printf("[don't insist on auth "
					       "for callout]");
				sp->lcp.opts &= ~(1 << LCP_OPT_AUTH_PROTO);
				break;
			}
			if (debug & 8)
				printf("[access denied]\n");
			lcp.Close(sp);
			break;
		}
	}
	if (debug & 8)
		printf("\n");
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

	if (debug & 8)
		printf("%s: lcp nak opts: ", pppoe->ifname);

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		if (debug & 8)
			printf("%s ", sppp_lcp_opt_name(*p));
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
					if (debug & 8)
						printf("magic glitch ");
					sp->lcp.magic = poor_prng(&pppoe->seed);
				} else {
					sp->lcp.magic = magic;
					if (debug & 8)
						printf("0x%.8x ", magic);
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
				if (debug & 8)
					printf("%d ", mru);
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
			if (debug & 8)
				printf("[access denied]\n");
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

	if (sp->lcp.opts & (1 << LCP_OPT_MAGIC)) {
		if (!sp->lcp.magic)
			sp->lcp.magic = poor_prng(&pppoe->seed);
		opt[i++] = LCP_OPT_MAGIC;
		opt[i++] = 6;
		opt[i++] = sp->lcp.magic >> 24;
		opt[i++] = sp->lcp.magic >> 16;
		opt[i++] = sp->lcp.magic >> 8;
		opt[i++] = sp->lcp.magic;
	}

	if (sp->lcp.opts & (1 << LCP_OPT_MRU)) {
		opt[i++] = LCP_OPT_MRU;
		opt[i++] = 4;
		opt[i++] = sp->lcp.mru >> 8;
		opt[i++] = sp->lcp.mru;
	}

	if (sp->lcp.opts & (1 << LCP_OPT_AUTH_PROTO)) {
		authproto = sp->hisauth.proto;
		opt[i++] = LCP_OPT_AUTH_PROTO;
		opt[i++] = authproto == PPP_CHAP? 5: 4;
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
	if (debug & 8)
		printf("%s: ipcp parse opts: ", pppoe->ifname);
	p = (void *) (h + 1);
	for (rlen = 0; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len) {
			FREE(buf);
			return -1;
		}
		if (debug & 8)
			printf("%s ", sppp_ipcp_opt_name(*p));
		switch (*p) {
		case IPCP_OPT_ADDRESS:
			if (len >= 6 && p[1] == 6) {
				/* correctly formed address option */
				continue;
			}
			if (debug & 8)
				printf("[invalid] ");
			break;
		default:
			/* Others not supported. */
			if (debug & 8)
				printf("[rej] ");
			break;
		}
		/* Add the option to rejected list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		if (debug & 8)
			printf(" send conf-rej\n");
		sppp_cp_send(sp, PPP_IPCP, CONF_REJ, h->ident, rlen, buf);
		goto end;
	} else if (debug & 8)
		printf("\n");

	/* pass 2: parse option values */
	if (sp->ipcp.flags & IPCP_HISADDR_SEEN)
		hisaddr = sp->ipcp.req_hisaddr; /* we already agreed on that */
	if (debug & 8)
		printf("%s: ipcp parse opt values: ", pppoe->ifname);
	p = (void *) (h + 1);
	len = origlen;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		if (debug & 8)
			printf(" %s ", sppp_ipcp_opt_name(*p));
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
				if (debug & 8)
					printf("%u.%u.%u.%u [ack] ",
					       NIPQUAD(desiredaddr));
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
			if (debug & 8) {
				if (desiredaddr == 0)
					printf("[addr requested] ");
				else
					printf("%u.%u.%u.%u [not agreed] ",
					       NIPQUAD(desiredaddr));
			}

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
		if (debug & 8)
			printf("still need hisaddr ");
	}

	if (rlen) {
		if (debug & 8)
			printf(" send conf-nak\n");
		sppp_cp_send(sp, PPP_IPCP, CONF_NAK, h->ident, rlen, buf);
	} else {
		if (debug & 8)
			printf(" send conf-ack\n");
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

	if (debug & 8)
		printf("%s: ipcp rej opts: ", pppoe->ifname);

	p = (void*) (h+1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		if (debug & 8)
			printf("%s ", sppp_ipcp_opt_name(*p));
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
	if (debug & 8)
		printf("\n");
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

	if (debug & 8)
		printf("%s: ipcp nak opts: ", pppoe->ifname);

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		if (debug & 8)
			printf("%s ", sppp_ipcp_opt_name(*p));
		switch (*p) {
		case IPCP_OPT_ADDRESS:
			/*
			 * Peer doesn't like our local IP address.  See
			 * if we can do something for him.  We'll drop
			 * him our address then.
			 */
			if (len >= 6 && p[1] == 6) {
				wantaddr = p[2] << 24 | p[3] << 16 |
					p[4] << 8 | p[5];
				sp->ipcp.opts |= (1 << SPPP_IPCP_OPT_ADDRESS);
				if (debug & 8)
					printf("[wantaddr %u.%u.%u.%u] ", NIPQUAD(wantaddr));
				/*
				 * When doing dynamic address assignment,
				 * we accept his offer.  Otherwise, we
				 * ignore it and thus continue to negotiate
				 * our already existing value.
				 */
				if (sp->ipcp.flags & IPCP_MYADDR_DYN) {
					if (debug & 8)
						printf("[agree] ");
					sp->ipcp.flags |= IPCP_MYADDR_SEEN;
					sp->ipcp.req_myaddr = wantaddr;
				}
			}
			break;
		case IPCP_OPT_PRIMDNS:
			if (len >= 6 && p[1] == 6)
				memcpy(&sp->ipcp.dns[0].s_addr, p + 2, sizeof(sp->ipcp.dns[0]));
			break;
		case IPCP_OPT_SECDNS:
			if (len >= 6 && p[1] == 6)
				memcpy(&sp->ipcp.dns[1].s_addr, p + 2, sizeof(sp->ipcp.dns[1]));
			break;
		}
	}
	if (debug & 8)
		printf("\n");
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
	char opt[6 /* compression */ + 6 /* address */ + 12 /* dns addrs */];
	u_int32_t ouraddr = 0;
	int i = 0;

	if (sp->ipcp.opts & (1 << SPPP_IPCP_OPT_ADDRESS)) {
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
	sp->ipv6cp.opts = 0;
	sp->ipv6cp.flags = 0;
	sp->state[IDX_IPV6CP] = STATE_INITIAL;
	sp->fail_counter[IDX_IPV6CP] = 0;
}

void
sppp_ipv6cp_destroy(sppp_t *sp)
{
}

void
sppp_ipv6cp_up(sppp_t *sp)
{
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
	sp->ipv6cp.flags &= ~(IPV6CP_MYIFID_SEEN|IPV6CP_MYIFID_DYN);
	sp->ipv6cp.opts |= (1 << IPV6CP_OPT_IFID);
	sppp_open_event(&ipv6cp, sp);
}

void
sppp_ipv6cp_close(sppp_t *sp)
{
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
	if (debug & 8)
		printf("%s: ipv6cp parse opts: ", pppoe->ifname);
	p = (void *) (h + 1);
	ifidcount = 0;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		/* Sanity check option length */
		if (p[1] < 2 || p[1] > len) {
			FREE(buf);
			return -1;
		}
		if (debug & 8)
			printf("%s ", sppp_ipv6cp_opt_name(*p));
		switch (*p) {
		case IPV6CP_OPT_IFID:
			if (len >= 10 && p[1] == 10 && ifidcount == 0) {
				/* correctly formed address option */
				ifidcount++;
				continue;
			}
			if (debug & 8)
				printf("[invalid] ");
			break;
		default:
			/* Others not supported. */
			if (debug & 8)
				printf("[rej] ");
			break;
		}
		/* Add the option to rejected list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		if (debug & 8)
			printf("send conf-rej\n");
		sppp_cp_send(sp, PPP_IPV6CP, CONF_REJ, h->ident, rlen, buf);
		goto end;
	} else if (debug & 8)
		printf("\n");

	/* pass 2: parse option values */
	if (sp->ipv6cp.flags & IPV6CP_MYIFID_DYN)
		myaddr = sp->ipv6cp.req_ifid;
	if (debug & 8)
		printf("%s: ipv6cp parse opt values: ", pppoe->ifname);
	p = (void *) (h + 1);
	len = origlen;
	type = CONF_ACK;
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		if (debug & 8)
			printf(" %s", sppp_ipv6cp_opt_name(*p));
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

				if (debug & 8) {
					printf(" %s [%s]",
					       inet_ntop(AF_INET6, &desiredaddr,
					       addr, sizeof(addr)),
					       sppp_cp_type_name(type));
				}
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
			if (debug & 8)
				printf(" %s [%s]",
				       inet_ntop(AF_INET6, &desiredaddr, addr, sizeof(addr)),
				       sppp_cp_type_name(type));
			break;
		}
		/* Add the option to nak'ed list. */
		bcopy(p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}

	if (rlen == 0 && type == CONF_ACK) {
		if (debug & 8)
			printf(" send %s\n", sppp_cp_type_name(type));
		sppp_cp_send(sp, PPP_IPV6CP, type, h->ident, origlen, h + 1);
	} else {
		if (debug & 8)
			printf(" send %s suggest %s\n", sppp_cp_type_name(type),
			       inet_ntop(AF_INET6, &suggestaddr, addr, sizeof(addr)));
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

	if (debug & 8)
		printf("%s: ipv6cp rej opts: ", pppoe->ifname);

	p = (void *) (h + 1);
	for (; len > 1 && p[1]; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		if (debug & 8)
			printf("%s ", sppp_ipv6cp_opt_name(*p));
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
	if (debug & 8)
		printf("\n");
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

	if (debug)
		printf("%s: ipv6cp nak opts: ", pppoe->ifname);

	p = (void *) (h + 1);
	for (; len > 1; len -= p[1], p += p[1]) {
		if (p[1] < 2 || p[1] > len)
			return;
		if (debug & 8)
			printf("%s ", sppp_ipv6cp_opt_name(*p));
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
				if (debug & 8)
					printf(" [suggestaddr %s]",
					       inet_ntop(AF_INET6, &suggestaddr,
							 addr, sizeof(addr)));
				if (debug & 8)
					printf(" [agree]");
				sp->ipv6cp.flags |= IPV6CP_MYIFID_SEEN;
			}
			break;
		}
	}
	if (debug & 8)
		printf("\n");
}

void
sppp_ipv6cp_tlu(sppp_t *sp)
{
}

void
sppp_ipv6cp_tld(sppp_t *sp)
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














int
sppp_pap_my_TO(void *arg)
{
	sppp_t *sp = (sppp_t *)arg;

	if (debug & 8)
		printf("pap peer timeout\n");

	pap.scr(sp);
	return 0;
}






/*
 *	PPP Timer related
 */
static int
sppp_keepalive(void *arg)
{
	return 0;
}



/*
 *	PPP Sessions related
 */

sppp_t *
sppp_init(spppoe_t *s)
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

	for (i = 0; i < IDX_COUNT; i++)
		timer_node_init(&sp->ch[i], (cps[i])->TO, sp);
	timer_node_init(&sp->pap_my_to_ch, sppp_pap_my_TO, sp);

	/* keepalive init */
	timer_node_init(&sp->keepalive, sppp_keepalive, sp);
	
	/* FIXME: correlate keepalive timer with pppoe_connect... */
	timer_node_add(&pppoe->ppp_timer, &sp->keepalive, 10);

	sppp_lcp_init(sp);
	sppp_ipcp_init(sp);
	sppp_ipv6cp_init(sp);
#if 0
	sppp_pap_init(sp);
#endif

	return sp;
}

void
sppp_destroy(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	int i;

	sppp_ipcp_destroy(sp);
	sppp_ipv6cp_destroy(sp);

	/* Stop keepalive handler. */
	timer_node_del(&pppoe->ppp_timer, &sp->keepalive);

	for (i = 0; i < IDX_COUNT; i++)
		timer_node_del(&pppoe->ppp_timer, &sp->ch[i]);
	timer_node_del(&pppoe->ppp_timer, &sp->pap_my_to_ch);

	/* release authentication data */
	if (sp->myauth.name != NULL)
		FREE(sp->myauth.name);
	if (sp->myauth.secret != NULL)
		FREE(sp->myauth.secret);
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

	return 0;
}

int
gtp_ppp_destroy(gtp_pppoe_t *pppoe)
{
	gtp_ppp_timer_destroy(pppoe);


	return 0;
}