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
	NULL, NULL, NULL, NULL,	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
};

static const struct cp ipcp = {
	PPP_IPCP, IDX_IPCP, CP_NCP, "ipcp",
	NULL, NULL, NULL, NULL,	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
};

static const struct cp ipv6cp = {
	PPP_IPV6CP, IDX_IPV6CP,	CP_NCP,	"ipv6cp",
	NULL, NULL, NULL, NULL,	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
};

static const struct cp pap = {
	PPP_PAP, IDX_PAP, CP_AUTH, "pap",
	NULL, NULL, NULL, NULL,	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
};

static const struct cp chap = {
	PPP_CHAP, IDX_CHAP, CP_AUTH, "chap",
	NULL, NULL, NULL, NULL,	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
};

static const struct cp *cps[IDX_COUNT] = {
	&lcp,			/* IDX_LCP */
	&ipcp,			/* IDX_IPCP */
	&ipv6cp,		/* IDX_IPV6CP */
	&pap,			/* IDX_PAP */
	&chap,			/* IDX_CHAP */
};


/*
 *	Utilities
 */
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

#if 0
	sppp_lcp_init(sp);
	sppp_ipcp_init(sp);
	sppp_ipv6cp_init(sp);
	sppp_pap_init(sp);
	sppp_chap_init(sp);
#endif

	return sp;
}

void
sppp_destroy(sppp_t *sp)
{
	gtp_pppoe_t *pppoe = sp->s_pppoe->pppoe;
	int i;
#if 0
	sppp_ipcp_destroy(sp);
	sppp_ipv6cp_destroy(sp);
#endif

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