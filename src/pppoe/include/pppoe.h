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

/*
 *	PPPoE RFC 2516 related
 */
#define PPPOE_STATE_INITIAL	0
#define PPPOE_STATE_PADI_SENT	1
#define	PPPOE_STATE_PADR_SENT	2
#define	PPPOE_STATE_SESSION	3
#define	PPPOE_STATE_CLOSING	4

#define PPPOE_NAMELEN		128		/* should be enough */

#define	PPPOE_HEADERLEN		sizeof(pppoe_hdr_t)
#define	PPPOE_OVERHEAD		(PPPOE_HEADERLEN + 2)
#define	PPPOE_VERTYPE		0x11		/* VER=1, TYPE = 1 */

#define	PPPOE_TAG_EOL		0x0000		/* end of list */
#define	PPPOE_TAG_SNAME		0x0101		/* service name */
#define	PPPOE_TAG_ACNAME	0x0102		/* access concentrator name */
#define	PPPOE_TAG_HUNIQUE	0x0103		/* host unique */
#define	PPPOE_TAG_ACCOOKIE	0x0104		/* AC cookie */
#define	PPPOE_TAG_VENDOR	0x0105		/* vendor specific */
#define	PPPOE_TAG_RELAYSID	0x0110		/* relay session id */
#define	PPPOE_TAG_MAX_PAYLOAD	0x0120		/* RFC 4638 max payload */
#define	PPPOE_TAG_SNAME_ERR	0x0201		/* service name error */
#define	PPPOE_TAG_ACSYS_ERR	0x0202		/* AC system error */
#define	PPPOE_TAG_GENERIC_ERR	0x0203		/* generic error */

/* Vendor Specific TAGs */
#define PPPOE_VENDOR_ID_BBF		0x00000de9	/* BroadBandForum Vendor-ID*/
#define PPPOE_VENDOR_TAG_CIRCUIT_ID	0x01
#define PPPOE_VENDOR_TAG_REMOTE_ID	0x02
#define PPPOE_VENDOR_TAG_UPSTREAM	0x81
#define PPPOE_VENDOR_TAG_DOWNSTREAM	0x82

#define	PPPOE_CODE_SESSION	0x00		/* Session */
#define	PPPOE_CODE_PADI		0x09		/* Active Discovery Initiation */
#define	PPPOE_CODE_PADO		0x07		/* Active Discovery Offer */
#define	PPPOE_CODE_PADR		0x19		/* Active Discovery Request */
#define	PPPOE_CODE_PADS		0x65		/* Active Discovery Session confirmation */
#define	PPPOE_CODE_PADT		0xA7		/* Active Discovery Terminate */

/* two byte PPP protocol discriminator, then IP data */
#define	PPPOE_MTU	(ETHERMTU - PPPOE_OVERHEAD)
#define	PPPOE_MAXMTU	PP_MAX_MRU

/* Add a 16 bit unsigned value to a buffer pointed to by PTR */
#define	PPPOE_ADD_16(PTR, VAL)			\
		*(PTR)++ = (VAL) / 256;		\
		*(PTR)++ = (VAL) % 256

/* Add a complete PPPoE header to the buffer pointed to by PTR */
#define	PPPOE_ADD_HEADER(PTR, CODE, SESS, LEN)	\
		*(PTR)++ = PPPOE_VERTYPE;	\
		*(PTR)++ = (CODE);		\
		PPPOE_ADD_16(PTR, SESS);	\
		PPPOE_ADD_16(PTR, LEN)

#define	PPPOE_DISC_TIMEOUT	5	/* base for quick timeout calculation (seconds) */
#define	PPPOE_SLOW_RETRY	60	/* persistent retry interval (seconds) */
#define	PPPOE_DISC_MAXPADI	4	/* retry PADI four times (quickly) */
#define	PPPOE_DISC_MAXPADR	2	/* retry PADR twice */

#define PPPOE_BUFSIZE		64
#define PPPOE_MPKT		10
#define PPPOE_BUNDLE_MAXSIZE	5

typedef struct _pppoe_hdr {
	uint8_t		vertype;
	uint8_t		code;
	uint16_t	session;
	uint16_t	plen;
} __attribute__((packed)) pppoe_hdr_t;

typedef struct _pppoe_tag {
	uint16_t	tag;
	uint16_t	len;
} __attribute__((packed)) pppoe_tag_t;

typedef struct _pppoe_vendor_tag {
	uint8_t		tag;
	uint8_t		len;
} __attribute__((packed)) pppoe_vendor_tag_t;

/* Receive channel */
#define GTP_PPPOE_RECV_TIMER	(3 * TIMER_HZ)
#define GTP_PPPOE_RPS_BITS	3
#define GTP_PPPOE_RPS_SIZE	(1 << GTP_PPPOE_RPS_BITS)
#define GTP_PPPOE_RPS_MASK	(GTP_PPPOE_RPS_SIZE - 1)

/* flags */
enum pppoe_flags {
	PPPOE_FL_STOPPING_BIT,
	PPPOE_FL_RUNNING_BIT,
	PPPOE_FL_PRIMARY_BIT,
	PPPOE_FL_SECONDARY_BIT,
	PPPOE_FL_FAULT_BIT,
	PPPOE_FL_VRRP_MONITOR_BIT,
	PPPOE_FL_GTP_USERNAME_TEMPLATE_0_BIT,
	PPPOE_FL_GTP_USERNAME_TEMPLATE_1_BIT,
	PPPOE_FL_VENDOR_SPECIFIC_BBF_BIT,
	PPPOE_FL_STATIC_USERNAME_BIT,
	PPPOE_FL_STATIC_PASSWD_BIT,
	PPPOE_FL_IPV6CP_DISABLE_BIT,
	PPPOE_FL_KEEPALIVE_BIT,
	PPPOE_FL_PADI_FAST_RETRY_BIT,
	PPPOE_FL_LCP_TIMEOUT_BIT,
	PPPOE_FL_LCP_MAX_TERMINATE_BIT,
	PPPOE_FL_LCP_MAX_CONFIGURE_BIT,
	PPPOE_FL_LCP_MAX_FAILURE_BIT,
	PPPOE_FL_IGNORE_INGRESS_PPP_BRD_BIT,
	PPPOE_FL_STRICT_AC_NAME_BIT,
	PPPOE_FL_METRIC_VRRP_BIT,
	PPPOE_FL_METRIC_PPPOE_BIT,
};

typedef struct _pppoe_channel {
	char			pname[GTP_PNAME];
	uint16_t		proto;
	int			fd;
	struct _pppoe		*pppoe;		/* backpointer */

	mpkt_t			mpkt;
	pkt_queue_t		pkt_q;

	/* I/O MUX */
	thread_t		*r_thread;
	thread_t		*w_thread;

	/* metrics */
	gtp_metrics_pkt_t	rx_metrics;
	gtp_metrics_pkt_t	tx_metrics;
} pppoe_channel_t;

typedef struct _pppoe_bundle {
	char			name[GTP_NAME_MAX_LEN];

	struct _pppoe	**pppoe;
	int			instance_idx;

	list_head_t		next;

	unsigned long		flags;
} pppoe_bundle_t;

typedef struct _pppoe {
	char			name[GTP_NAME_MAX_LEN];
	char			ifname[GTP_NAME_MAX_LEN];
	unsigned int		ifindex;
	uint8_t			vmac_hbits;
	char			ac_name[PPPOE_NAMELEN];
	int			ac_name_len;
	char			service_name[PPPOE_NAMELEN];
	char			pap_username[PPPOE_NAMELEN];
	char			pap_passwd[PPPOE_NAMELEN];
	int			keepalive;
	int			mru;
	int			lcp_timeout;
	int			lcp_max_terminate;
	int			lcp_max_configure;
	int			lcp_max_failure;
	int			refcnt;
	unsigned int		seed;
	pthread_t		task;

	pppoe_bundle_t		*bundle;	/* Part of a pppoe-bundle */
	int			session_count;	/* Number of session tracked */

	pppoe_channel_t		channel_disc;
	pppoe_channel_t		channel_ses;
	pkt_queue_t		pkt_q;

	int			monitor_fd;	/* Monitoring channel */
	unsigned char		monitor_buffer[GTP_BUFFER_SIZE];
	unsigned long		credit;
	unsigned long		expire;

	/* metrics */
	uint64_t		vrrp_pkt_rx;
	pppoe_metrics_t		*pppoe_metrics;
	ppp_metrics_t		*ppp_metrics;

	list_head_t		next;

	unsigned long		flags;
} pppoe_t;

/* Prototypes */
extern int vrrp_metrics_dump(FILE *);
extern int vrrp_metrics_reset(pppoe_t *);
extern int ppp_metric_update(pppoe_t *, uint16_t, int, int);
extern int ppp_metric_update_total(pppoe_t *, uint16_t, int);
extern int ppp_metric_update_dropped(pppoe_t *, int);
extern int ppp_metrics_reset(pppoe_t *);
extern int pppoe_metric_update(pppoe_t *, int, int);
extern int pppoe_metrics_reset(pppoe_t *);
extern int pppoe_metrics_dump(FILE *);
extern int pppoe_metrics_alloc(pppoe_t *);
extern int pppoe_metrics_destroy(pppoe_t *);

extern void pppoe_metrics_foreach(int (*hdl) (pppoe_t *, void *, const char *, int),
				      void *, const char *, int);
extern void pppoe_foreach(int (*hdl) (pppoe_t *, void *), void *);
extern pppoe_t *pppoe_get_by_name(const char *);
extern int pppoe_disc_send(pppoe_t *, pkt_t *);
extern int pppoe_ses_send(pppoe_t *, pkt_t *);
extern int pppoe_put(pppoe_t *);
extern int pppoe_start(pppoe_t *);
extern int pppoe_release(pppoe_t *);
extern int pppoe_interface_init(pppoe_t *, const char *);
extern pppoe_t *pppoe_alloc(const char *);
extern int pppoe_init(void);
extern int pppoe_destroy(void);

extern pppoe_bundle_t *pppoe_bundle_get_by_name(const char *);
extern pppoe_bundle_t *pppoe_bundle_init(const char *);
extern pppoe_t *pppoe_bundle_get_active_instance(pppoe_bundle_t *);
extern int pppoe_bundle_release(pppoe_bundle_t *);
extern int pppoe_bundle_destroy(void);
