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

#ifndef _GTP_SWITCH_H
#define _GTP_SWITCH_H

/* Default values */
#define GTP_STR_MAX		64
#define GTPC_PORT		2123
#define GTP_DEFAULT_THREAD_CNT	10
#define GTP_BUFFER_SIZE		4096

/* Flags */
enum gtp_flags {
	GTP_FL_RUNNING_BIT,
	GTP_FL_STARTING_BIT,
	GTP_FL_STOPING_BIT,
	GTP_FL_HASHED_BIT,
	GTP_FL_UPF_BIT,
	GTP_FL_FORCE_PGW_BIT,
	GTP_FL_IPTNL_BIT,
};

#define IPTNL_FL_TRANSPARENT_INGRESS_ENCAP	(1 << 0)
#define IPTNL_FL_TRANSPARENT_EGRESS_ENCAP	(1 << 1)
#define IPTNL_FL_TRANSPARENT_EGRESS_BYPASS	(1 << 2)
#define IPTNL_FL_DPD				(1 << 3)
#define IPTNL_FL_DEAD				(1 << 4)
#define IPTNL_FL_UNTAG_VLAN			(1 << 5)
#define IPTNL_FL_TAG_VLAN			(1 << 6)

/* GTP Switching context */
typedef struct _gtp_srv_worker {
	int			id;
	pthread_t		task;
	int			fd;
	struct _gtp_srv		*srv;		/* backpointer */
	uint8_t			buffer[GTP_BUFFER_SIZE];
	size_t			buffer_size;
	unsigned int		seed;

	/* stats */
	uint64_t		rx_bytes;
	uint64_t		tx_bytes;
	uint64_t		rx_pkt;
	uint64_t		tx_pkt;

	list_head_t		next;

	unsigned long		flags;
} gtp_srv_worker_t;

typedef struct _gtp_htab {
	struct hlist_head	*htab;
	dlock_mutex_t		*dlock;
} gtp_htab_t;

typedef struct _gtp_srv {
	struct sockaddr_storage	addr;
	int			thread_cnt;
	struct _gtp_ctx		*ctx;		/* backpointer */

	pthread_mutex_t		workers_mutex;
	list_head_t		workers;

	unsigned long		flags;
} gtp_srv_t;

typedef struct _gtp_iptnl {
	/* Dead-Peer-Detection */
	int			fd_in;
	int			fd_out;
	uint8_t			recv_buffer[GTP_BUFFER_SIZE];
	size_t			recv_buffer_size;
	uint8_t			send_buffer[GTP_BUFFER_SIZE];
	size_t			send_buffer_size;
	unsigned long		credit;
	unsigned long		expire;
	size_t			payload_len;

	/* Tunnel declaration */
	int			ifindex;
	uint32_t		selector_addr;
	uint32_t		local_addr;
	uint32_t		remote_addr;
	uint16_t		encap_vlan_id;
	uint16_t		decap_vlan_id;
	uint8_t			flags;
} gtp_iptnl_t;

typedef struct _gtp_ctx {
	char			name[GTP_STR_MAX];
	gtp_srv_t		gtpc;
	gtp_srv_t		gtpu;

	gtp_htab_t		gtpc_teid_tab;	/* GTP-C teid hashtab */
	gtp_htab_t		gtpu_teid_tab;	/* GTP-U teid hashtab */
	gtp_htab_t		vteid_tab;	/* virtual teid hashtab */
	gtp_htab_t		vsqn_tab;	/* virtual Seqnum hashtab */
	uint32_t		seqnum;		/* Global context Seqnum */

	gtp_apn_t		*apn_resolv;
	char			service_selection[GTP_STR_MAX];
	gtp_naptr_t		*pgw;
	struct sockaddr_storage	pgw_addr;

	gtp_iptnl_t		iptnl;

	unsigned long		flags;
	uint32_t		refcnt;

	list_head_t		next;
} gtp_ctx_t;


/* Prototypes */
extern int gtp_switch_worker_init(gtp_ctx_t *, gtp_srv_t *);
extern int gtp_switch_worker_launch(gtp_srv_t *);
extern int gtp_switch_worker_start(gtp_ctx_t *);
extern gtp_ctx_t *gtp_switch_get(const char *);
extern gtp_ctx_t *gtp_switch_init(const char *);
extern int gtp_switch_destroy(gtp_ctx_t *);
extern int gtp_switch_vty_init(void);

#endif
