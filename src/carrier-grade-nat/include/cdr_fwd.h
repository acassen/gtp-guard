/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2010, 2011, 2018, 2024, 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#pragma once

#include "addr.h"
#include "thread.h"

/* Default values */
#define CDR_FWD_TICKETS_MAX_BUFF		4095
#define CDR_FWD_PATH_MAX			400

/* forward declaration */
struct _thread_master;
struct cdr_fwd_context;
struct fmlog;
struct fmcfg;

/* load balancing mode */
enum cdr_fwd_lb_mode {
	CDR_FWD_MODE_ACTIVE_ACTIVE	= 1,
	CDR_FWD_MODE_FAIL_OVER		= 2,
	CDR_FWD_MODE_ROUND_ROBIN	= 3,
};

struct cdr_fwd_config
{
	char				spool_path[CDR_FWD_PATH_MAX];
	int				roll_period;	/* seconds */
	int				ack_window;
	enum cdr_fwd_lb_mode		lb_mode;
	uint32_t			instance_id;
	union addr			addr_ip_bound;

	/* round-robin, switch connection after this period (seconds) */
	int				rr_roll_period;

	uint64_t			log;
	thread_master_t			*loop;
};


/* cdr_fwd.c */
struct cdr_fwd_context *cdr_fwd_ctx_create(const struct cdr_fwd_config *,
					   const union addr *);
void cdr_fwd_ctx_release(struct cdr_fwd_context *);
void cdr_fwd_ctx_force_spool_set(struct cdr_fwd_context *, bool);
bool cdr_fwd_ctx_force_spool_get(struct cdr_fwd_context *);

bool cdr_fwd_remote_select_addr(struct cdr_fwd_context *,
				const union addr *);
void cdr_fwd_send_ticket(struct cdr_fwd_context *,
			 const uint8_t *, int);
int cdr_fwd_ctx_dump(const struct cdr_fwd_context *, char *, size_t);
int cdr_fwd_ctx_dump_stats(const struct cdr_fwd_context *, char *, size_t);

const char *cdr_fwd_lb_mode_to_str(int);
int str_to_cdr_fwd_lb_mode(const char *);
