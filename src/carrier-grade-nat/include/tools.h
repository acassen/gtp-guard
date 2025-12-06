/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */


/*
 * this file contains some wrappers to ease integration of some old
 * code from this author to this repository.
 */

#pragma once

#include <stdint.h>


/* have more meaning that TIMER_HZ for me */
#define USEC_PER_SEC				1000000


/* used to have a bigger lib for logging. avoid lots of replace */
#include <syslog.h>
#include "logger.h"

#define trace2(Mod, Fmt, ...)			\
	do { if (Mod & 2) log_message(LOG_DEBUG, Fmt, ## __VA_ARGS__); } while (0)
#define trace1(Mod, Fmt, ...)			\
	do { if (Mod & 1) log_message(LOG_DEBUG, Fmt, ##__VA_ARGS__); } while (0)
#define debug(Mod, Fmt, ...)	log_message(LOG_DEBUG, Fmt, ## __VA_ARGS__)
#define info(Mod, Fmt,...)	log_message(LOG_INFO, Fmt, ## __VA_ARGS__)
#define notice(Mod, Fmt, ...)	log_message(LOG_NOTICE, Fmt, ## __VA_ARGS__)
#define warn(Mod, Fmt, ...)	log_message(LOG_WARNING, Fmt, ## __VA_ARGS__)
#define err(Mod, Fmt, ...)	log_message(LOG_ERR, Fmt, ## __VA_ARGS__)
