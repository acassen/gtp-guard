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

#ifndef _GTP_CMD_H
#define _GTP_CMD_H

typedef struct _gtp_cmd_args {
	struct sockaddr_storage addr;
	vty_t			*vty;
	int			version;
	int			count;
	uint32_t		sqn;
	int			fd;
	char			buffer[64];
	size_t			buffer_len;
	thread_ref_t		t_read;
	thread_ref_t		t_write;
} gtp_cmd_args_t;

/* Prototypes */
extern int gtp_cmd_echo_request(gtp_cmd_args_t *);

#endif
