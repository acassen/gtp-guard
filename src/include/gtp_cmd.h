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

#ifndef _GTP_CMD_H
#define _GTP_CMD_H

#define GTP_CMD_BUFFER_SIZE	128

enum {
	GTP_CMD_ECHO_REQUEST = 0,
	GTP_CMD_ECHO_REQUEST_EXTENDED,
};

typedef struct _gtp_cmd_args {
	int			type;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	int			ifindex;
	vty_t			*vty;
	int			version;
	int			count;
	uint32_t		sqn;
	int			fd_in;
	int			fd_out;
	char			buffer[GTP_CMD_BUFFER_SIZE];
	size_t			buffer_len;
	size_t			buffer_offset;
	thread_ref_t		t_read;
	thread_ref_t		t_write;
} gtp_cmd_args_t;

/* Prototypes */
extern int gtp_cmd_echo_request(gtp_cmd_args_t *);

#endif
