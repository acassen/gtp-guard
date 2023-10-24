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

#ifndef _GTP_UTILS_H
#define _GTP_UTILS_H


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

/* GTPv1 */
extern int gtp1_ie_apn_extract(gtp1_ie_apn_t *, char *, size_t);
extern size_t gtp1_get_header_len(gtp1_hdr_t *);
extern uint8_t *gtp1_get_ie_offset(uint8_t, uint8_t *, uint8_t *);
extern uint8_t *gtp1_get_ie(uint8_t type, uint8_t *buffer, size_t size);

/* GTPv2 */
extern int bcd_buffer_swap(uint8_t *, int, uint8_t *);
extern int str_imsi_to_bcd_swap(char *, size_t, uint8_t *);
extern int64_t bcd_to_int64(uint8_t *, int);
extern size_t gtpc_get_header_len(gtp_hdr_t *);
extern int gtp_imsi_rewrite(gtp_apn_t *, uint8_t *);
extern int gtp_ie_imsi_rewrite(gtp_apn_t *, uint8_t *);
extern  int gtp_ie_apn_labels_cnt(const char *, size_t);
extern int gtp_apn_extract_ni(char *, size_t, char *, size_t);
extern int gtp_ie_apn_extract_ni(gtp_ie_apn_t *, char *, size_t);
extern int gtp_ie_apn_extract_oi(gtp_ie_apn_t *, char *, size_t);
extern int gtp_ie_apn_rewrite_oi(gtp_ie_apn_t *, size_t, char *);
extern int gtp_ie_apn_rewrite(gtp_apn_t *, gtp_ie_apn_t *, size_t);
extern int gtp_ie_f_teid_dump(gtp_ie_f_teid_t *);
extern int gtp_dump_ie(uint8_t *, size_t);
extern uint8_t *gtp_get_ie_offset(uint8_t, uint8_t *, size_t, size_t);
extern uint8_t *gtp_get_ie(uint8_t, uint8_t *, size_t);
extern int gtp_foreach_ie(uint8_t, uint8_t *, size_t, uint8_t *,
                          gtp_srv_worker_t *, gtp_session_t *, void *,
	                  gtp_teid_t * (*hdl) (gtp_srv_worker_t *, gtp_session_t *, void *, uint8_t *));
extern ssize_t gtpu_get_header_len(uint8_t *, size_t);
extern int gtp_cmd_echo_request(gtp_cmd_args_t *);

#endif
