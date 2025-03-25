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

#ifndef _GTP_UTILS_H
#define _GTP_UTILS_H

typedef struct _gtp_msg_type_map {
	const char *name;
	const char *description;
} gtp_msg_type_map_t;

/* Prototypes */
extern char *gtp_flags2str(char *, size_t, unsigned long);
extern const char *gtp_msgtype2str(int, int);
extern const char *gtpc_cause2str(int);

/* GTPv1 */
extern int gtp1_ie_apn_extract(gtp1_ie_apn_t *, char *, size_t);
extern size_t gtp1_get_header_len(gtp1_hdr_t *);
extern uint8_t *gtp1_get_ie_offset(uint8_t, uint8_t *, uint8_t *);
extern uint8_t *gtp1_get_ie(uint8_t type, pkt_buffer_t *);
extern size_t gtp1_ie_add_tail(pkt_buffer_t *, uint16_t);

/* GTPv2 */
extern int bcd_buffer_swap(uint8_t *, int, uint8_t *);
extern int str_imsi_to_bcd_swap(char *, size_t, uint8_t *);
extern int64_t bcd_to_int64(const uint8_t *, size_t);
extern int int64_to_bcd_swap(const uint64_t, uint8_t *, size_t);
extern int int64_to_bcd(const uint64_t, uint8_t *, size_t);
extern int gtp_imsi_ether_addr_build(const uint64_t, struct ether_addr *, uint8_t);
extern int gtp_ifid_from_ether_build(struct ether_addr *, struct in6_addr *);
extern size_t gtpc_get_header_len(gtp_hdr_t *);
extern int gtp_imsi_rewrite(gtp_apn_t *, uint8_t *);
extern int gtp_ie_imsi_rewrite(gtp_apn_t *, uint8_t *);
extern  int gtp_ie_apn_labels_cnt(const char *, size_t);
extern int gtp_apn_extract_ni(char *, size_t, char *, size_t);
extern int gtp_ie_apn_extract_ni(gtp_ie_apn_t *, char *, size_t);
extern int gtp_ie_apn_extract_oi(gtp_ie_apn_t *, char *, size_t);
extern int gtp_ie_apn_extract_plmn(gtp_ie_apn_t *, char *, size_t);
extern int gtp_ie_apn_rewrite_oi(gtp_ie_apn_t *, size_t, char *);
extern int gtp_ie_apn_rewrite(gtp_apn_t *, gtp_ie_apn_t *, size_t);
extern int gtp_ie_f_teid_dump(gtp_ie_f_teid_t *);
extern int gtp_dump_ie(uint8_t *, size_t);
extern uint8_t *gtp_get_ie_offset(uint8_t, uint8_t *, size_t, size_t);
extern uint8_t *gtp_get_ie(uint8_t, pkt_buffer_t *);
extern int gtp_foreach_ie(uint8_t, uint8_t *, size_t, uint8_t *,
			  gtp_server_worker_t *, gtp_session_t *, int, void *,
			  gtp_teid_t * (*hdl) (gtp_server_worker_t *, gtp_session_t *, int, void *, uint8_t *));
extern ssize_t gtpu_get_header_len(pkt_buffer_t *);


#endif
