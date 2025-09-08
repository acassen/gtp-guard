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

#include "gtp.h"
#include "gtp_apn.h"
#include "gtp_server.h"
#include "gtp_session.h"

struct gtp_msg_type_map {
	const char *name;
	const char *description;
};

/* Prototypes */
char *gtp_flags2str(char *, size_t, unsigned long);
const char *gtp_msgtype2str(int, int);
const char *gtpc_cause2str(int);

/* GTPv1 */
int gtp1_ie_apn_extract(struct gtp1_ie_apn *, char *, size_t);
size_t gtp1_get_header_len(struct gtp1_hdr *);
uint8_t *gtp1_get_ie_offset(uint8_t, uint8_t *, uint8_t *);
uint8_t *gtp1_get_ie(uint8_t type, struct pkt_buffer *);
size_t gtp1_ie_add_tail(struct pkt_buffer *, uint16_t);

/* GTPv2 */
int bcd_buffer_swap(uint8_t *, int, uint8_t *);
int str_imsi_to_bcd_swap(char *, size_t, uint8_t *);
int64_t bcd_to_int64(const uint8_t *, size_t);
int int64_to_bcd_swap(const uint64_t, uint8_t *, size_t);
int int64_to_bcd(const uint64_t, uint8_t *, size_t);
uint8_t hex_to_bcd(uint8_t);
int str_plmn_to_bcd(const char *, uint8_t *, size_t);
int64_t bcd_plmn_to_int64(const uint8_t *, size_t);
int bcd_plmn_cmp(const uint8_t *, const uint8_t *);
bool bcd_imsi_plmn_match(const uint8_t *, const uint8_t *);
int gtp_imsi_ether_addr_build(const uint64_t, struct ether_addr *, uint8_t);
int gtp_ifid_from_ether_build(struct ether_addr *, struct in6_addr *);
size_t gtpc_get_header_len(struct gtp_hdr *);
int gtp_imsi_rewrite(struct gtp_apn *, uint8_t *);
int gtp_ie_imsi_rewrite(struct gtp_apn *, uint8_t *);
int gtp_ie_apn_labels_cnt(const char *, size_t);
int gtp_apn_extract_ni(char *, size_t, char *, size_t);
int gtp_ie_apn_extract_ni(struct gtp_ie_apn *, char *, size_t);
int gtp_ie_apn_extract_oi(struct gtp_ie_apn *, char *, size_t);
int gtp_ie_apn_extract_plmn(struct gtp_ie_apn *, char *, size_t);
int gtp_ie_apn_rewrite_oi(struct gtp_ie_apn *, size_t, char *);
int gtp_ie_apn_rewrite(struct gtp_apn *, struct gtp_ie_apn *, size_t);
int gtp_ie_f_teid_dump(struct gtp_ie_f_teid *);
int gtp_dump_ie(uint8_t *, size_t);
uint8_t *gtp_get_ie_offset(uint8_t, uint8_t *, size_t, size_t);
uint8_t *gtp_get_ie(uint8_t, struct pkt_buffer *);
int gtp_foreach_ie(uint8_t, uint8_t *, size_t, uint8_t *,
		   struct gtp_server *, struct gtp_session *, int, void *,
		   struct gtp_teid * (*hdl) (struct gtp_server *, struct gtp_session *, int, void *, uint8_t *));
ssize_t gtpu_get_header_len(struct pkt_buffer *);
