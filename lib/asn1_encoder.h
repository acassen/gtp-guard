/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define asn1_oid_len(oid) (sizeof(oid)/sizeof(uint32_t))
unsigned char *asn1_encode_integer(unsigned char *, const unsigned char *, bool, int64_t);
unsigned char *asn1_encode_oid(unsigned char *, const unsigned char *, uint32_t *, int);
unsigned char *asn1_encode_tag(unsigned char *, const unsigned char *,
			       uint8_t, uint8_t, uint32_t,
			       const unsigned char *, int);
unsigned char *asn1_encode_octet_string(unsigned char *, const unsigned char *,
					const unsigned char *, uint32_t);
unsigned char *asn1_encode_sequence(unsigned char *, const unsigned char *,
				    const unsigned char *, int);
unsigned char *asn1_encode_boolean(unsigned char *, const unsigned char *, bool);
