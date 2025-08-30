/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define asn1_oid_len(oid) (sizeof(oid)/sizeof(uint32_t))
unsigned char *asn1_encode_integer(unsigned char *data, const unsigned char *end_data,
				   bool tag, int64_t integer);
unsigned char *asn1_encode_oid(unsigned char *data, const unsigned char *end_data,
			       uint32_t *oid, int oid_len);
unsigned char *asn1_encode_tag(unsigned char *data, const unsigned char *end_data,
			       uint8_t class, uint8_t method, uint32_t tag,
			       const unsigned char *string, int len);
unsigned char *asn1_encode_octet_string(unsigned char *data, const unsigned char *end_data,
					const unsigned char *string, uint32_t len);
unsigned char *asn1_encode_sequence(unsigned char *data, const unsigned char *end_data,
				    const unsigned char *seq, int len);
unsigned char *asn1_encode_boolean(unsigned char *data, const unsigned char *data_end,
				   bool val);
