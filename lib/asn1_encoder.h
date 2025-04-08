/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _LINUX_ASN1_ENCODER_H
#define _LINUX_ASN1_ENCODER_H

#include <linux/types.h>
#include <stdbool.h>
#include "asn1.h"
#include "asn1_ber_bytecode.h"

#define asn1_oid_len(oid) (sizeof(oid)/sizeof(uint32_t))
unsigned char *asn1_encode_integer(unsigned char *, const unsigned char *, int64_t);
unsigned char *asn1_encode_oid(unsigned char *, const unsigned char *, uint32_t *, int);
unsigned char *asn1_encode_tag(unsigned char *, const unsigned char *,
			       uint32_t, const unsigned char *, int);
unsigned char *asn1_encode_octet_string(unsigned char *, const unsigned char *,
					const unsigned char *, uint32_t);
unsigned char *asn1_encode_sequence(unsigned char *, const unsigned char *,
				    const unsigned char *, int);
unsigned char *asn1_encode_boolean(unsigned char *, const unsigned char *, bool);

#endif
