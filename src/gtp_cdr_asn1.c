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

#include "asn1.h"
#include "asn1_encoder.h"
#include "gtp_cdr.h"
#include "gtp_cdr_asn1.h"


/*
 *	ASN.1 3GPP ETSI TS 132 298 encoding
 */
static uint8_t *
gtp_cdr_asn1_tag(uint8_t *dst, const uint8_t *end, uint32_t tag, uint8_t *data, size_t dlen)
{
	return asn1_encode_tag(dst, end, ASN1_CONT, ASN1_PRIM, tag, data, dlen);
}

static uint8_t *
gtp_cdr_asn1_tag_ip4(uint8_t *dst, const uint8_t *end, uint32_t tag, uint8_t *data, size_t dlen)
{
	uint8_t *cp = asn1_encode_tag(dst, end, ASN1_CONT, ASN1_CONS, tag, NULL, dlen + 2);

	return gtp_cdr_asn1_tag(cp, end, 0, data, dlen);
}

static uint8_t *
gtp_cdr_asn1_tag_integer(uint8_t *dst, const uint8_t *end, uint32_t tag, uint8_t *data, size_t dlen)
{
	uint64_t value = *(uint64_t *) data;
	uint8_t *cp = gtp_cdr_asn1_tag(dst, end, tag, NULL, -1);

	return asn1_encode_integer(cp, end, false, value);
}

static uint8_t *
gtp_cdr_asn1_served_addr(gtp_cdr_t *cdr, int m, uint32_t tag, uint8_t *dst, const uint8_t *end)
{
	uint8_t *cp;

	/* FIXME: Add support to IPv6 */
	if (!cdr->served_addr)
		return dst;

	cp = asn1_encode_tag(dst, end, ASN1_CONT, ASN1_CONS, tag, NULL, 8);
	return gtp_cdr_asn1_tag_ip4(cp, end, 0, (uint8_t *) &cdr->served_addr, 4);
}

static uint8_t *
gtp_cdr_asn1_service_data(gtp_cdr_t *cdr, int m, uint32_t tag, uint8_t *dst, const uint8_t *end)
{
	uint8_t *cp, *outer, *seq;
	uint16_t *len, *len_seq;

	if (!cdr->volume_up && !cdr->volume_down)
		return dst;

	outer = asn1_encode_tag(dst, end, ASN1_CONT, ASN1_CONS, tag, NULL, 0xffff);
	len = (uint16_t *) (outer - 2);

	seq = asn1_encode_sequence(outer, end, NULL, 0xffff);
	len_seq = (uint16_t *) (seq - 2);
	cp = gtp_cdr_asn1_tag(seq, end, 1, (uint8_t *) &cdr->rating_group, 1);
	cp = gtp_cdr_asn1_tag(cp, end, 8, cdr->service_condition_change, 5);
	cp = gtp_cdr_asn1_tag_integer(cp, end, 12, (uint8_t *) &cdr->volume_up, -1);
	cp = gtp_cdr_asn1_tag_integer(cp, end, 13, (uint8_t *) &cdr->volume_down, -1);
	cp = gtp_cdr_asn1_tag(cp, end, 14, cdr->stop_time, 9);

	/* Update len */
	*len_seq = htons(cp - seq);
	*len = htons(cp - outer);

	return cp;
}

static uint8_t *
gtp_cdr_asn1_serving_node_type(gtp_cdr_t *cdr, int m, uint32_t tag, uint8_t *dst, const uint8_t *end)
{
	uint8_t *cp = asn1_encode_tag(dst, end, ASN1_CONT, ASN1_CONS, tag, NULL, 3);

	return asn1_encode_tag(cp, end, ASN1_UNIV, ASN1_PRIM, ASN1_ENUM
				 , (uint8_t *) &cdr->serving_node_type, 1);
}


/*
 *	ASN.1 encoder
 */
static const struct {
	uint8_t * (*encode) (uint8_t *, const uint8_t *, uint32_t, uint8_t *, size_t);
} cdr_asn1_method[] = {
	{ gtp_cdr_asn1_tag		},
	{ gtp_cdr_asn1_tag_ip4		},
	{ gtp_cdr_asn1_tag_integer	},
	{ NULL }
};

static uint8_t *
gtp_cdr_asn1_encode(gtp_cdr_t *cdr, int m, uint32_t tag, uint8_t *dst, const uint8_t *end)
{
	if (!cdr || !cdr->asn1_ctx[tag].data || m >= M_MAX)
		return dst;

	return (*(cdr_asn1_method[m].encode)) (dst, end, tag
						  , cdr->asn1_ctx[tag].data
						  , cdr->asn1_ctx[tag].data_len);
}

static const struct {
	uint32_t tag;
	uint8_t * (*encode) (gtp_cdr_t *, int, uint32_t, uint8_t *, const uint8_t *);
	int method;
} cdr_asn1_encoder[] = {
	{ 0,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 3,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 4,	gtp_cdr_asn1_encode		,	M_IP_ADDRESS	},
	{ 5,	gtp_cdr_asn1_encode		,	M_INTEGER	},
	{ 6,	gtp_cdr_asn1_encode		,	M_IP_ADDRESS	},
	{ 7,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 8,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 9,	gtp_cdr_asn1_served_addr	,	M_RAW		},
	{ 13,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 14,	gtp_cdr_asn1_encode		,	M_INTEGER	},
	{ 15,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 18,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 22,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 23,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 27,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 29,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 30,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 31,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 32,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 34,	gtp_cdr_asn1_service_data	,	M_RAW		},
	{ 35,	gtp_cdr_asn1_serving_node_type	,	M_RAW		},
	{ 37,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 38,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 39,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 45,	gtp_cdr_asn1_encode		,	M_RAW		},
	{ 0,	NULL				,	0		}
};

int
gtp_cdr_asn1_pgw_record_encode(gtp_cdr_t *cdr, uint8_t *dst, size_t dsize)
{
	const uint8_t *end = dst + dsize;
	uint8_t *outer, *cp;
	uint16_t *len;
	int i;

	/* Trick: we reserve enough headroom by tagging with large length.
	 * It will prevent buffer copying.
	 */
	outer = asn1_encode_tag(dst, end, ASN1_CONT, ASN1_CONS, PGW_RECORD_TAG, NULL, 0xffff);
	len = (uint16_t *) (outer - 2);

	for (i = 0, cp = outer; *(cdr_asn1_encoder[i].encode); i++) {
		cp = (*(cdr_asn1_encoder[i].encode)) (cdr, cdr_asn1_encoder[i].method
							 , cdr_asn1_encoder[i].tag
							 , cp, end);
	}

	/* Update len */
	*len = htons(cp - outer);

	return cp - dst;
}

int
gtp_cdr_asn1_ctx_set(gtp_cdr_ctx_t *ctx, uint32_t tag, uint8_t *data, size_t dlen)
{
	if (!ctx)
		return -1;

	ctx[tag].data = data;
	ctx[tag].data_len = dlen;
	return 0;
}
