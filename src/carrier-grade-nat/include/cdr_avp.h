/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2018, 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#pragma once


/*
 * generic / binary cdrs with avp.
 */
struct cdr_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int	hl:4;
	unsigned int	version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int	version:4;
	unsigned int	hl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t		ne_type;
	uint8_t		cdr_type;
	uint8_t		nb_avp;
	uint16_t	seq_num;
	uint16_t	size;
	uint8_t		auth_type;
	uint8_t		reserved[3];

	uint8_t		payload[0];
} __attribute__ ((packed));

/* version */
#define CDR_VERSION			2

/* ne type */
#define CDR_NE_SMS			0x04
#define CDR_NE_CGNLOG			0x12



struct cdr_value_ptr
{
	uint16_t		size;
	void			*ptr;
};

union cdr_value
{
	uint64_t		u64;
	uint32_t		u32;
	uint16_t		u16;
	uint8_t			u8;
	char			*str;
	void			*ptr;	/* struct cdr_value_ptr or
					 * any other ptr */
};


static inline int
cdr_avp_append(uint8_t **pdst, int max_size, uint16_t code,
	       uint16_t len, const void *data)
{
	uint8_t *dst = *pdst;

	if (len + 4 > max_size)
		return 0;

	dst[0] = code >> 8;
	dst[1] = code & 0xff;
	dst[2] = len >> 8;
	dst[3] = len & 0xff;
	if (len)
		memcpy(dst + 4, data, len);

	*pdst += 4 + len;
	return 1;
}

static inline int
cdr_avp_append_str(uint8_t **pdst, int max_size, uint16_t code, const char *str)
{
	int len = strlen(str);
	uint8_t *dst = *pdst;

	/* max len is 65536, but limit to 512. we should never
	 * have things this big. */
	if (len > 512)
		len = 512;

	if (len + 4 > max_size)
		return 0;

	dst[0] = code >> 8;
	dst[1] = code & 0xff;
	dst[2] = len >> 8;
	dst[3] = len & 0xff;
	memcpy(dst + 4, str, len);

	*pdst += 4 + len;
	return 1;
}

