/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IP prefix implementation
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#ifndef _PREFIX_H
#define _PREFIX_H

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/*
 *	IPv4 and IPv6 unified prefix structure
 */
typedef struct _prefix {
	uint8_t		family;
	uint8_t		prefixlen;
	union {
		uint8_t		prefix;
		struct in_addr	prefix4;
		struct in6_addr	prefix6;
	} u __attribute__ ((aligned (8)));
} prefix_t;

typedef struct _prefix_ipv4 {
	uint8_t		family;
	uint8_t		prefixlen;
	struct in_addr	prefix __attribute__ ((aligned (8)));
} prefix_ipv4_t;

typedef struct _prefix_ipv6 {
	uint8_t		family;
	uint8_t		prefixlen;
	struct in6_addr	prefix __attribute__ ((aligned (8)));
} prefix_ipv6_t;


/* Max bit/byte length of IPv4 address */
#define IPV4_MAX_BYTELEN	4
#define IPV4_MAX_BITLEN		32
#define IPV4_MAX_PREFIXLEN	32
#define IPV4_ADDR_CMP(D,S)	memcmp ((D), (S), IPV4_MAX_BYTELEN)
#define IPV4_ADDR_SAME(D,S)	(memcmp ((D), (S), IPV4_MAX_BYTELEN) == 0)
#define IPV4_ADDR_COPY(D,S)	memcpy ((D), (S), IPV4_MAX_BYTELEN)

#define IPV4_NET0(a)		((((uint32_t) (a)) & 0xff000000) == 0x00000000)
#define IPV4_NET127(a)		((((uint32_t) (a)) & 0xff000000) == 0x7f000000)
#define IPV4_LINKLOCAL(a)	((((uint32_t) (a)) & 0xffff0000) == 0xa9fe0000)

/* Max bit/byte length of IPv6 address */
#define IPV6_MAX_BYTELEN	16
#define IPV6_MAX_BITLEN		128
#define IPV6_MAX_PREFIXLEN	128
#define IPV6_ADDR_CMP(D,S)	memcmp ((D), (S), IPV6_MAX_BYTELEN)
#define IPV6_ADDR_SAME(D,S)	(memcmp ((D), (S), IPV6_MAX_BYTELEN) == 0)
#define IPV6_ADDR_COPY(D,S)	memcpy ((D), (S), IPV6_MAX_BYTELEN)

/* Count prefix size from mask length */
#define PSIZE(a)		(((a) + 7) / (8))

/* Prefix's family member */
#define PREFIX_FAMILY(p)	((p)->family)

/* Check bit of the prefix */
static inline unsigned int
prefix_bit(const uint8_t *prefix, const uint8_t prefixlen)
{
	unsigned int offset = prefixlen / 8;
	unsigned int shift  = 7 - (prefixlen % 8);

	return (prefix[offset] >> shift) & 1;
}

static inline unsigned int
prefix6_bit(const struct in6_addr *prefix, const uint8_t prefixlen)
{
	return prefix_bit((const u_char *) &prefix->s6_addr, prefixlen);
}


/*
 *	Prototypes
 */
extern int prefix_match(const prefix_t *, const prefix_t *);
extern int prefix_copy(prefix_t *, const prefix_t *);
extern int str2prefix(const char *, prefix_t *);
extern int ip2prefix_ipv4(const uint32_t, prefix_t *);
extern prefix_t *prefix_alloc(void);
extern void prefix_free(prefix_t *);
extern void prefix_dump(prefix_t *);

#endif
