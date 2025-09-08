/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IP prefix implementation
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#include <string.h>
#include <arpa/inet.h>

#include "memory.h"
#include "inet_utils.h"
#include "prefix.h"

/* Maskbit. */
static const uint8_t maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

#define MASKBIT(offset)  ((0xff << (PNBBY - (offset))) & 0xff)


/*
 *	If n includes p prefix then return 1 else return 0.
 */
int
prefix_match(const struct prefix *n, const struct prefix *p)
{
	int offset;
	int shift;
	const uint8_t *np, *pp;

	/* If n's prefix is longer than p's one return 0. */
	if (n->prefixlen > p->prefixlen)
		return 0;

	/* Set both prefix's head pointer. */
	np = (const uint8_t *)&n->u.prefix;
	pp = (const uint8_t *)&p->u.prefix;

	offset = n->prefixlen / PNBBY;
	shift =  n->prefixlen % PNBBY;

	if (shift) {
		if (maskbit[shift] & (np[offset] ^ pp[offset])) {
			return 0;
		}
	}

	while (offset--) {
		if (np[offset] != pp[offset]) {
			return 0;
		}
	}

	return 1;
}

/*
 *	Copy prefix from src to dest.
 */
int
prefix_copy(struct prefix *dst, const struct prefix *src)
{
	dst->family = src->family;
	dst->prefixlen = src->prefixlen;

	if (src->family == AF_INET) {
		dst->u.prefix4 = src->u.prefix4;
	} else if (src->family == AF_INET6) {
		dst->u.prefix6 = src->u.prefix6;
	} else {
		return -1;
	}

	return 0;
}


/*
 *	Convert a string to a prefix
 */
int
str2prefix_ipv4(const char *str, struct prefix_ipv4 *p)
{
	int ret, plen;
	char *pnt, *cp;

	/* Find slash inside string. */
	pnt = strchr(str, '/');

	/* String doesn't contail slash. */
	if (pnt == NULL) {
		/* Convert string to prefix. */
		ret = inet_aton(str, &p->prefix);
		if (ret == 0)
			return -1;

		/* If address doesn't contain slash we assume it host address. */
		p->prefixlen = IPV4_MAX_BITLEN;

		return 0;
	} else {
		cp = MALLOC((pnt - str) + 1);
		strncpy(cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_aton(cp, &p->prefix);
		FREE(cp);

		/* Get prefix length. */
		plen = (u_char) atoi(++pnt);
		if (plen > IPV4_MAX_PREFIXLEN)
			return -1;

		p->prefixlen = plen;
	}

	p->family = AF_INET;

	return ret ? 0 : -1;
}

int
str2prefix_ipv6(const char *str, struct prefix_ipv6 *p)
{
	int ret, plen;
	char *pnt, *cp;

	pnt = strchr(str, '/');

	/* If string doesn't contain `/' treat it as host route. */
	if (pnt == NULL) {
		ret = inet_pton(AF_INET6, str, &p->prefix);
		if (ret == 0)
			return -1;
		p->prefixlen = IPV6_MAX_BITLEN;
	} else {
		cp = MALLOC((pnt - str) + 1);
		strncpy (cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_pton(AF_INET6, cp, &p->prefix);
		FREE(cp);
		if (ret == 0)
			return -1;
		plen = (u_char)atoi (++pnt);
		if (plen > 128)
			return -1;
		p->prefixlen = plen;
	}

	p->family = AF_INET6;

	return ret ? 0 : -1;
}

int
str2prefix(const char *str, struct prefix *p)
{
	int err;

	/* First we try to convert string to struct prefix_ipv4. */
	err = str2prefix_ipv4(str, (struct prefix_ipv4 *) p);
	if (!err)
		return 0;

	/* Next we try to convert string to struct prefix_ipv6. */
	return str2prefix_ipv6(str, (struct prefix_ipv6 *) p);
}

/*
 *	Convert bytes to prefix
 */
int
ip2prefix_ipv4(const uint32_t addr, struct prefix *p)
{
	struct prefix_ipv4 *prefix_ipv4 = (struct prefix_ipv4 *) p;

	prefix_ipv4->family = AF_INET;
	prefix_ipv4->prefixlen = IPV4_MAX_BITLEN;
	prefix_ipv4->prefix.s_addr = addr;

	return 0;
}


/*
 *	Prefix alloc
 */
struct prefix *
prefix_alloc(void)
{
	struct prefix *p = (struct prefix *) MALLOC(sizeof(*p));
	return p;
}

void
prefix_free(struct prefix *p)
{
	FREE(p);
}

void
prefix_dump(struct prefix *p)
{
	printf("prefix : %u.%u.%u.%u/%d\n"
	       , NIPQUAD(p->u.prefix4.s_addr)
	       , p->prefixlen);
}
