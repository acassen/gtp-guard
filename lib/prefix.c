/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IP prefix implementation
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#include <time.h>
#include <ctype.h>
#include <syslog.h>
#include "memory.h"
#include "utils.h"
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
prefix_match(const prefix_t *n, const prefix_t *p)
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
prefix_copy(prefix_t *dest, const prefix_t *src)
{
	dest->family = src->family;
	dest->prefixlen = src->prefixlen;

	if (src->family == AF_INET) {
		dest->u.prefix4 = src->u.prefix4;
	} else if (src->family == AF_INET6) {
		dest->u.prefix6 = src->u.prefix6;
	} else {
		return -1;
	}

	return 0;
}


/*
 *	Convert a string to a prefix
 */
int
str2prefix_ipv4(const char *str, prefix_ipv4_t *p)
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
			return 0;

		/* If address doesn't contain slash we assume it host address. */
		p->prefixlen = IPV4_MAX_BITLEN;

		return ret;
	} else {
		cp = MALLOC((pnt - str) + 1);
		strncpy(cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_aton(cp, &p->prefix);
		FREE(cp);

		/* Get prefix length. */
		plen = (u_char) atoi(++pnt);
		if (plen > IPV4_MAX_PREFIXLEN)
			return 0;

		p->prefixlen = plen;
	}

	p->family = AF_INET;

	return ret;
}

int
str2prefix_ipv6(const char *str, prefix_ipv6_t *p)
{
	int ret, plen;
	char *pnt, *cp;

	pnt = strchr(str, '/');

	/* If string doesn't contain `/' treat it as host route. */
	if (pnt == NULL) {
		ret = inet_pton(AF_INET6, str, &p->prefix);
		if (ret == 0)
			return 0;
		p->prefixlen = IPV6_MAX_BITLEN;
	} else {
		cp = MALLOC((pnt - str) + 1);
		strncpy (cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_pton(AF_INET6, cp, &p->prefix);
		FREE(cp);
		if (ret == 0)
			return 0;
		plen = (u_char)atoi (++pnt);
		if (plen > 128)
			return 0;
		p->prefixlen = plen;
	}

	p->family = AF_INET6;

	return ret;
}

int
str2prefix(const char *str, prefix_t *p)
{
	int ret;

	/* First we try to convert string to struct prefix_ipv4. */
	ret = str2prefix_ipv4(str, (prefix_ipv4_t *) p);
	if (ret)
		return ret;

	/* Next we try to convert string to struct prefix_ipv6. */
	ret = str2prefix_ipv6(str, (prefix_ipv6_t *) p);
	if (ret)
		return ret;

	return 0;
}

/*
 *	Convert bytes to prefix
 */
int
ip2prefix_ipv4(const uint32_t ip_address, prefix_t *p)
{
	prefix_ipv4_t *prefix_ipv4 = (prefix_ipv4_t *) p;

	prefix_ipv4->family = AF_INET;
	prefix_ipv4->prefixlen = IPV4_MAX_BITLEN;
	prefix_ipv4->prefix.s_addr = ip_address;

	return 0;
}


/*
 *	Prefix alloc
 */
prefix_t *
prefix_alloc(void)
{
	prefix_t *p = (prefix_t *) MALLOC(sizeof(prefix_t));
	return p;
}

void
prefix_free(prefix_t *p)
{
	FREE(p);
}

void
prefix_dump(prefix_t *p)
{
	syslog(LOG_INFO, "prefix : %u.%u.%u.%u/%d"
		       , NIPQUAD(p->u.prefix4.s_addr)
		       , p->prefixlen);
}
