/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/version.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

#include "addr.h"


socklen_t
addr_len(const union addr *a)
{
	switch (a->sa.sa_family) {
	case AF_INET:
		return sizeof (a->sin);
	case AF_INET6:
		return sizeof (a->sin6);
	case AF_PACKET:
		return sizeof (a->sll);
	default:
		return 0;
	}
}

void
addr_copy(union addr *dst, const union addr *src)
{
	socklen_t l = addr_len(src);

	if (l > 0)
		memcpy(&dst->ss, &src->ss, l);
	else
		dst->sa.sa_family = AF_UNSPEC;
}

int
addr_cmp(const union addr *la, const union addr *ra)
{
	int r;

	if (la->sa.sa_family < ra->sa.sa_family)
		return -1;
	else if (la->sa.sa_family > ra->sa.sa_family)
		return 1;

	switch (la->sa.sa_family) {
	case AF_INET:
		r = memcmp(&la->sin.sin_addr, &ra->sin.sin_addr,
			   sizeof (la->sin.sin_addr));
		if (r != 0)
			return r;
		if (la->sin.sin_port < ra->sin.sin_port)
			return -1;
		if (la->sin.sin_port > ra->sin.sin_port)
			return 1;
		return 0;

	case AF_INET6:
		r = memcmp(&la->sin6.sin6_addr, &ra->sin6.sin6_addr,
			   sizeof (la->sin6.sin6_addr));
		if (r != 0)
			return r;
		if (la->sin6.sin6_port < ra->sin6.sin6_port)
			return -1;
		if (la->sin6.sin6_port > ra->sin6.sin6_port)
			return 1;
		return 0;

	case AF_PACKET:
		if (la->sll.sll_ifindex < ra->sll.sll_ifindex)
			return -1;
		if (la->sll.sll_ifindex > ra->sll.sll_ifindex)
			return 1;
		return 0;

	default:
		return 0;
	}
}

int
addr_cmp_ip(const union addr *la, const union addr *ra)
{
	if (la->sa.sa_family < ra->sa.sa_family)
		return -1;
	else if (la->sa.sa_family > ra->sa.sa_family)
		return 1;

	switch (la->sa.sa_family) {
	case AF_INET:
		return memcmp(&la->sin.sin_addr, &ra->sin.sin_addr,
			      sizeof (la->sin.sin_addr));
	case AF_INET6:
		return memcmp(&la->sin6.sin6_addr, &ra->sin6.sin6_addr,
			      sizeof (la->sin6.sin6_addr));
	default:
		return 0;
	}
}

int
addr_cmp_port(const union addr *la, const union addr *ra)
{
	if (la->sa.sa_family < ra->sa.sa_family)
		return -1;
	else if (la->sa.sa_family > ra->sa.sa_family)
		return 1;

	switch (la->sa.sa_family) {
	case AF_INET:
		return !(la->sin.sin_port == ra->sin.sin_port);
	case AF_INET6:
		return !(la->sin6.sin6_port == ra->sin6.sin6_port);
	default:
		return 0;
	}
}


uint16_t
addr_get_port(const union addr *a)
{
	switch (a->sa.sa_family) {
	case AF_INET:
		return ntohs(a->sin.sin_port);
	case AF_INET6:
		return ntohs(a->sin6.sin6_port);
	default:
		return 0;
	}
}

void
addr_set_port(union addr *a, uint16_t port)
{
	switch (a->sa.sa_family) {
	case AF_INET:
		a->sin.sin_port = htons(port);
		break;
	case AF_INET6:
		a->sin6.sin6_port = htons(port);
		break;
	}
}

bool
addr_is_unicast(const union addr *a)
{
	uint32_t addr;
	uint8_t last;

	if (a == NULL)
		return false;

	switch (a->sa.sa_family) {
	case AF_INET:
		addr = ntohl(a->sin.sin_addr.s_addr);

		/* must not be a bcast addr or network addr */
		last = addr & 0xff;
		if (last == 0 || last == 0xff)
			return false;

		/* must not be a multicast address */
		if ((addr & 0xf0000000) >= 0xe0000000)
			return false;

		return true;

	case AF_INET6:
		if (!memcmp(&a->sin6.sin6_addr, &in6addr_any,
			    sizeof (in6addr_any)))
			return false;
		return true;

	default:
		return false;
	}
}


/*
 * sockaddr -> ipv4:port or [ipv6]:port
 */
char *
addr_stringify(const union addr *a, char *buf, size_t buf_size)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	if (getnameinfo(&a->sa, sizeof (*a),
			hbuf, sizeof (hbuf), sbuf, sizeof (sbuf),
			NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
		if (sbuf[0] == '0' && !sbuf[1])
			snprintf(buf, buf_size, "%s", hbuf);
		else
			snprintf(buf, buf_size, "%s:%s", hbuf, sbuf);
	} else {
		buf[0] = 0;
	}

	return buf;
}

/*
 * sockaddr -> ipv4 or ipv6
 */
char *
addr_stringify_ip(const union addr *a, char *buf, size_t buf_size)
{
	if (getnameinfo(&a->sa, sizeof (*a),
			buf, buf_size, NULL, 0,
			NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
	} else {
		buf[0] = 0;
	}

	return buf;
}

/*
 * sockaddr -> ipv4 or ipv6
 */
char *
addr_stringify_port(const union addr *a, char *buf, size_t buf_size)
{
	uint16_t port = addr_get_port(a);

	if (port)
		snprintf(buf, buf_size, "%d", port);
	else
		buf[0] = 0;

	return buf;
}


/*
 * parse ipv4:port or [ipv6]:port
 */
int
addr_parse(char *paddr, union addr *a)
{
	struct addrinfo *res, hints;
	unsigned int port;
	char *pport, *end;
	int ret;

	memset(&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags |= AI_NUMERICHOST;

	/* remove [] from ipv6 address (port is after) */
	if (paddr[0] == '[') {
		paddr++;
		pport = strchr(paddr, ']');
		if (pport)
			*pport++ = 0;

	} else {
		pport = paddr;
	}

	pport = strchr(pport, ':');
	if (pport != NULL) {
		/* multiple ':': must be an ipv6 */
		if (strchr(pport + 1, ':') == NULL)
			*pport++ = 0;
		else
			pport = NULL;
	}

	ret = getaddrinfo(paddr, NULL, &hints, &res);
	if (ret || !res)
		return 1;

	memcpy(a, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (!pport)
		return 0;

	port = strtoul(pport, &end, 10);
	if (port > 65535 || *end)
		return 1;

	switch (a->sa.sa_family) {
	case AF_INET:
	default:
		a->sin.sin_port = htons(port);
		break;
	case AF_INET6:
		a->sin6.sin6_port = htons(port);
		break;
	}

	return 0;
}

int
addr_parse_const(const char *paddr, union addr *a)
{
	char buf[strlen(paddr) + 1];

	strcpy(buf, paddr);
	return addr_parse(buf, a);
}

int
addr_parse_iface(const char *iface_name, union addr *a)
{
	struct if_nameindex *if_nidxs, *itf;

	if_nidxs = if_nameindex();
	if (if_nidxs == NULL)
		return 1;

	for (itf = if_nidxs; itf->if_index; itf++) {
		if (!strcmp(itf->if_name, iface_name)) {
			memset(a, 0x00, sizeof (a->sll));
			a->sll.sll_family = AF_PACKET;
			a->sll.sll_protocol = SOCK_RAW;
			a->sll.sll_ifindex = itf->if_index;
			if_freenameindex(if_nidxs);
			return 0;
		}
	}
	if_freenameindex(if_nidxs);
	return 1;
}



/*
 * parse ipv4 or ipv6, with optional netmask and range. ex:
 *
 * 172.18.68.0/24
 * 172.18.68.200-172.18.68.250
 *
 * for ipv6, out_count is the number of /64 prefixes
 *
 * first_ip is false   10.13.26.16/8 => 10.13.26.16
 * first_ip is true    10.13.26.16/8 => 10.0.0.0
 */
int
addr_parse_ip(const char *paddr, union addr *a,
	      uint32_t *out_netmask, uint64_t *out_count,
	      bool first_ip)
{
	struct addrinfo *res, hints;
	char buf[strlen(paddr) + 1];
	uint32_t mask_max, mask;
	char *nmask, *end, *srange;
	union addr aend;
	int ret;

	strcpy(buf, paddr);

	aend.family = AF_UNSPEC;
	if (out_count != NULL) {
		*out_count = 1;
		srange = strchr(buf, '-');
		if (srange != NULL) {
			*srange = 0;
			if (addr_parse_ip(srange + 1, &aend, NULL, NULL, 0))
				return 1;
		}
	}

	memset(&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags |= AI_NUMERICHOST;

	nmask = strchr(buf, '/');
	if (nmask)
		*nmask++ = 0;

	ret = getaddrinfo(buf, NULL, &hints, &res);
	if (ret || !res)
		return 1;

	memcpy(a, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (!nmask && !out_netmask && !out_count)
		return 0;

	mask_max = a->family == AF_INET6 ? 128 : 32;
	if (nmask) {
		mask = strtoul(nmask, &end, 10);
		if (mask > mask_max || *end)
			return 1;

		switch (a->family) {
		case AF_INET:
			if (first_ip)
				a->sin.sin_addr.s_addr &=
					htonl(~((1 << (mask_max - mask)) - 1));
			if (out_count != NULL)
				*out_count = 1 << (32 - mask);
			break;
		case AF_INET6:
			if (first_ip && (mask & 0x07))
				a->sin6.sin6_addr.s6_addr[mask / 8] &=
					~(0xff >> (mask & 0x07));
			if (first_ip && mask <= 120)
				memset(a->sin6.sin6_addr.s6_addr +
				       ((mask + 7) / 8),
				       0x00, 16 - ((mask + 7) / 8));
			if (out_count != NULL && mask < 64)
				*out_count = 1ULL << (64 - mask);
			break;
		}

	} else {
		mask = mask_max;
	}

	if (out_netmask)
		*out_netmask = mask;

	if (aend.family != AF_UNSPEC) {
		if (aend.family != a->family)
			return 1;
		switch (a->family) {
		case AF_INET:
			if (ntohl(aend.sin.sin_addr.s_addr) >
			    ntohl(a->sin.sin_addr.s_addr)) {
				*out_count = ntohl(aend.sin.sin_addr.s_addr) -
					ntohl(a->sin.sin_addr.s_addr) + 1;
			}
			break;

		case AF_INET6:
			*out_count =
				((uint64_t)(aend.sin6.sin6_addr.s6_addr32[0] -
				  a->sin6.sin6_addr.s6_addr32[0]) << 32) |
				(aend.sin6.sin6_addr.s6_addr32[1] -
				 a->sin6.sin6_addr.s6_addr32[1]);
			break;
		}
	}

	return 0;
}
