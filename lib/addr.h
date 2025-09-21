/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024, 2025 Olivier Gournet, <gournet.olivier@gmail.com> */

#pragma once

#include <stdbool.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

#ifdef __cplusplus
extern "C" {
#endif

union addr
{
	sa_family_t family;
	struct sockaddr sa;
	struct sockaddr_in sin;		/* AF_INET */
	struct sockaddr_in6 sin6;	/* AF_INET6 */
	struct sockaddr_ll sll;		/* AF_PACKET */
	struct sockaddr_storage ss;
};

static void addr_zero(union addr *a);
socklen_t addr_len(const union addr *a);
void addr_copy(union addr *dst, const union addr *src);
int addr_cmp(const union addr *la, const union addr *ra);
int addr_cmp_ip(const union addr *la, const union addr *ra);
int addr_cmp_port(const union addr *la, const union addr *ra);
int addr_cmp_ss(const union addr *la, const union addr *ra);
uint16_t addr_get_port(const union addr *a);
void addr_set_port(union addr *a, uint16_t port);
bool addr_is_unicast(const union addr *a);
char *addr_stringify(const union addr *a, char *buf, size_t buf_size);
char *addr_stringify_ip(const union addr *a, char *buf, size_t buf_size);
char *addr_stringify_port(const union addr *a, char *buf, size_t buf_size);
int addr_parse(char *paddr, union addr *a);
int addr_parse_const(const char *paddr, union addr *a);
int addr_parse_ip(const char *paddr, union addr *a, uint32_t *out_netmask,
		  uint64_t *out_count, bool first_ip);
int addr_parse_iface(const char *iface_name, union addr *a);
int addr_get_ifindex(const union addr *a);
uint32_t addr_hash_in6_addr(const struct in6_addr *addr);

static inline void
addr_zero(union addr *a)
{
	a->sa.sa_family = AF_UNSPEC;
}

static inline int __addr_ip4_equal(const struct in_addr *a1,
				   const struct in_addr *a2)
{
	return (a1->s_addr == a2->s_addr);
}

static inline int __addr_ip6_equal(const struct in6_addr *a1,
				   const struct in6_addr *a2)
{
	return (((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
		 (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
		 (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
		 (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0);
}

static inline int __attribute__((pure))
ss_cmp(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2)
{
	if (s1->ss_family < s2->ss_family)
		return -1;
	if (s1->ss_family > s2->ss_family)
		return 1;

	if (s1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a1 = (const struct sockaddr_in6 *) s1;
		const struct sockaddr_in6 *a2 = (const struct sockaddr_in6 *) s2;

		if (__addr_ip6_equal(&a1->sin6_addr, &a2->sin6_addr) &&
		    (a1->sin6_port == a2->sin6_port))
			return 0;
	} else if (s1->ss_family == AF_INET) {
		const struct sockaddr_in *a1 = (const struct sockaddr_in *) s1;
		const struct sockaddr_in *a2 = (const struct sockaddr_in *) s2;

		if (__addr_ip4_equal(&a1->sin_addr, &a2->sin_addr) &&
		    (a1->sin_port == a2->sin_port))
			return 0;
	} else if (s1->ss_family == AF_UNSPEC)
		return 0;

	return -1;
}


#ifdef __cplusplus
} // extern "C"
#endif
