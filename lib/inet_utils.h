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

#ifndef _INET_UTILS_H
#define _INET_UTILS_H

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <stdbool.h>

/* defines */
#define INET_DEFAULT_CONNECTION_KEEPIDLE	20
#define INET_DEFAULT_CONNECTION_KEEPCNT		2
#define INET_DEFAULT_CONNECTION_KEEPINTVL	10

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define NIPQUAD(__addr)                         \
	((unsigned char *)&(__addr))[0],        \
	((unsigned char *)&(__addr))[1],        \
	((unsigned char *)&(__addr))[2],        \
	((unsigned char *)&(__addr))[3]
#elif __BYTE_ORDER == __BIG_ENDIAN
#define NIPQUAD(__addr)                         \
	((unsigned char *)&(__addr))[3],        \
	((unsigned char *)&(__addr))[2],        \
	((unsigned char *)&(__addr))[1],        \
	((unsigned char *)&(__addr))[0]
#else
#error "Please fix <bits/endian.h>"
#endif

#define ETHER_FMT "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
#define ETHER_BYTES(__eth_addr)			\
	(unsigned char)__eth_addr[0],		\
	(unsigned char)__eth_addr[1],		\
	(unsigned char)__eth_addr[2],		\
	(unsigned char)__eth_addr[3],		\
	(unsigned char)__eth_addr[4],		\
	(unsigned char)__eth_addr[5]

#define ETHER_IS_BROADCAST(__eth_addr)					\
	(((__eth_addr)[0] & (__eth_addr)[1] & (__eth_addr)[2] &		\
	  (__eth_addr)[3] & (__eth_addr)[4] & (__eth_addr)[5]) == 0xff)

/* inline stuff */
static inline int __ip6_addr_equal(const struct in6_addr *a1,
                                   const struct in6_addr *a2)
{
	return (((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
		(a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
		(a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
		(a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0);
}

static inline bool __attribute__((pure))
sockstorage_equal(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2)
{
	if (s1->ss_family != s2->ss_family)
		return false;

	if (s1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a1 = (const struct sockaddr_in6 *) s1;
		const struct sockaddr_in6 *a2 = (const struct sockaddr_in6 *) s2;

		if (__ip6_addr_equal(&a1->sin6_addr, &a2->sin6_addr) &&
		    (a1->sin6_port == a2->sin6_port))
			return true;
	} else if (s1->ss_family == AF_INET) {
		const struct sockaddr_in *a1 = (const struct sockaddr_in *) s1;
		const struct sockaddr_in *a2 = (const struct sockaddr_in *) s2;

		if ((a1->sin_addr.s_addr == a2->sin_addr.s_addr) &&
		    (a1->sin_port == a2->sin_port))
			return true;
	} else if (s1->ss_family == AF_UNSPEC)
		return true;

	return false;
}

/* Prototypes defs */
extern uint16_t in_csum(uint16_t *, int, uint16_t);
extern uint16_t udp_csum(const void *, size_t, uint32_t, uint32_t);
extern char *inet_ntop2(uint32_t);
extern char *inet_ntoa2(uint32_t, char *);
extern uint8_t inet_stom(char *);
extern uint8_t inet_stor(char *);
extern int inet_stosockaddr(const char *, const uint16_t, struct sockaddr_storage *);
extern int inet_ip4tosockaddr(uint32_t, struct sockaddr_storage *);
extern char *inet_sockaddrtos(struct sockaddr_storage *);
extern char *inet_sockaddrtos2(struct sockaddr_storage *, char *);
extern uint16_t inet_sockaddrport(struct sockaddr_storage *);
extern uint32_t inet_sockaddrip4(struct sockaddr_storage *);
extern int inet_sockaddrip6(struct sockaddr_storage *, struct in6_addr *);
extern int inet_sockaddrifindex(struct sockaddr_storage *);
extern int inet_ston(const char *, uint32_t *);
extern uint32_t inet_broadcast(uint32_t, uint32_t);
extern uint32_t inet_cidrtomask(uint8_t);
extern char *inet_fd2str(int, char *, size_t);
extern int inet_setsockopt_reuseaddr(int, int);
extern int inet_setsockopt_nolinger(int, int);
extern int inet_setsockopt_tcpcork(int, int);
extern int inet_setsockopt_nodelay(int, int);
extern int inet_setsockopt_keepalive(int, int);
extern int inet_setsockopt_tcp_keepidle(int, int);
extern int inet_setsockopt_tcp_keepcnt(int, int);
extern int inet_setsockopt_tcp_keepintvl(int, int);
extern int inet_setsockopt_rcvtimeo(int, int);
extern int inet_setsockopt_sndtimeo(int, int);
extern int inet_setsockopt_reuseport(int, int);
extern int inet_setsockopt_hdrincl(int);
extern int inet_setsockopt_broadcast(int);
extern int inet_setsockopt_promisc(int, int, bool);
extern int inet_setsockopt_attach_bpf(int, int);
extern int inet_setsockopt_no_receive(int *);
extern int inet_setsockopt_rcvbuf(int *, int);
extern int inet_setsockopt_bindtodevice(int *, const char *);
extern int inet_setsockopt_priority(int *, int);

#endif
