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

#pragma once

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

/* struct */
typedef struct _ip_address {
	uint16_t		family;
	union {
		struct in_addr	sin_addr;
		struct in6_addr	sin6_addr;
	} u;
} ip_address_t;


/* Prototypes defs */
extern uint16_t in_csum(uint16_t *, int, uint16_t);
extern uint16_t udp_csum(const void *, size_t, uint32_t, uint32_t);
extern char *inet_ntop2(uint32_t);
extern char *inet_ntoa2(uint32_t, char *);
extern uint8_t inet_stom(char *);
extern uint8_t inet_stor(char *);
extern int inet_stoipaddress(const char *, ip_address_t *);
extern char *inet_ipaddresstos(ip_address_t *, char *);
extern int inet_stosockaddr(const char *, const uint16_t, struct sockaddr_storage *);
extern int inet_ip4tosockaddr(uint32_t, struct sockaddr_storage *);
extern char *inet_sockaddrtos(struct sockaddr_storage *);
extern char *inet_sockaddrtos2(struct sockaddr_storage *, char *);
extern uint16_t inet_sockaddrport(struct sockaddr_storage *);
extern uint32_t inet_sockaddrip4(struct sockaddr_storage *);
extern int inet_sockaddrip6(struct sockaddr_storage *, struct in6_addr *);
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
extern int inet_setsockopt_no_receive(int);
extern int inet_setsockopt_rcvbuf(int, int);
extern int inet_setsockopt_sndbuf(int, int);
extern int inet_setsockopt_sndbufforce(int, int);
extern int inet_setsockopt_bindtodevice(int, const char *);
extern int inet_setsockopt_priority(int, int);
