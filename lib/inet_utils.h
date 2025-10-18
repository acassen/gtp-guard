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
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* defines */
#define INET_DEFAULT_CONNECTION_KEEPIDLE	20
#define INET_DEFAULT_CONNECTION_KEEPCNT		2
#define INET_DEFAULT_CONNECTION_KEEPINTVL	10

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define NIPQUAD(__addr)				\
	((unsigned char *)&(__addr))[0],	\
	((unsigned char *)&(__addr))[1],	\
	((unsigned char *)&(__addr))[2],	\
	((unsigned char *)&(__addr))[3]
#elif __BYTE_ORDER == __BIG_ENDIAN
#define NIPQUAD(__addr)				\
	((unsigned char *)&(__addr))[3],	\
	((unsigned char *)&(__addr))[2],	\
	((unsigned char *)&(__addr))[1],	\
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
struct ip_address {
	uint16_t		family;
	union {
		struct in_addr	sin_addr;
		struct in6_addr	sin6_addr;
	} u;
};


/* Prototypes defs */
uint16_t in_csum(uint16_t *addr, int, uint16_t csum);
uint16_t udp_csum(const void *buffer, size_t len,
		  uint32_t src_addr, uint32_t dst_addr);
char *inet_fqdn2str(char *dst, size_t dsize, const uint8_t *fqdn, size_t fsize);
char *inet_ntop2(uint32_t addr);
char *inet_ntoa2(uint32_t addr, char *buffer);
uint8_t inet_stom(char *str);
uint8_t inet_stor(char *str);
int inet_stoipaddress(const char *str, struct ip_address *addr);
char *inet_ipaddresstos(struct ip_address *addr, char *str);
int inet_stosockaddr(const char *str, const uint16_t port,
		     struct sockaddr_storage *addr);
int inet_ip4tosockaddr(uint32_t addr_ip,
		       struct sockaddr_storage *addr);
char *inet_sockaddrtos2(struct sockaddr_storage *addr,
			char *addr_str);
char *inet_sockaddrtos(struct sockaddr_storage *addr);
uint16_t inet_sockaddrport(struct sockaddr_storage *addr);
uint32_t inet_sockaddrip4(struct sockaddr_storage *addr);
int inet_sockaddrip6(struct sockaddr_storage *addr,
		     struct in6_addr *ip6);
int inet_ston(const char *str, uint32_t *addr);
uint32_t inet_broadcast(uint32_t network, uint32_t netmask);
uint32_t inet_cidrtomask(uint8_t cidr);
char *inet_fd2str(int fd, char *dst, size_t dsize);
int inet_setsockopt_reuseaddr(int fd, int onoff);
int inet_setsockopt_nolinger(int fd, int onoff);
int inet_setsockopt_tcpcork(int fd, int onoff);
int inet_setsockopt_nodelay(int fd, int onoff);
int inet_setsockopt_keepalive(int fd, int optval);
int inet_setsockopt_tcp_keepidle(int fd, int optval);
int inet_setsockopt_tcp_keepcnt(int fd, int optval);
int inet_setsockopt_tcp_keepintvl(int fd, int optval);
int inet_setsockopt_rcvtimeo(int fd, int timeout);
int inet_setsockopt_sndtimeo(int fd, int timeout);
int inet_setsockopt_reuseport(int fd, int onoff);
int inet_setsockopt_hdrincl(int fd);
int inet_setsockopt_broadcast(int fd);
int inet_setsockopt_promisc(int fd, int ifindex, bool enable);
int inet_setsockopt_attach_bpf(int fd, int prog_fd);
int inet_setsockopt_no_receive(int fd);
int inet_setsockopt_rcvbuf(int fd, int optval);
int inet_setsockopt_sndbuf(int fd, int optval );
int inet_setsockopt_sndbufforce(int fd, int optval);
int inet_setsockopt_bindtodevice(int fd, const char *ifname);
int inet_setsockopt_priority(int fd, int family);
