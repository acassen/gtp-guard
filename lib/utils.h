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

#ifndef _UTILS_H
#define _UTILS_H

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

/* Evaluates to -1, 0 or 1 as appropriate.
 * Avoids a - b <= 0 producing "warning: assuming signed overflow does not occur when simplifying ‘X - Y <= 0’ to ‘X <= Y’ [-Wstrict-overflow]" */
#define less_equal_greater_than(a,b)    ({ typeof(a) _a = (a); typeof(b) _b = (b); (_a) < (_b) ? -1 : (_a) == (_b) ? 0 : 1; })

/* Some library functions that take pointer parameters should have them
 * specified as const pointers, but don't. We need to cast away the constness,
 * but also want to avoid compiler warnings for doing so. The following "trick"
 * achieves that. */
#define no_const(type, var_cp) \
({ union { type *p; const type *cp; } ps = { .cp = var_cp }; \
 ps.p;})
#define no_const_char_p(var_cp) no_const(char, var_cp)

/* Funky version of ARRAY_SIZE Macro */
#define ARRAY_SIZE(arr) \
    (sizeof(arr) / sizeof((arr)[0]) \
     + sizeof(typeof(int[1 - 2 * \
           !!__builtin_types_compatible_p(typeof(arr), \
                 typeof(&arr[0]))])) * 0)

/* defines */
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

/* ASM related */
static inline void cpu_relax(void)
{
	asm volatile("rep; nop" ::: "memory");
}

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

/* global vars exported */
extern unsigned long debug;

/* Prototypes defs */
extern void dump_buffer(char *, char *, int);
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
uint32_t inet_broadcast(uint32_t, uint32_t);
uint32_t inet_cidrtomask(uint8_t);
extern char *get_local_name(void);
extern int string_equal(const char *, const char *);
extern char hextochar(char);
extern int hextostring(char *, int, char *);
extern int stringtohex(const char *, int, char *, int);
extern int swapbuffer(uint8_t *, int, uint8_t *);
extern int __set_nonblock(int);
extern uint32_t adler_crc32(uint8_t *, size_t);
extern uint32_t fletcher_crc32(uint8_t *, size_t);
extern int integer_to_string(const int, char *, size_t);
extern uint32_t poor_prng(unsigned int *);
extern uint32_t xorshift_prng(uint64_t *);
extern size_t bsd_strlcpy(char *, const char *, size_t);
extern size_t bsd_strlcat(char *, const char *, size_t);
extern char *fd2str(int, char *, size_t);

#endif
