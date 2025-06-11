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

/* global vars exported */
extern unsigned long debug;

/* Prototypes defs */
extern void dump_buffer(const char *, char *, int);
extern void buffer_to_c_array(const char *, char *, size_t);
extern char *get_local_name(void);
extern int string_equal(const char *, const char *);
extern char hextochar(char);
extern int hextostring(char *, int, char *);
extern int stringtohex(const char *, int, char *, int);
extern int swapbuffer(uint8_t *, int, uint8_t *);
extern uint32_t adler_crc32(uint8_t *, size_t);
extern uint32_t fletcher_crc32(uint8_t *, size_t);
extern int integer_to_string(const int, char *, size_t);
extern uint32_t poor_prng(unsigned int *);
extern uint32_t xorshift_prng(uint64_t *);
extern size_t bsd_strlcpy(char *, const char *, size_t);
extern size_t bsd_strlcat(char *, const char *, size_t);
extern char *memcpy2str(char *, size_t, const void *, size_t);
extern int open_pipe(int [2]);

#endif
