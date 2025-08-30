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

#include <stddef.h>
#include <stdint.h>

/* Evaluates to -1, 0 or 1 as appropriate.
 * Avoids a - b <= 0 producing "warning: assuming signed overflow does not occur when simplifying ‘X - Y <= 0’ to ‘X <= Y’ [-Wstrict-overflow]" */
#define less_equal_greater_than(a,b)    ({ typeof(a) _a = (a); typeof(b) _b = (b); (_a) < (_b) ? -1 : (_a) == (_b) ? 0 : 1; })

/* Functions that can return EAGAIN also document that they can return
 * EWOULDBLOCK, and that both should be checked. If they are the same
 * value, that is unnecessary. */
#if EAGAIN == EWOULDBLOCK
#define check_EAGAIN(xx)        ((xx) == EAGAIN)
#else
#define check_EAGAIN(xx)        ((xx) == EAGAIN || (xx) == EWOULDBLOCK)
#endif

/* Used in functions returning a string matching a defined value */
#define switch_define_str(x) case x: return #x

/* Some library functions that take pointer parameters should have them
 * specified as const pointers, but don't. We need to cast away the constness,
 * but also want to avoid compiler warnings for doing so. The following "trick"
 * achieves that. */
#define no_const(type, var_cp) \
({ union { type *p; const type *cp; } ps = { .cp = var_cp }; \
 ps.p;})
#define no_const_char_p(var_cp) no_const(char, var_cp)

/* ARRAY_SIZE */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* STR(MACRO) stringifies MACRO */
#define _STR(x) #x
#define STR(x) _STR(x)

/* global vars exported */
extern unsigned long debug;

/* Prototypes defs */
void dump_buffer(const char *prefix, char *buf, int count);
void buffer_to_c_array(const char *name, char *buffer, size_t blen);
char *get_local_name(void);
int string_equal(const char *str1, const char *str2);
char hextochar(char c);
int hextostring(char *data, int size, char *buffer_out);
int stringtohex(const char *buffer_in, int size_in, char *buffer_out, int size_out);
int swapbuffer(uint8_t *buffer_in, int size_in, uint8_t *buffer_out);
uint32_t adler_crc32(uint8_t *data, size_t len);
uint32_t fletcher_crc32(uint8_t *data, size_t len);
int integer_to_string(const int value, char *str, size_t size);
uint32_t poor_prng(unsigned int *seed);
uint32_t xorshift_prng(uint64_t *state);
size_t bsd_strlcpy(char *dst, const char *src, size_t dsize);
size_t bsd_strlcat(char *dst, const char *src, size_t dsize);
char *memcpy2str(char *dst, size_t dsize, const void *src, size_t ssize);
int open_pipe(int pipe_arr[2]);
