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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>

#include "utils.h"

/* global vars */
unsigned long debug = 0;


/*
 * like snprintf & vsnprintf, but always return number of char
 * written, this allows usage like this:
 *
 * len += scnprintf(buf + len, size - len, ...)
 */
int
vscnprintf(char *buf, size_t size, const char *format, va_list args)
{
	int ret;

	if (!size)
		return 0;
	ret = vsnprintf(buf, size, format, args);
	if ((size_t)ret > size - 1)
		return size - 1;
	return ret;
}

int
scnprintf(char *buf, size_t size, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vscnprintf(buf, size, format, ap);
	va_end(ap);
	return ret;
}

/* Display a buffer into a HEXA formated output */
size_t
hexdump(const char *prefix, const unsigned char *buffer, size_t bsize)
{
	size_t i, j;

	if (!buffer)
		return 0;

	for (i = 0; i < bsize; i += 16) {
		/* Print offset */
		printf("%s%08zx  ", prefix, i);

		/* Print hex values */
		for (j = 0; j < 16; j++) {
			if (i + j < bsize)
				printf("%02x ", buffer[i + j]);
			else
				printf("   ");

			if (j == 7)
				printf("- ");
		}

		/* Print ASCII representation */
		for (j = 0; j < 16 && i + j < bsize; j++) {
			unsigned char c = buffer[i + j];
			printf("%c", (c >= 32 && c <= 126) ? c : '.');
		}

		printf("\n");
	}

	return bsize;
}

ssize_t
hexdump_format(const char *prefix, unsigned char *dst, size_t dsize,
	       const unsigned char *src, size_t ssize)
{
	size_t i, j, pos = 0;

	if (!dst || !src)
		return -1;

	for (i = 0; i < ssize; i += 16) {
		/* Print offset */
		pos += scnprintf((char *)dst + pos, dsize - pos, "%s%04zx  ", prefix, i);

		/* Print hex values */
		for (j = 0; j < 16; j++) {
			if (i + j < ssize)
				pos += scnprintf((char *)dst + pos, dsize - pos, "%02x ", src[i + j]);
			else
				pos += scnprintf((char *)dst + pos, dsize - pos, "   ");

			if (j == 7)
				pos += scnprintf((char *)dst + pos, dsize - pos, "- ");
		}

		pos += scnprintf((char *)dst + pos, dsize - pos, " ");

		/* Print ASCII representation */
		for (j = 0; j < 16 && i + j < ssize; j++) {
			unsigned char c = src[i + j];
			pos += scnprintf((char *)dst + pos, dsize - pos, "%c",
					 (c >= 32 && c <= 126) ? c : '.');
		}

		/* Last '\n' MUST be under the caller's control */
		if (i + 16 < ssize)
			pos += scnprintf((char *)dst + pos, dsize - pos, "\n");
	}

	return pos;
}

void
buffer_to_c_array(const char *name, const unsigned char *buffer, size_t bsize)
{
	int i;

	printf("const unsigned char %s[%ld] = {\n  ", name, bsize);
	for (i = 0; i < bsize; i++)
		printf("0x%.2x%s%s", buffer[i] & 0xff
				   , (i < bsize - 1) ? "," : ""
				   , ((i + 1) % 16) ? " " : "\n  ");
	printf("\n};\n");
}

/* Getting localhost official canonical name */
char *
get_local_name(void)
{
	struct hostent *host;
	struct utsname name;

	if (uname(&name) < 0)
		return NULL;

	if (!(host = gethostbyname(name.nodename)))
		return NULL;

	return host->h_name;
}

/* String compare with NULL string handling */
int
string_equal(const char *str1, const char *str2)
{
	if (!str1 && !str2)
		return 1;
	if ((!str1 && str2) || (str1 && !str2))
		return 0;
	for (; *str1 == *str2; str1++, str2++) {
		if (*str1 == 0 || *str2 == 0)
			break;
	}

	return (*str1 == 0 && *str2 == 0);
}

/* String to Hexa */
char
hextochar(char c)
{
	char pseudo[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                          '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	return pseudo[(int) c];
}
int
hextostring(char *data, int size, char *buffer_out)
{
	char ch = 0x00;
	int i = 0, j = 0;

        for (i = 0; i < size; i++) {
                ch = (char) (data[i] & 0xf0);		/* Strip off high nibble */
                ch = (char) (ch >> 4);			/* shift the bits down */
                ch = (char) (ch & 0x0f);		/* must do this is high order bit is on! */
                buffer_out[j++] = hextochar(ch);	/* convert the nibble to a String Character */

                ch = (char) (data[i] & 0x0f);		/* Strip off low nibble */
                buffer_out[j++] = hextochar(ch);	/* convert the nibble to a String Character */
        }

        buffer_out[j++] = '\0';
        return 0;
}
int
stringtohex(const char *buffer_in, int size_in, char *buffer_out, int size_out)
{
        static char digits[] = "0123456789abcdef";
        const char *cp = buffer_in;
        int i=0, ch;

        while ((ch = *cp++) != '\0' && i < size_in) {
                const char *pch;
                if ((pch = strchr(digits, tolower(ch))) != NULL) {
                        buffer_out[i/2] |= (pch - digits) << 4 * (1 - (i % 2));
                        i++;
                }
        }

	return 0;
}

uint8_t
swapbyte(uint8_t data)
{
	return (data << 4) | (data >> 4);
}

int
swapbuffer(uint8_t *buffer_in, int size_in, uint8_t *buffer_out)
{
	int i;

	for (i = 0; i < size_in; i++)
		buffer_out[i] = swapbyte(buffer_in[i]);

	return 0;
}

/*
 *	CRC32 helpers
 */
/*
 * Simple ADLER CRC code. More info in rfc1950.
 * This one is optimized for speed.
 */
#define MOD_ADLER 65521
uint32_t
adler_crc32(uint8_t *data, size_t len)
{
        uint32_t a = 1, b = 0;

        while (len) {
                size_t tlen = len > 5550 ? 5550 : len;
                len -= tlen;
                do {
                        a += *data++;
                        b += a;
                } while (--tlen);

                a = (a & 0xffff) + (a >> 16) * (65536-MOD_ADLER);
                b = (b & 0xffff) + (b >> 16) * (65536-MOD_ADLER);
        }

        /* It can be shown that a <= 0x1013a here, so a single subtract will do. */
        if (a >= MOD_ADLER)
                a -= MOD_ADLER;

        /* It can be shown that b can reach 0xffef1 here. */
        b = (b & 0xffff) + (b >> 16) * (65536-MOD_ADLER);

        if (b >= MOD_ADLER)
                b -= MOD_ADLER;

        return (b << 16) | a;
}

/*
 * Fletcher's CRC. Formerly an ADLER CRC with modulo-65535
 */
uint32_t
fletcher_crc32(uint8_t *data, size_t len)
{
        uint32_t sum1 = 0xffff, sum2 = 0xffff;

        while (len) {
                unsigned tlen = len > 360 ? 360 : len;
                len -= tlen;
                do {
                        sum1 += *data++;
                        sum2 += sum1;
                } while (--tlen);
                sum1 = (sum1 & 0xffff) + (sum1 >> 16);
                sum2 = (sum2 & 0xffff) + (sum2 >> 16);
        }

        /* Second reduction step to reduce sums to 16 bits */
        sum1 = (sum1 & 0xffff) + (sum1 >> 16);
        sum2 = (sum2 & 0xffff) + (sum2 >> 16);

        return sum2 << 16 | sum1;
}


/* Convert an integer into a string */
int
integer_to_string(const int value, char *str, size_t size)
{
        int i, len = 0, t = value, s = size;

        for (i = value; i; i/=10) {
                if (++len > s)
                        return -1;
        }

        for (i = 0; i < len; i++,t/=10)
                str[len - (i + 1)] = t % 10 + '0';

        return len;
}

/*
 *	poor PRNG
 */
uint32_t
poor_prng(unsigned int *seed)
{
	uint32_t shuffle;

	shuffle = rand_r(seed) & 0xff;
	shuffle |= (rand_r(seed) & 0xff) << 8;
	shuffle |= (rand_r(seed) & 0xff) << 16;
	shuffle |= (rand_r(seed) & 0xff) << 24;

	return shuffle;
}

/*
 *	XorShift*
 */
uint32_t
xorshift_prng(uint64_t *state)
{
	*state ^= *state >> 12;
	*state ^= *state << 25;
	*state ^= *state >> 27;
	return (*state * 0x2545F4914F6CDD1DULL) >> 32;
}

/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 * -- Coming from OpenBSD
 */
size_t
bsd_strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}

/*
 * Appends src to string dst of size dsize (unlike strncat, dsize is the
 * full size of dst, not space left).  At most dsize-1 characters
 * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
 * Returns strlen(src) + MIN(dsize, strlen(initial dst)).
 * If retval >= dsize, truncation occurred.
 * -- Coming from OpenBSD
 */
size_t
bsd_strlcat(char *dst, const char *src, size_t dsize)
{
	const char *odst = dst;
	const char *osrc = src;
	size_t n = dsize;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end. */
	while (n-- != 0 && *dst != '\0')
		dst++;
	dlen = dst - odst;
	n = dsize - dlen;

	if (n-- == 0)
		return(dlen + strlen(src));
	while (*src != '\0') {
		if (n != 0) {
			*dst++ = *src;
			n--;
		}
		src++;
	}
	*dst = '\0';

	return(dlen + (src - osrc));	/* count does not include NUL */
}

char *
memcpy2str(char *dst, size_t dsize, const void *src, size_t ssize)
{
	uint8_t *cp = (uint8_t *) src;
	size_t i;

	for (i = 0; i < ssize && i < dsize - 1; i++)
		dst[i] = *cp++;
	dst[i] = '\0';
	return dst;
}

int
open_pipe(int pipe_arr[2])
{
	/* Open pipe */
	if (pipe2(pipe_arr, O_CLOEXEC | O_NONBLOCK) == -1)
		return -1;

	return 0;
}

/*
 *	Fast hash function for buffer data
 *	Based on FNV-1a hash algorithm - fast and good distribution
 */
uint32_t
fnv1a_hash(const uint8_t *buffer, size_t size)
{
	uint32_t hash = 2166136261U; /* FNV offset basis */
	const uint8_t *end = buffer + size;

	if (!buffer || !size)
		return 0;

	/* Process 4 bytes at a time for speed */
	while (buffer + 4 <= end) {
		hash ^= *(const uint32_t *) buffer;
		hash *= 16777619U; /* FNV prime */
		buffer += 4;
	}

	/* Process remaining bytes */
	while (buffer < end) {
		hash ^= *buffer++;
		hash *= 16777619U;
	}

	return hash;
}
