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

#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/un.h>
#include "utils.h"

/* global vars */
unsigned long debug = 0;

/* Display a buffer into a HEXA formated output */
void
dump_buffer(char *prefix, char *buff, int count)
{
        int i, j, c;
        int printnext = 1;

        if (count % 16)
                c = count + (16 - count % 16);
        else
                c = count;

        for (i = 0; i < c; i++) {
                if (printnext) {
                        printnext--;
                        printf("%s%.4x ", prefix, i & 0xffff);
                }
                if (i < count)
                        printf("%3.2x", buff[i] & 0xff);
                else
                        printf("   ");
                if (!((i + 1) % 8)) {
                        if ((i + 1) % 16)
                                printf(" -");
                        else {
                                printf("   ");
                                for (j = i - 15; j <= i; j++)
                                        if (j < count) {
                                                if ((buff[j] & 0xff) >= 0x20
                                                    && (buff[j] & 0xff) <= 0x7e)
                                                        printf("%c",
                                                               buff[j] & 0xff);
                                                else
                                                        printf(".");
                                        } else
                                                printf(" ");
                                printf("\n");
                                printnext = 1;
                        }
                }
        }
}

/* Compute a checksum */
uint16_t
in_csum(uint16_t *addr, int len, uint16_t csum)
{
	register int nleft = len;
	const uint16_t *w = addr;
	register uint16_t answer;
	register uint32_t sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *) w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/* Compute udp checksum */
uint16_t
udp_csum(const void *buffer, size_t len, uint32_t src_addr, uint32_t dest_addr)
{
	const uint16_t *buf = buffer;
	uint16_t *ip_src = (void*)&src_addr, *ip_dst = (void*)&dest_addr;
	uint32_t sum;
	size_t length = len;

	/* Calculate the sum */
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len & 1)
		/* Add the padding if the packet lenght is odd */
		sum += *((uint8_t*)buf);

	/* Add the pseudo-header */
	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(IPPROTO_UDP);
	sum += htons(length);

	/* Add the carries */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	/* Return the one's complement of sum */
	return (uint16_t)~sum;
}

/* IP network to ascii representation */
char *
inet_ntop2(uint32_t ip)
{
	static char buf[16];
	unsigned char *bytep;

	bytep = (unsigned char *) &(ip);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

/*
 * IP network to ascii representation. To use
 * for multiple IP address convertion into the same call.
 */
char *
inet_ntoa2(uint32_t ip, char *buf)
{
	unsigned char *bytep;

	bytep = (unsigned char *) &(ip);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

/* IP string to network mask representation. CIDR notation. */
uint8_t
inet_stom(char *addr)
{
	uint8_t mask = 32;
	char *cp = addr;

	if (!strstr(addr, "/"))
		return mask;
	while (*cp != '/' && *cp != '\0')
		cp++;
	if (*cp == '/')
		return atoi(++cp);
	return mask;
}

/* IP string to network range representation. */
uint8_t
inet_stor(char *addr)
{
	char *cp = addr;

	if (!strstr(addr, "-"))
		return 0;
	while (*cp != '-' && *cp != '\0')
		cp++;
	if (*cp == '-')
		return strtoul(++cp, NULL, (strchr(addr, ':')) ? 16 : 10);
	return 0;
}

/* IP string to sockaddr_storage */
int
inet_stosockaddr(const char *ip, const uint16_t port, struct sockaddr_storage *addr)
{
	void *addr_ip;

	addr->ss_family = (strchr(ip, ':')) ? AF_INET6 : AF_INET;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		if (port)
			addr6->sin6_port = htons(port);
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		if (port)
			addr4->sin_port = htons(port);
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_pton(addr->ss_family, ip, addr_ip))
		return -1;

	return 0;
}

/* IPv4 to sockaddr_storage */
int
inet_ip4tosockaddr(uint32_t addr_ip, struct sockaddr_storage *addr)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
	addr4->sin_family = AF_INET;
	addr4->sin_addr.s_addr = addr_ip;
	return 0;
}

/* IP network to string representation */
char *
inet_sockaddrtos2(struct sockaddr_storage *addr, char *addr_str)
{
	void *addr_ip;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_ntop(addr->ss_family, addr_ip, addr_str, INET6_ADDRSTRLEN))
		return NULL;

	return addr_str;
}

char *
inet_sockaddrtos(struct sockaddr_storage *addr)
{
	static char addr_str[INET6_ADDRSTRLEN];
	inet_sockaddrtos2(addr, addr_str);
	return addr_str;
}

uint16_t
inet_sockaddrport(struct sockaddr_storage *addr)
{
	uint16_t port;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		port = addr6->sin6_port;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		port = addr4->sin_port;
	}
	
	return port;
}

uint32_t
inet_sockaddrip4(struct sockaddr_storage *addr)
{
	if (addr->ss_family != AF_INET)
		return -1;
	
	return ((struct sockaddr_in *) addr)->sin_addr.s_addr;
}

int
inet_sockaddrip6(struct sockaddr_storage *addr, struct in6_addr *ip6)
{
	if (addr->ss_family != AF_INET6)
		return -1;
	
	*ip6 = ((struct sockaddr_in6 *) addr)->sin6_addr;
	return 0;
}

/* Get ifindex from IP Address */
int
inet_sockaddrifindex(struct sockaddr_storage *addr)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, ifindex;

	if (getifaddrs(&ifaddr) == -1)
		return -1;

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		family = ifa->ifa_addr->sa_family;
		if (family != addr->ss_family)
			continue;

		if (family == AF_INET6) {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
			struct sockaddr_in6 *ifa_addr6 = (struct sockaddr_in6 *) ifa->ifa_addr;

			if (__ip6_addr_equal(&addr6->sin6_addr, &ifa_addr6->sin6_addr))
				goto match;
			continue;
		}

		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		struct sockaddr_in *ifa_addr4 = (struct sockaddr_in *) ifa->ifa_addr;

		if (addr4->sin_addr.s_addr == ifa_addr4->sin_addr.s_addr)
			goto match;
	}

	freeifaddrs(ifaddr);
	return -1;

  match:
	ifindex = if_nametoindex(ifa->ifa_name);
	freeifaddrs(ifaddr);
	return ifindex;
}

/*
 * IP string to network representation
 * Highly inspired from Paul Vixie code.
 */
int
inet_ston(const char *addr, uint32_t * dst)
{
	static char digits[] = "0123456789";
	int saw_digit, octets, ch;
	u_char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;

	while ((ch = *addr++) != '\0' && ch != '/' && ch != '-') {
		const char *pch;
		if ((pch = strchr(digits, ch)) != NULL) {
			u_int new = *tp * 10 + (pch - digits);
			if (new > 255)
				return 0;
			*tp = new;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}

	if (octets < 4)
		return 0;

	memcpy(dst, tmp, INADDRSZ);
	return 1;
}

/*
 * Return broadcast address from network and netmask.
 */
uint32_t
inet_broadcast(uint32_t network, uint32_t netmask)
{
	return 0xffffffff - netmask + network;
}

/*
 * Convert CIDR netmask notation to long notation.
 */
uint32_t
inet_cidrtomask(uint8_t cidr)
{
	uint32_t mask = 0;
	int b;

	for (b = 0; b < cidr; b++)
		mask |= (1 << (31 - b));
	return ntohl(mask);
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
 *	Non-Block stuff
 */
int
__set_nonblock(int fd)
{
	int val = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, val | O_NONBLOCK);
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

/*
 *	Stringify fd infos
 */
static ssize_t
regular_file_fd2str(int fd, char *dst, size_t dsize)
{
	char path[PATH_MAX];
	ssize_t dlen = 0;
	int ret;

	ret = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	if (ret < 0)
		return -1;

	dlen = readlink(path, dst, dsize - 1);
	if (dlen < 0)
		return snprintf(dst, dsize, "error: %m");

	return dlen;
}

static ssize_t
socket_fd2str(struct sockaddr_storage *addr, char *dst, size_t dsize)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct sockaddr_un *un;

	if (dsize <= 0)
		return -1;

	if (addr->ss_family == AF_INET || addr->ss_family == AF_INET6)
		return snprintf(dst, dsize, "%s%s%s:%d"
				   , (addr->ss_family == AF_INET6) ? "[" : ""
				   , inet_sockaddrtos2(addr, addr_str)
				   , (addr->ss_family == AF_INET6) ? "]" : ""
				   , ntohs(inet_sockaddrport(addr)));

	if (addr->ss_family == AF_UNIX) {
		un = (struct sockaddr_un *) addr;
		return snprintf(dst, dsize, "unix[%s]"
				   , (*un->sun_path) ? un->sun_path : "'abstract'");
	}

	return snprintf(dst, dsize, "socket type not supported");
}

char *
fd2str(int fd, char *dst, size_t dsize)
{
	struct stat statbuf;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	ssize_t dlen = 0;

	if (fd < 0 || !dst || !dsize)
		goto err;

	/* what is fd ? socket, regular file name, etc... (could be used to get pipe, etc.) */
	if (fstat(fd, &statbuf) < 0)
		goto err;

	/* Buffer init */
	memset(dst, 0, dsize);

	/* fd is a regular file, get its pathname */
	if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode)) {
		dlen = regular_file_fd2str(fd, dst, dsize);
		if (dlen < 0)
			goto err;

		goto end;
	}

	/* fd is a socket */
	if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) < 0)
		goto unknown;

	dlen = socket_fd2str(&addr, dst, dsize);
	if (dlen < 0)
		goto end;

	/* fetch peer */
	if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) < 0)
		goto end;

	dlen = bsd_strlcat(dst + dlen, " -> remote_peer: ", dsize - dlen);
	socket_fd2str(&addr, dst + dlen, dsize - dlen);
	return dst;

  unknown:
	snprintf(dst, dsize, "Unknown");
	return dst;
  err:
	snprintf(dst, dsize, "invalid fd");
  end:
	return dst;
}
