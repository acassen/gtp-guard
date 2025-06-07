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
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/if_packet.h>

#include "logger.h"
#include "inet_utils.h"
#include "utils.h"

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
	if (addr->ss_family == AF_INET6)
		return ((struct sockaddr_in6 *) addr)->sin6_port;

	return ((struct sockaddr_in *) addr)->sin_port;
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
inet_fd2str(int fd, char *dst, size_t dsize)
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


/*
 *	Setsockopt
 */

 /* Set Reuse addr option */
int
inet_setsockopt_reuseaddr(int fd, int onoff)
{
	int err;

	/* reuseaddr option */
	err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &onoff, sizeof (onoff));
	if (err)
		log_message(LOG_INFO, "%s(): cant do SO_REUSEADDR (%m)"
				    , __FUNCTION__);
	return fd;
}

/* Set so_linger option */
int
inet_setsockopt_nolinger(int fd, int onoff)
{
	struct linger opt;
	int err;

	/* reuseaddr option */
	memset(&opt, 0, sizeof (struct linger));
	opt.l_onoff = onoff;
	opt.l_linger = 0;
	err = setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &opt, sizeof (struct linger));
	if (err)
		log_message(LOG_INFO, "%s(): cant do SO_LINGER (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set TCP_CORK option */
int
inet_setsockopt_tcpcork(int fd, int onoff)
{
	int err;

	/* reuseaddr option */
	err = setsockopt(fd, IPPROTO_TCP, TCP_CORK, &onoff, sizeof(onoff));
	if (err)
		log_message(LOG_INFO, "%s(): cant set TCP_CORK (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set TCP_NODELAY option */
int
inet_setsockopt_nodelay(int fd, int onoff)
{
	int err;

	/* reuseaddr option */
	err = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &onoff, sizeof(onoff));
	if (err)
		log_message(LOG_INFO, "%s(): cant set TCP_NODELAY (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set so_keepalive option */
int
inet_setsockopt_keepalive(int fd, int onoff)
{
	int err;

	/* reuseaddr option */
	err = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &onoff, sizeof (onoff));
	if (err)
		log_message(LOG_INFO, "%s(): cant do SO_KEEPALIVE (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set TCP Keepalive IDLE Timer */
int
inet_setsockopt_tcp_keepidle(int fd, int optval)
{
	int err;

	/* reuseaddr option */
	err = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof (optval));
	if (err)
		log_message(LOG_INFO, "%s(): cant do TCP_KEEPIDLE (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set maximum number of TCP keepalive probes */
int
inet_setsockopt_tcp_keepcnt(int fd, int optval)
{
	int err;

	/* reuseaddr option */
	err = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof (optval));
	if (err)
		log_message(LOG_INFO, "%s(): cant do TCP_KEEPCNT (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set keepalive interval between 2 TCP keepalive probes */
int
inet_setsockopt_tcp_keepintvl(int fd, int optval)
{
	int err;

	/* reuseaddr option */
	err = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof (optval));
	if (err)
		log_message(LOG_INFO, "%s(): cant do TCP_KEEPINTVL (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set SO_RCVTIMEO option */
int
inet_setsockopt_rcvtimeo(int fd, int timeout)
{
	struct timeval tv;
	int err;

	/* Set timeval */
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	/* reuseaddr option */
	err = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (err)
		log_message(LOG_INFO, "%s(): cant do SO_RCVTIMEO (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set SO_SNDTIMEO option */
int
inet_setsockopt_sndtimeo(int fd, int timeout)
{
	struct timeval tv;
	int err;

	/* Set timeval */
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	/* reuseaddr option */
	err = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (err)
		log_message(LOG_INFO, "%s(): cant do SO_RCVTIMEO (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set SO_REUSEPORT option */
int
inet_setsockopt_reuseport(int fd, int onoff)
{
	int err;

	/* reuseport option */
	err = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &onoff, sizeof(onoff));
	if (err)
		log_message(LOG_INFO, "%s(): cant set SO_REUSEPORT (%m)"
				    , __FUNCTION__);
	return err;
}

/* Include IP Header */
int
inet_setsockopt_hdrincl(int fd)
{
	int err, on = 1;

	/* Include IP header into RAW protocol packet */
	err = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if (err)
		log_message(LOG_INFO, "%s(): cant set IP_HDRINCL (%m)"
				    , __FUNCTION__);
	return err;
}

/* Enable Broadcast */
int
inet_setsockopt_broadcast(int fd)
{
	int err, on = 1;

	/* Enable broadcast sending */
	err = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	if (err)
		log_message(LOG_INFO, "%s(): cant set SO_BROADCAST (%m)"
				    , __FUNCTION__);
	return err;
}

/* Set Promiscuous mode */
int
inet_setsockopt_promisc(int fd, int ifindex, bool enable)
{
	struct packet_mreq mreq = {};
	int err;

	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;

	/* Enable promiscuous mode */
	err = setsockopt(fd, SOL_PACKET
			   , enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP
			   , &mreq, sizeof(mreq));
	if (err)
		log_message(LOG_INFO, "%s(): cant %s PROMISC mode (%m)"
				    , __FUNCTION__
				    , enable ? "set" : "unset");
	return err;
}

/* Attach BPF program fd */
int
inet_setsockopt_attach_bpf(int fd, int prog_fd)
{
	int err;

	err = setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
	if (err)
		log_message(LOG_INFO, "%s(): Error attaching eBPF program to socket (%m)\n"
				    , __FUNCTION__);
	return err;
}

/*
 *	BPF L3 filtering code. Only work on SOCK_RAW !!!
 *
 * ASM code :
 *	(000) ldh      [12]
 *	(001) jeq      #0x800           jt 2	jf 5
 *	(002) ld       [26]
 *	(003) jeq      #0x8badf00d      jt 4	jf 5
 *	(004) ret      #0xffffffff
 *	(005) ret      #0
 */
int
inet_bpf_filter_socket(int fd, const unsigned long ip_src)
{
	int err;
	struct sock_filter bpfcode[6] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 3, 0x00000800 },
		{ 0x20, 0, 0, 0x0000001a },
		{ 0x15, 0, 1, 0x8badf00d },
		{ 0x6,  0, 0, (uint)-1   },
		{ 0x6,  0, 0, 0x00000000 }
	};
	struct sock_fprog bpf = {1, bpfcode};

	/* Set ip_src into BPF filter */
	bpfcode[3].k = ip_src;

	err = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (err)
		log_message(LOG_INFO, "%s(): failed to attach filter. (%m)"
				    , __FUNCTION__);
	return err;
}

int
inet_setsockopt_no_receive(int fd)
{
	int err;
	struct sock_filter bpfcode[1] = {
		{0x06, 0, 0, 0},        /* ret #0 - means that all packets will be filtered out */
	};
	struct sock_fprog bpf = {1, bpfcode};

	err = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (err)
		log_message(LOG_INFO, "Can't set SO_ATTACH_FILTER option. errno=%d (%m)", errno);

	return err;
}

int
inet_setsockopt_rcvbuf(int fd, int val)
{
	int err;

	/* rcvbuf option */
	err = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
	if (err)
		log_message(LOG_INFO, "cant set SO_RCVBUF IP option. errno=%d (%m)", errno);

	return err;
}

int
inet_setsockopt_bindtodevice(int fd, const char *ifname)
{
	int err;

	/* -> inbound processing option
	 * Specify the bound_dev_if.
	 * why IP_ADD_MEMBERSHIP & IP_MULTICAST_IF doesnt set
	 * sk->bound_dev_if themself ??? !!!
	 * Needed for filter multicasted advert per interface.
	 *
	 * -- If you read this !!! and know the answer to the question
	 *    please feel free to answer me ! :)
	 */
	err = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, (socklen_t)strlen(ifname) + 1);
	if (err)
		log_message(LOG_INFO, "can't bind to device %s. errno=%d. (try to run it as root)"
				    , ifname, errno);

	return err;
}

int
inet_setsockopt_priority(int fd, int family)
{
	int err, val;

	/* Set PRIORITY traffic */
	if (family == AF_INET) {
		val = IPTOS_PREC_INTERNETCONTROL;
		err = setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof(val));
	} else {
		/* set tos to internet network control */
		val = 0xc0;     /* 192, which translates to DCSP value 48, or cs6 */
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val));
	}

	if (err)
		log_message(LOG_INFO, "can't set %s option. errno=%d (%m)"
				    , (family == AF_INET) ? "IP_TOS" : "IPV6_TCLASS"
				    ,  errno);

	return err;
}
