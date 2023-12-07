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
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

/* global includes */
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <linux/filter.h>
#include <linux/ip.h>

/* local includes */
#include "gtp_guard.h"


/* Set Reuse addr option */
int
if_setsockopt_reuseaddr(int sd, int onoff)
{
	int ret;

	if (sd < 0)
		return sd;

	/* reuseaddr option */
	ret = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &onoff, sizeof (onoff));
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): cant do SO_REUSEADDR (%m)"
				    , __FUNCTION__);
		close(sd);
		sd = -1;
	}

	return sd;
}

/* Set so_linger option */
int
if_setsockopt_nolinger(int sd, int onoff)
{
	int ret;
	struct linger opt;

	if (sd < 0)
		return sd;

	/* reuseaddr option */
	memset(&opt, 0, sizeof (struct linger));
	opt.l_onoff = onoff;
	opt.l_linger = 0;
	ret = setsockopt(sd, SOL_SOCKET, SO_LINGER, (struct linger *) &opt, sizeof (struct linger));
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): cant do SO_LINGER (%m)"
				    , __FUNCTION__);
		close(sd);
		sd = -1;
	}
	return sd;
}

/* Set TCP_CORK option */
int
if_setsockopt_tcpcork(int sd, int onoff)
{
        int ret;

        if (sd < 0)
                return sd;

        /* reuseaddr option */
        ret = setsockopt(sd, IPPROTO_TCP, TCP_CORK, &onoff, sizeof(onoff));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant set TCP_CORK (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }
        return sd;
}

/* Set TCP_NODELAY option */
int
if_setsockopt_nodelay(int sd, int onoff)
{
        int ret;

        if (sd < 0)
                return sd;

        /* reuseaddr option */
        ret = setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &onoff, sizeof(onoff));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant set TCP_NODELAY (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }
        return sd;
}

/* Set so_keepalive option */
int
if_setsockopt_keepalive(int sd, int onoff)
{
        int ret;

        if (sd < 0)
                return sd;

        /* reuseaddr option */
        ret = setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, &onoff, sizeof (onoff));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant do SO_KEEPALIVE (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }
        return sd;
}

/* Set TCP Keepalive IDLE Timer */
int
if_setsockopt_tcp_keepidle(int sd, int optval)
{
        int ret;

        if (sd < 0)
                return sd;

        /* reuseaddr option */
        ret = setsockopt(sd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof (optval));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant do TCP_KEEPIDLE (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }
        return sd;
}

/* Set maximum number of TCP keepalive probes */
int
if_setsockopt_tcp_keepcnt(int sd, int optval)
{
        int ret;

        if (sd < 0)
                return sd;

        /* reuseaddr option */
        ret = setsockopt(sd, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof (optval));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant do TCP_KEEPCNT (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }
        return sd;
}

/* Set keepalive interval between 2 TCP keepalive probes */
int
if_setsockopt_tcp_keepintvl(int sd, int optval)
{
        int ret;

        if (sd < 0)
                return sd;

        /* reuseaddr option */
        ret = setsockopt(sd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof (optval));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant do TCP_KEEPINTVL (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }
        return sd;
}

/* Set SO_RCVTIMEO option */
int
if_setsockopt_rcvtimeo(int sd, int timeout)
{
        struct timeval tv;
        int ret;

        if (sd < 0)
                return sd;

        /* Set timeval */
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        /* reuseaddr option */
        ret = setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant do SO_RCVTIMEO (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }

        return sd;
}

/* Set SO_SNDTIMEO option */
int
if_setsockopt_sndtimeo(int sd, int timeout)
{
        struct timeval tv;
        int ret;

        if (sd < 0)
                return sd;

        /* Set timeval */
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        /* reuseaddr option */
        ret = setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (ret < 0) {
                log_message(LOG_INFO, "%s(): cant do SO_RCVTIMEO (%m)"
				    , __FUNCTION__);
                close(sd);
                sd = -1;
        }

        return sd;
}

/* Set SO_REUSEPORT option */
int
if_setsockopt_reuseport(int sd, int onoff)
{
	int ret;

	if (sd < 0)
		return sd;

	/* reuseport option */
	ret = setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &onoff, sizeof(onoff));
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): cant set SO_REUSEPORT (%m)"
				    , __FUNCTION__);
                close(sd);
		return -1;
	}

	return sd;
}

/* Include IP Header */
int
if_setsockopt_hdrincl(int sd)
{
        int ret, on = 1;

	if (sd < 0)
		return sd;

	/* Include IP header into RAW protocol packet */
	ret = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): cant set IP_HDRINCL (%m)"
				    , __FUNCTION__);
		close(sd);
		return -1;
	}


        return sd;
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
if_bpf_filter_socket(int sd, const unsigned long ip_src)
{
        int ret;
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

        ret = setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
        if (ret < 0)
		log_message(LOG_INFO, "%s(): failed to attach filter. (%m)"
				    , __FUNCTION__);
	return ret;
}

int
if_setsockopt_no_receive(int *sd)
{
	int ret;
	struct sock_filter bpfcode[1] = {
		{0x06, 0, 0, 0},        /* ret #0 - means that all packets will be filtered out */
	};
	struct sock_fprog bpf = {1, bpfcode};

	if (*sd < 0)
		return -1;

	ret = setsockopt(*sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0) {
		log_message(LOG_INFO, "Can't set SO_ATTACH_FILTER option. errno=%d (%m)", errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_rcvbuf(int *sd, int val)
{
        int ret;

        if (*sd < 0)
                return -1;

        /* rcvbuf option */
        ret = setsockopt(*sd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
        if (ret < 0) {
                log_message(LOG_INFO, "cant set SO_RCVBUF IP option. errno=%d (%m)", errno);
                close(*sd);
                *sd = -1;
        }

        return *sd;
}

int
if_setsockopt_bindtodevice(int *sd, const char *ifname)
{
	int ret;

	if (*sd < 0)
		return -1;

	/* -> inbound processing option
	 * Specify the bound_dev_if.
	 * why IP_ADD_MEMBERSHIP & IP_MULTICAST_IF doesnt set
	 * sk->bound_dev_if themself ??? !!!
	 * Needed for filter multicasted advert per interface.
	 *
	 * -- If you read this !!! and know the answer to the question
	 *    please feel free to answer me ! :)
	 */
        ret = setsockopt(*sd, SOL_SOCKET, SO_BINDTODEVICE, ifname, (socklen_t)strlen(ifname) + 1);
        if (ret < 0) {
		log_message(LOG_INFO, "can't bind to device %s. errno=%d. (try to run it as root)"
				    , ifname, errno);
		close(*sd);
		*sd = -1;
	}

	return *sd;
}

int
if_setsockopt_priority(int *sd, int family)
{
        int ret, val;

        if (*sd < 0)
                return -1;

        /* Set PRIORITY traffic */
        if (family == AF_INET) {
                val = IPTOS_PREC_INTERNETCONTROL;
                ret = setsockopt(*sd, IPPROTO_IP, IP_TOS, &val, sizeof(val));
        } else {
                /* set tos to internet network control */
                val = 0xc0;     /* 192, which translates to DCSP value 48, or cs6 */
                ret = setsockopt(*sd, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val));
        }

        if (ret < 0) {
                log_message(LOG_INFO, "can't set %s option. errno=%d (%m)", (family == AF_INET) ? "IP_TOS" : "IPV6_TCLASS",  errno);
                close(*sd);
                *sd = -1;
        }

        return *sd;
}
