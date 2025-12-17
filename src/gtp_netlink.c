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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_tunnel.h>
#include <linux/veth.h>

#include "gtp_data.h"
#include "gtp_netlink.h"
#include "gtp_interface.h"
#include "utils.h"
#include "memory.h"
#include "logger.h"
#include "bitops.h"


/* Fwd declaration  */
static int netlink_if_link_del(struct nlmsghdr *h);

/* Local data */
static struct nl_handle nl_kernel = { .fd = -1 };	/* Kernel reflection channel */
static struct nl_handle nl_cmd = { .fd = -1 };		/* Kernel command channel */

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;

static const char *
get_nl_msg_type(unsigned type)
{
	switch (type) {
		switch_define_str(RTM_NEWLINK);
		switch_define_str(RTM_DELLINK);
		switch_define_str(RTM_NEWADDR);
		switch_define_str(RTM_DELADDR);
		switch_define_str(RTM_NEWROUTE);
		switch_define_str(RTM_DELROUTE);
		switch_define_str(RTM_NEWRULE);
		switch_define_str(RTM_DELRULE);
		switch_define_str(RTM_GETLINK);
		switch_define_str(RTM_GETADDR);
	};

	return "";
}

/* iproute2 utility function */
static int
addattr_l(struct nlmsghdr *n, size_t maxlen, unsigned short type, const void *data, size_t alen)
{
	unsigned short len = RTA_LENGTH(alen);
	uint32_t align_len = RTA_SPACE(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + align_len > maxlen)
		return -1;

	rta = (struct rtattr *) NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + align_len;

	return 0;
}

static int
get_rtnl_link_stats_rta(struct rtnl_link_stats64 *stats64, struct rtattr *tb[])
{
	struct rtattr *rta = tb[IFLA_STATS64];

	if (!rta)
		return -1;

	memcpy(stats64, RTA_DATA(rta), RTA_PAYLOAD(rta));
	return 0;
}

static void
parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, size_t len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		/* Note: clang issues a -Wcast-align warning for RTA_NEXT, whereas gcc does not.
		 * gcc is more clever in it's analysis, and realises that RTA_NEXT is actually
		 * forcing alignment.
		 */
		rta = RTA_NEXT(rta, len);
	}
}

/* Parse Netlink message */
static int
netlink_parse_info(int (*filter) (struct sockaddr_nl *, struct nlmsghdr *, void *arg),
		   struct nl_handle *nl, struct nlmsghdr *n, void *filter_arg, bool read_all)
{
	ssize_t len;
	int ret = 0;
	int error;
	char *nlmsg_buf __attribute__((aligned(__alignof__(struct nlmsghdr)))) = NULL;
	int nlmsg_buf_size = 0;

	while (true) {
		struct iovec iov = {
			.iov_len = 0
		};
		struct sockaddr_nl snl;
		struct msghdr msg = {
			.msg_name = &snl,
			.msg_namelen = sizeof(snl),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0
		};
		struct nlmsghdr *h;

		/* Find out how big our receive buffer needs to be */
		do {
			len = recvmsg(nl->fd, &msg, MSG_PEEK | MSG_TRUNC);
		} while (len < 0 && errno == EINTR);

		if (len < 0) {
			ret = -1;
			break;
		}

		if (len == 0)
			break;

		if (len > nlmsg_buf_size) {
			FREE_PTR(nlmsg_buf);
			nlmsg_buf = MALLOC(len);
			nlmsg_buf_size = len;
		}

		iov.iov_base = nlmsg_buf;
		iov.iov_len = nlmsg_buf_size;

		do {
			len = recvmsg(nl->fd, &msg, 0);
		} while (len < 0 && errno == EINTR);

		if (len < 0) {
			if (check_EAGAIN(errno))
				break;
			if (errno == ENOBUFS) {
				log_message(LOG_INFO, "Netlink: Receive buffer overrun on %s socket - (%m)"
						    , nl == &nl_kernel ? "monitor" : "cmd");
				log_message(LOG_INFO, "  - increase the relevant netlink_rcv_bufs global parameter and/or set force");
			} else
				log_message(LOG_INFO, "Netlink: recvmsg error on %s socket - %d (%m)"
						    , nl == &nl_kernel ? "monitor" : "cmd", errno);
			continue;
		}

		if (len == 0) {
			log_message(LOG_INFO, "Netlink: EOF");
			ret = -1;
			break;
		}

		if (msg.msg_namelen != sizeof snl) {
			log_message(LOG_INFO, "Netlink: Sender address length error: length %u"
					    , msg.msg_namelen);
			ret = -1;
			break;
		}

		/* See -Wcast-align comment above, also applies to NLMSG_NEXT */
		for (h = (struct nlmsghdr *) nlmsg_buf; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len)) {
			/* Finish off reading. */
			if (h->nlmsg_type == NLMSG_DONE) {
				FREE(nlmsg_buf);
				return ret;
			}

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(h);

				/*
				 * If error == 0 then this is a netlink ACK.
				 * return if not related to multipart message.
				 */
				if (err->error == 0) {
					if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all) {
						FREE(nlmsg_buf);
						return 0;
					}
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
					log_message(LOG_INFO, "Netlink: error: message truncated");
					FREE(nlmsg_buf);
					return -1;
				}

				log_message(LOG_INFO, "Netlink: error: %s(%d), type=%s(%u), seq=%u, pid=%u"
						    , strerror(-err->error), -err->error
						    , get_nl_msg_type(err->msg.nlmsg_type)
						    , err->msg.nlmsg_type, err->msg.nlmsg_seq
						    , err->msg.nlmsg_pid);
				FREE(nlmsg_buf);
				return -1;
			}

			error = (*filter) (&snl, h, filter_arg);
			if (error < 0) {
				log_message(LOG_INFO, "Netlink: filter function error");
				ret = error;
			}

			if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all) {
				FREE(nlmsg_buf);
				return ret;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			log_message(LOG_INFO, "Netlink: error: message truncated");
			continue;
		}

		if (len) {
			log_message(LOG_INFO, "Netlink: error: data remnant size %zd", len);
			ret = -1;
			break;
		}
	}

	if (nlmsg_buf)
		FREE(nlmsg_buf);

	return ret;
}


/* Open Netlink channel with kernel */
static int
netlink_open(struct nl_handle *nl, unsigned group, ...)
{
	socklen_t addr_len;
	struct sockaddr_nl snl;
	unsigned rcvbuf_sz = NL_DEFAULT_BUFSIZE;
	va_list gp;
	int err = 0;

	memset(nl, 0, sizeof (*nl));

	nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
			NETLINK_ROUTE);
	if (nl->fd < 0) {
		log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%m)");
		return -1;
	}

	memset(&snl, 0, sizeof (snl));
	snl.nl_family = AF_NETLINK;

	err = bind(nl->fd, (struct sockaddr *) &snl, sizeof (snl));
	if (err) {
		log_message(LOG_INFO, "Netlink: Cannot bind netlink socket : (%m)");
		close(nl->fd);
		nl->fd = -1;
		return -1;
	}

	/* Join the requested groups */
	va_start(gp, group);
	while (group) {
		err = setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
				 &group, sizeof(group));
		if (err)
			log_message(LOG_INFO, "Netlink: Cannot add group %u membership "
				    "on netlink socket : (%m)", group);

		group = va_arg(gp, unsigned);
	}
	va_end(gp);

	addr_len = sizeof (snl);
	err = getsockname(nl->fd, (struct sockaddr *) &snl, &addr_len);
	if (err || addr_len != sizeof (snl)) {
		log_message(LOG_INFO, "Netlink: Cannot getsockname : (%m)");
		close(nl->fd);
		nl->fd = -1;
		return -1;
	}

	if (snl.nl_family != AF_NETLINK) {
		log_message(LOG_INFO, "Netlink: Wrong address family %d", snl.nl_family);
		close(nl->fd);
		nl->fd = -1;
		return -1;
	}

	/* Save the port id for checking message source later */
	nl->nl_pid = snl.nl_pid;
	nl->seq = (uint32_t)time(NULL);

	err = setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_sz, sizeof(rcvbuf_sz));
	if (err)
		log_message(LOG_INFO, "Cannot set SO_RCVBUF IP option. errno=%d (%m)", errno);

	return err;
}

/* Close Netlink channel with kernel */
static void
netlink_close(struct nl_handle *nl)
{
	if (nl->thread) {
		thread_del(nl->thread);
		nl->thread = NULL;
	}

	if (nl->fd != -1)
		close(nl->fd);

	nl->fd = -1;
}


/*
 *	Netlink veth creation
 */

static void *
nl_attr_put(struct nlmsghdr *nlh, int type, const void *data, int len)
{
	struct nlattr *nla;

	nla = (struct nlattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
	nla->nla_type = type;
	nla->nla_len  = NLA_HDRLEN + len;
	if (data)
		memcpy((char *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(nla->nla_len);
	return nla;
}

static inline struct nlattr *
nl_attr_nest_start(struct nlmsghdr *nlh, int type)
{
	return nl_attr_put(nlh, type, NULL, 0);
}

static inline void
nl_attr_nest_end(struct nlmsghdr *nlh, struct nlattr *start)
{
	start->nla_len = (char *)nlh + nlh->nlmsg_len - (char *)start;
}

static int
nl_send_and_recv_ack(struct nl_handle *nl, struct nlmsghdr *nlh)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct iovec iov = { nlh, nlh->nlmsg_len };
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[1024];

	if (sendmsg(nl->fd, &msg, 0) < 0) {
		log_message(LOG_INFO, "Netlink: sendmsg() failed: %m");
		return -1;
	}

	/* read reply */
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	int len = recvmsg(nl->fd, &msg, 0);
	if (len < 0) {
		log_message(LOG_INFO, "Netlink: recvmsg() failed: %m");
		return -1;
	}

	struct nlmsghdr *h;
	for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = NLMSG_DATA(h);
			if (err->error == 0)
				return 0;
			errno = -err->error;
			log_message(LOG_INFO, "Netlink: ack error: %m");
			return -1;
		}
	}

	return 0;
}

static int
nl_bring_up(struct nl_handle *nl, const char *name)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	char buf[1024] = {};

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++nl->seq;

	ifm = NLMSG_DATA(nlh);
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_change = IFF_UP;
	ifm->ifi_flags  = IFF_UP;

	nl_attr_put(nlh, IFLA_IFNAME, name, strlen(name) + 1);

	if (nl_send_and_recv_ack(nl, nlh) < 0)
		return -1;
	return 0;
}


int
gtp_netlink_link_create_veth(const char *name, const char *peer_name)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm, *peer_ifm;
	struct nlattr *linkinfo, *peer, *info_data;
	char buf[1024] = {};

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	nlh->nlmsg_seq = ++nl_cmd.seq;

	ifm = NLMSG_DATA(nlh);
	ifm->ifi_family = AF_UNSPEC;

	nl_attr_put(nlh, IFLA_IFNAME, name, strlen(name) + 1);

	linkinfo = nl_attr_nest_start(nlh, IFLA_LINKINFO);
	nl_attr_put(nlh, IFLA_INFO_KIND, "veth", strlen("veth") + 1);
	info_data = nl_attr_nest_start(nlh, IFLA_INFO_DATA);

	/* Add peer ifinfomsg */
	peer = nl_attr_nest_start(nlh, VETH_INFO_PEER);
	peer_ifm = (struct ifinfomsg *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
	memset(peer_ifm, 0, sizeof(*peer_ifm));
	peer_ifm->ifi_family = AF_UNSPEC;
	nlh->nlmsg_len += NLMSG_ALIGN(sizeof(*peer_ifm));
	nl_attr_put(nlh, IFLA_IFNAME, peer_name, strlen(peer_name) + 1);
	nl_attr_nest_end(nlh, peer);

	nl_attr_nest_end(nlh, info_data);
	nl_attr_nest_end(nlh, linkinfo);

	/* send request (create veth) */
	if (nl_send_and_recv_ack(&nl_cmd, nlh) < 0)
		return -1;

	nl_bring_up(&nl_cmd, name);
	nl_bring_up(&nl_cmd, peer_name);

	return 0;
}


int
gtp_netlink_link_delete(int ifindex)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	char buf[128] = {};

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlh->nlmsg_type = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++nl_cmd.seq;

	ifm = NLMSG_DATA(nlh);
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = ifindex;

	/* send request */
	if (nl_send_and_recv_ack(&nl_cmd, nlh) < 0)
		return -1;

	return 0;
}


/*
 *	Netlink neighbour lookup
 */
static int
netlink_neigh_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h,
		     __attribute__((unused)) void *arg)
{
	struct ndmsg *r = NLMSG_DATA(h);
	struct rtattr *tb[NDA_MAX + 1];
	union addr addr;
	int len = h->nlmsg_len;

	if (h->nlmsg_type != RTM_NEWNEIGH && h->nlmsg_type != RTM_GETNEIGH)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0)
		return -1;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(r), len, 0);

	/* Only netlink broadcast related to IP Address matter */
	if (!tb[NDA_DST] || !tb[NDA_LLADDR] || RTA_PAYLOAD(tb[NDA_LLADDR]) != ETH_ALEN)
		return 0;

	addr_zero(&addr);
	switch (r->ndm_family) {
	case AF_INET:
		addr.sin.sin_addr.s_addr = *(uint32_t *) RTA_DATA(tb[NDA_DST]);
		break;
	case AF_INET6:
		memcpy(&addr.sin6.sin6_addr, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));
		break;
	default:
		return 0;
	}
	addr.family = r->ndm_family;

	gtp_interface_update_direct_tx_lladdr(&addr, RTA_DATA(tb[NDA_LLADDR]));
	return 0;
}


/*
 *	Kernel Netlink reflector
 */
static int
netlink_filter(struct sockaddr_nl *snl, struct nlmsghdr *h, __attribute__((unused)) void *arg)
{
	switch (h->nlmsg_type) {
	case RTM_NEWNEIGH:
		netlink_neigh_filter(snl, h, NULL);
		break;
	case RTM_DELLINK:
		netlink_if_link_del(h);
		break;
	}
	return 0;
}

static void
kernel_netlink(struct thread *thread)
{
	struct nl_handle *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_filter, nl, NULL, NULL, true);

	nl->thread = thread_add_read(master, kernel_netlink, nl, nl->fd, TIMER_NEVER, 0);
}


/*
 *	Netlink Interface lookup
 */

static int
netlink_if_link_del(struct nlmsghdr *h)
{
	struct ifinfomsg *ifi = NLMSG_DATA(h);
	struct gtp_interface *iface;
	int len = h->nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	iface = gtp_interface_get_by_ifindex(ifi->ifi_index, false);
	if (!iface)
		return 0;

	gtp_interface_destroy(iface);

	return 0;
}

static int
netlink_if_get_ll_addr(struct gtp_interface *iface, struct rtattr *tb[])
{
	struct ether_addr zero_eth = {};
	struct ether_addr *eth = RTA_DATA(tb[IFLA_ADDRESS]);

	/* Is address set ? */
	if (!tb[IFLA_ADDRESS] || RTA_PAYLOAD(tb[IFLA_ADDRESS]) != ETH_ALEN)
		return 0;

	/* Don't allow a hardware address of all zeroes */
	if (!memcmp(eth, &zero_eth, ETH_ALEN))
		return 0;

	memcpy(iface->hw_addr, eth, ETH_ALEN);
	iface->hw_addr_len = ETH_ALEN;

	return 0;
}

static int
netlink_if_request(struct nl_handle *nl, unsigned char family, uint16_t type, int ifindex, bool stats)
{
	ssize_t status;
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg i;
		char buf[1024];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.i),
		.nlh.nlmsg_flags = (ifindex == 0 ? NLM_F_DUMP : 0) | NLM_F_REQUEST,
		.nlh.nlmsg_type = type,
		.nlh.nlmsg_pid = 0,
		.nlh.nlmsg_seq = ++nl->seq,
		.i.ifi_family = family,
		.i.ifi_index = ifindex,
	};
	__u32 filt_mask = 0;

	if (!stats)
		filt_mask |= RTEXT_FILTER_SKIP_STATS;

	addattr_l(&req.nlh, sizeof(req), IFLA_EXT_MASK, &filt_mask, sizeof(uint32_t));

	status = sendto(nl->fd, (void *) &req, sizeof (req), 0
			      , (struct sockaddr *) &snl, sizeof(snl));
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}

	return 0;
}

/*
 * fill gtp_interface data from kernel for vlan or gre devices
 */
static int
netlink_if_link_info(struct rtattr *tb, struct gtp_interface *iface)
{
	struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
	struct rtattr *linkdata;
	const char *kind;

	if (!tb)
		return -1;

	parse_rtattr(linkinfo, IFLA_INFO_MAX
			     , RTA_DATA(tb), RTA_PAYLOAD(tb)
			     , NLA_F_NESTED);

	if (!linkinfo[IFLA_INFO_KIND] || !linkinfo[IFLA_INFO_DATA])
		return -1;

	kind = (const char *)RTA_DATA(linkinfo[IFLA_INFO_KIND]);
	linkdata = linkinfo[IFLA_INFO_DATA];

	if (!strcmp(kind, "vlan")) {
		struct rtattr *attr[IFLA_VLAN_MAX + 1];

		parse_rtattr(attr, IFLA_VLAN_MAX, RTA_DATA(linkdata),
			     RTA_PAYLOAD(linkdata), NLA_F_NESTED);

		if (!attr[IFLA_VLAN_ID])
			return -1;

		iface->vlan_id = *(__u16 *)RTA_DATA(attr[IFLA_VLAN_ID]);

	} else if (!strcmp(kind, "gre")) {
		struct rtattr *attr[IFLA_GRE_MAX + 1];

		parse_rtattr(attr, IFLA_GRE_MAX, RTA_DATA(linkdata),
			     RTA_PAYLOAD(linkdata), NLA_F_NESTED);

		if (!attr[IFLA_GRE_REMOTE] ||
		    RTA_PAYLOAD(attr[IFLA_GRE_REMOTE]) != 4 ||
		    !attr[IFLA_GRE_REMOTE] ||
		    RTA_PAYLOAD(attr[IFLA_GRE_REMOTE]) != 4)
			return -1;

		iface->tunnel_mode = GTP_INTERFACE_TUN_GRE;

		addr_fromip4(&iface->tunnel_local,
			     *(uint32_t *)RTA_DATA(attr[IFLA_GRE_LOCAL]));
		addr_fromip4(&iface->tunnel_remote,
			     *(uint32_t *)RTA_DATA(attr[IFLA_GRE_REMOTE]));

	} else if (!strcmp(kind, "ipip")) {
		struct rtattr *attr[IFLA_IPTUN_MAX + 1];

		parse_rtattr(attr, IFLA_IPTUN_MAX, RTA_DATA(linkdata),
			     RTA_PAYLOAD(linkdata), NLA_F_NESTED);

		if (!attr[IFLA_IPTUN_LOCAL] ||
		    RTA_PAYLOAD(attr[IFLA_IPTUN_LOCAL]) != 4 ||
		    !attr[IFLA_IPTUN_REMOTE] ||
		    RTA_PAYLOAD(attr[IFLA_IPTUN_REMOTE]) != 4)
			return -1;

		iface->tunnel_mode = GTP_INTERFACE_TUN_IPIP;

		addr_fromip4(&iface->tunnel_local,
			     *(uint32_t *)RTA_DATA(attr[IFLA_IPTUN_LOCAL]));
		addr_fromip4(&iface->tunnel_remote,
			     *(uint32_t *)RTA_DATA(attr[IFLA_IPTUN_REMOTE]));

	} else {
		/* not handled */
		return 0;
	}

	return 1;
}

static int
netlink_if_link_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(h);
	struct rtattr *tb[IFLA_MAX + 1];
	bool create = arg == (void*)1;
	struct gtp_interface *iface, *li;
	int link_ifindex;
	int len = h->nlmsg_len;
	int ret = 0;

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len, 0);

	iface = gtp_interface_get_by_ifindex(ifi->ifi_index, false);
	if (!iface) {
		/* do not create interface when updating stats */
		if (!create)
			return 0;

		/* reflect interface topology */
		iface = gtp_interface_alloc((char *)RTA_DATA(tb[IFLA_IFNAME]),
					    ifi->ifi_index);
		if (!iface)
			return -1;

		/* get mac address (if it's a device) */
		ret = netlink_if_get_ll_addr(iface, tb);
		if (ret) {
			log_message(LOG_INFO, "%s(): Error getting ll_addr for interface:'%s'"
					    , __FUNCTION__
					    , iface->ifname);
			gtp_interface_destroy(iface);
			return ret;
		}

		ret = netlink_if_link_info(tb[IFLA_LINKINFO], iface);
		if (ret == 1) {
			/* IFLA_LINK point to physical interface (real device)
			 * in the same netns. Use it to link vlan devices to their
			 * physical devices */
			if (tb[IFLA_LINK] != NULL &&
			    tb[IFLA_LINK_NETNSID] == NULL &&
			    RTA_PAYLOAD(tb[IFLA_LINK]) == sizeof (uint32_t)) {
				link_ifindex = *(uint32_t *)RTA_DATA(tb[IFLA_LINK]);
				li = gtp_interface_get_by_ifindex(link_ifindex, true);
				if (li != NULL)
					gtp_interface_link(li, iface);
			}
		}
	}

	if (__test_bit(GTP_INTERFACE_FL_METRICS_LINK_BIT, &iface->flags))
		get_rtnl_link_stats_rta(iface->link_metrics, tb);

	return 0;
}

static void
netlink_if_stats_update(__attribute__((unused)) struct thread *t)
{
	int err;

	if (nl_cmd.fd == -1) {
		err = netlink_open(&nl_cmd, 0, 0);
		if (err) {
			log_message(LOG_INFO, "Error while creating Kernel netlink command channel");
			goto end;
		}
	}

	err = netlink_if_request(&nl_cmd, AF_PACKET, RTM_GETLINK, 0, true);
	if (err) {
		netlink_close(&nl_cmd);
		goto end;
	}

	netlink_parse_info(netlink_if_link_filter, &nl_cmd, NULL, (void *)0, false);
 end:
	nl_cmd.thread = thread_add_timer(master, netlink_if_stats_update
					       , NULL, TIMER_HZ);
}

int
gtp_netlink_if_lookup(int ifindex)
{
	if (netlink_if_request(&nl_cmd, AF_PACKET, RTM_GETLINK, ifindex, true) < 0)
		return -1;
	netlink_parse_info(netlink_if_link_filter, &nl_cmd, NULL, (void *)1, false);
	return 0;
}


/*
 *	Kernel Netlink channel init
 */
int
gtp_netlink_init(void)
{
	int err;

	/* Netlink command interface init */
	err = netlink_open(&nl_cmd, 0, 0);
	if (err) {
		log_message(LOG_INFO, "Error while creating Kernel netlink "
			    "command channel");
		return -1;
	}
	nl_cmd.thread = thread_add_timer(master, netlink_if_stats_update,
					 NULL, TIMER_HZ);

	/* Register Kernel netlink reflector */
	err = netlink_open(&nl_kernel, RTNLGRP_NEIGH, RTNLGRP_LINK, 0);
	if (err) {
		log_message(LOG_INFO, "Error while registering Kernel netlink "
			    "reflector channel");
		return -1;
	}

	log_message(LOG_INFO, "Registering Kernel netlink reflector");
	nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel,
					   nl_kernel.fd, TIMER_NEVER, 0);
	return 0;
}

void
gtp_netlink_destroy(void)
{
	log_message(LOG_INFO, "Unregistering Kernel netlink reflector");
	netlink_close(&nl_kernel);

	/* stop if_stats_update, and allow netlink commands to be performed
	 * until destructor is called */
	thread_del(nl_cmd.thread);
	nl_cmd.thread = NULL;
}


static void __attribute__((destructor))
gtp_netlink_destructor(void)
{
	netlink_close(&nl_cmd);
}
