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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include "gtp_data.h"
#include "gtp_netlink.h"
#include "gtp_interface.h"
#include "inet_utils.h"
#include "utils.h"
#include "memory.h"
#include "logger.h"
#include "bitops.h"


/* Fwd declaration  */
static int netlink_if_link_del(struct nlmsghdr *h);

/* Local data */
static struct nl_handle nl_kernel = { .fd = -1 };	/* Kernel reflection channel */
static struct nl_handle nl_cmd = { .fd = -1 };	/* Kernel command channel */

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
netlink_open(struct nl_handle *nl, unsigned rcvbuf_size, int flags, int protocol, unsigned group, ...)
{
	socklen_t addr_len;
	struct sockaddr_nl snl;
	unsigned rcvbuf_sz = rcvbuf_size ? : NL_DEFAULT_BUFSIZE;
	va_list gp;
	int err = 0;

	memset(nl, 0, sizeof (*nl));

	nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | flags, protocol);
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
		err = setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
		if (err)
			log_message(LOG_INFO, "Netlink: Cannot add group %u membership on netlink socket : (%m)"
					    , group);

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

	err = setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_sz, sizeof(rcvbuf_size));
	if (err)
		log_message(LOG_INFO, "Cannot set SO_RCVBUF IP option. errno=%d (%m)", errno);

	return err;
}

/* Close Netlink channel with kernel */
static void
netlink_close(struct nl_handle *nl)
{
	if (!nl)
		return;

	if (nl->thread) {
		thread_del(nl->thread);
		nl->thread = NULL;
	}

	if (nl->fd != -1)
		close(nl->fd);

	nl->fd = -1;
}

/*
 *	Netlink neighbour lookup
 */
static int
netlink_neigh_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h, void *)
{
	struct ndmsg *r = NLMSG_DATA(h);
	struct rtattr *tb[NDA_MAX + 1];
	struct ip_address *addr;
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

	PMALLOC(addr);
	addr->family = r->ndm_family;
	switch (r->ndm_family) {
	case AF_INET:
		addr->u.sin_addr.s_addr = *(uint32_t *) RTA_DATA(tb[NDA_DST]);
		break;
	case AF_INET6:
		memcpy(&addr->u.sin6_addr, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));
		break;
	}

	gtp_interface_update_direct_tx_lladdr(addr, RTA_DATA(tb[NDA_LLADDR]));
	FREE(addr);
	return 0;
}

static int
netlink_neigh_request(struct nl_handle *nl, unsigned char family, uint16_t type)
{
	ssize_t status;
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr nlh;
		struct ndmsg ndm;
		char buf[256];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		.nlh.nlmsg_type = type,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = ++nl->seq,
		.ndm.ndm_family = family,
	};

	status = sendto(nl->fd, (void *) &req, sizeof(req), 0
			      , (struct sockaddr *) &snl, sizeof(snl));
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}

	return 0;
}

static void
netlink_neigh_lookup(__attribute__((unused)) struct thread *thread)
{
	int err;

	err = netlink_neigh_request(&nl_cmd, AF_UNSPEC, RTM_GETNEIGH);
	if (err)
		return;

	netlink_parse_info(netlink_neigh_filter, &nl_cmd, NULL, NULL, false);
}


/*
 *	Kernel Netlink reflector
 */
static int
netlink_filter(struct sockaddr_nl *snl, struct nlmsghdr *h, void *)
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

	iface = gtp_interface_get_by_ifindex(ifi->ifi_index);
	if (!iface)
		return 0;

	log_message(LOG_INFO, "Netlink: deleting interface '%s'", iface->ifname);

	gtp_interface_put(iface);
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

static int
netlink_if_link_info(struct rtattr *tb, struct gtp_interface *iface)
{
	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	struct rtattr *attr[IFLA_VLAN_MAX+1], **data = NULL;
	struct rtattr *linkdata;
	const char *kind;

	if (!tb)
		return -1;

	parse_rtattr(linkinfo, IFLA_INFO_MAX
			     , RTA_DATA(tb), RTA_PAYLOAD(tb)
			     , NLA_F_NESTED);

	if (!linkinfo[IFLA_INFO_KIND])
		return -1;

	kind = (const char *)RTA_DATA(linkinfo[IFLA_INFO_KIND]);

	/* Only take care of vlan interface type */
	if (strncmp(kind, "vlan", 4))
		return -1;

	linkdata = linkinfo[IFLA_INFO_DATA];
	if (!linkdata)
		return -1;

	parse_rtattr(attr, IFLA_VLAN_MAX
			 , RTA_DATA(linkdata), RTA_PAYLOAD(linkdata)
			 , NLA_F_NESTED);
	data = attr;

	if (!data[IFLA_VLAN_ID])
		return -1;

	iface->vlan_id = *(__u16 *)RTA_DATA(data[IFLA_VLAN_ID]);
	return 0;
}

static int
netlink_if_link_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(h);
	struct rtattr *tb[IFLA_MAX + 1];
	bool create = arg == (void*)1;
	struct gtp_interface *iface;
	int len = h->nlmsg_len;
	int err = 0;

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len, 0);

	iface = gtp_interface_get_by_ifindex(ifi->ifi_index);
	if (!iface) {
		/* do not create interface when updating stats */
		if (!create)
			return 0;

		/* reflect interface topology */
		iface = gtp_interface_alloc((char *)RTA_DATA(tb[IFLA_IFNAME])
					    , ifi->ifi_index);
		if (!iface)
			return -1;

		err = netlink_if_get_ll_addr(iface, tb);
		if (err || !iface->hw_addr_len) {
			/* ignore interface if it does not have a valid ethernet address */
			if (err) {
				log_message(LOG_INFO, "%s(): Error getting ll_addr for interface:'%s'"
						    , __FUNCTION__
						    , iface->ifname);
			}
			gtp_interface_destroy(iface);
			return err;
		}

		netlink_if_link_info(tb[IFLA_LINKINFO], iface);
	}

	if (__test_bit(GTP_INTERFACE_FL_METRICS_LINK_BIT, &iface->flags))
		get_rtnl_link_stats_rta(iface->link_metrics, tb);

	gtp_interface_put(iface);
	return 0;
}

static void
netlink_if_stats_update(__attribute__((unused)) struct thread *t)
{
	int err;

	if (nl_cmd.fd == -1) {
		err = netlink_open(&nl_cmd, daemon_data->nl_rcvbuf_size
					  , SOCK_NONBLOCK, NETLINK_ROUTE, 0, 0);
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

static int
netlink_if_init(void)
{
	int err;

	err = netlink_open(&nl_cmd, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK, NETLINK_ROUTE
				  , 0, 0);
	if (err) {
		log_message(LOG_INFO, "Error while creating Kernel netlink command channel");
		return -1;
	}

	err = gtp_netlink_if_lookup(0);
	if (err)
		return -1;

	thread_add_event(master, netlink_if_stats_update, NULL, 0);

	/* Interface configuration induces the fetching of information via
	 * the netlink channel. However, interface configuration occurs
	 * after the initial Netlink neighbor lookup. Therefore, if an
	 * entry is already present in the neighbor table, we will never
	 * receive a Netlink broadcast for it until next ARP state.
	 * Register an I/O MUX event to force fetching after parsing the
	 * configuration. */
	thread_add_event(master, netlink_neigh_lookup, NULL, 0);
	return 0;
}


/*
 *	Kernel Netlink channel init
 */
int
gtp_netlink_init(void)
{
	int err;

	/* Interface init */
	err = netlink_if_init();
	if (err) {
		log_message(LOG_INFO, "Error while probing Kernel netlink command channel");
		return -1;
	}

	/* Register Kernel netlink reflector */
	err = netlink_open(&nl_kernel, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK, NETLINK_ROUTE
				     , RTNLGRP_NEIGH, RTNLGRP_LINK, 0);
	if (err) {
		log_message(LOG_INFO, "Error while registering Kernel netlink reflector channel");
		return -1;
	}

	log_message(LOG_INFO, "Registering Kernel netlink reflector");
	nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd,
					   TIMER_NEVER, 0);
	return 0;
}

int
gtp_netlink_destroy(void)
{
	log_message(LOG_INFO, "Unregistering Kernel netlink reflector");
	netlink_close(&nl_kernel);
	netlink_close(&nl_cmd);
	return 0;
}
