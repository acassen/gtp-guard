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

#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/tc_act/tc_skbedit.h>

#include "gtp_netlink.h"
#include "gtp_netlink_fs.h"
#include "gtp_interface.h"
#include "gtp_flow_steering.h"
#include "gtp_range_partition.h"
#include "gtp.h"
#include "id_pool.h"
#include "ip_pool.h"
#include "utils.h"
#include "vty.h"
#include "logger.h"


/*
 *	Target resolution
 */
static void
fs_resolve_target(struct gtp_interface *iface, int *out_ifindex,
		  uint16_t *out_vlan_id)
{
	if (iface->vlan_id) {
		*out_ifindex = iface->link_iface->ifindex;
		*out_vlan_id = iface->vlan_id;
		return;
	}

	*out_ifindex = iface->ifindex;
	*out_vlan_id = 0;
}

static uint16_t
rp_type_to_protocol(int rp_type, uint16_t vlan_id)
{
	if (vlan_id)
		return ETH_P_8021Q;
	if (rp_type == GTP_RANGE_PARTITION_IPV6)
		return ETH_P_IPV6;
	return ETH_P_IP;
}

static uint16_t
rp_type_to_ethtype(int rp_type)
{
	if (rp_type == GTP_RANGE_PARTITION_IPV6)
		return ETH_P_IPV6;
	return ETH_P_IP;
}


/*
 *	Flower key
 */
static void
prefix_to_mask6(int prefix_bits, struct in6_addr *mask)
{
	int i;

	memset(mask, 0, sizeof(*mask));
	for (i = 0; i < prefix_bits / 8; i++)
		mask->s6_addr[i] = 0xff;
	if (prefix_bits % 8)
		mask->s6_addr[i] = (uint8_t)(0xff << (8 - (prefix_bits % 8)));
}

static void
tc_flower_add_teid_keys(struct nlmsghdr *nlh, struct gtp_range_part *part)
{
	uint16_t port = htons(GTP_U_PORT);
	uint32_t key = htonl(part->id_pool->base);
	uint32_t mask = htonl(~0U << (32 - part->id_pool->mask_bits));

	nl_attr_put(nlh, TCA_FLOWER_KEY_ENC_UDP_DST_PORT, &port, sizeof(port));
	nl_attr_put(nlh, TCA_FLOWER_KEY_ENC_KEY_ID, &key, sizeof(key));
	nl_attr_put(nlh, TCA_FLOWER_KEY_ENC_KEY_ID_MASK, &mask, sizeof(mask));
}

static void
tc_flower_add_ipv4_keys(struct nlmsghdr *nlh, struct gtp_range_part *part)
{
	uint32_t mask = htonl(~0U << (32 - part->ip_pool->prefix_bits));

	nl_attr_put(nlh, TCA_FLOWER_KEY_IPV4_DST,
		    &part->ip_pool->prefix.sin.sin_addr, sizeof(struct in_addr));
	nl_attr_put(nlh, TCA_FLOWER_KEY_IPV4_DST_MASK, &mask, sizeof(mask));
}

static void
tc_flower_add_ipv6_keys(struct nlmsghdr *nlh, struct gtp_range_part *part)
{
	struct in6_addr mask;

	prefix_to_mask6(part->ip_pool->prefix_bits, &mask);
	nl_attr_put(nlh, TCA_FLOWER_KEY_IPV6_DST,
		    &part->ip_pool->prefix.sin6.sin6_addr, sizeof(struct in6_addr));
	nl_attr_put(nlh, TCA_FLOWER_KEY_IPV6_DST_MASK, &mask, sizeof(mask));
}


/*
 *	Skbedit action
 */
static void
tc_flower_add_skbedit(struct nlmsghdr *nlh, uint16_t queue_id)
{
	struct nlattr *act_nest, *act_entry, *act_opts;
	struct tc_skbedit parms = { .action = TC_ACT_PIPE };
	struct nla_bitfield32 act_flags = {
		.value = TCA_ACT_FLAGS_SKIP_SW,
		.selector = TCA_ACT_FLAGS_SKIP_SW,
	};

	act_nest = nl_attr_nest_start(nlh, TCA_FLOWER_ACT);

	/* Action entry at priority 1 */
	act_entry = nl_attr_nest_start(nlh, 1);
	nl_attr_put(nlh, TCA_ACT_KIND, "skbedit", sizeof("skbedit"));

	act_opts = nl_attr_nest_start(nlh, TCA_ACT_OPTIONS);
	nl_attr_put(nlh, TCA_SKBEDIT_PARMS, &parms, sizeof(parms));
	nl_attr_put(nlh, TCA_SKBEDIT_QUEUE_MAPPING, &queue_id, sizeof(queue_id));
	nl_attr_nest_end(nlh, act_opts);

	nl_attr_put(nlh, TCA_ACT_FLAGS, &act_flags, sizeof(act_flags));
	nl_attr_nest_end(nlh, act_entry);

	nl_attr_nest_end(nlh, act_nest);
}


/*
 *	Flower filter
 */
static int
tc_flower_add(int ifindex, uint16_t vlan_id, uint16_t prio,
	      uint16_t protocol, struct gtp_range_partition *rp,
	      struct gtp_range_part *part, uint16_t queue_id)
{
	struct {
		struct nlmsghdr nlh;
		struct tcmsg tc;
		char buf[1024];
	} req = {};
	struct nlattr *opts;
	uint32_t flags = TCA_CLS_FLAGS_SKIP_SW;
	uint16_t ethtype = htons(rp_type_to_ethtype(rp->type));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nlh.nlmsg_type = RTM_NEWTFILTER;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = ++nl_cmd.seq;
	req.tc.tcm_family = AF_UNSPEC;
	req.tc.tcm_ifindex = ifindex;
	req.tc.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
	req.tc.tcm_info = TC_H_MAKE(prio << 16, htons(protocol));

	nl_attr_put(&req.nlh, TCA_KIND, "flower", sizeof("flower"));

	opts = nl_attr_nest_start(&req.nlh, TCA_OPTIONS);
	nl_attr_put(&req.nlh, TCA_FLOWER_FLAGS, &flags, sizeof(flags));

	if (vlan_id) {
		nl_attr_put(&req.nlh, TCA_FLOWER_KEY_VLAN_ID,
			    &vlan_id, sizeof(vlan_id));
		nl_attr_put(&req.nlh, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
			    &ethtype, sizeof(ethtype));
	}

	switch (rp->type) {
	case GTP_RANGE_PARTITION_TEID:
		tc_flower_add_teid_keys(&req.nlh, part);
		break;
	case GTP_RANGE_PARTITION_IPV4:
		tc_flower_add_ipv4_keys(&req.nlh, part);
		break;
	case GTP_RANGE_PARTITION_IPV6:
		tc_flower_add_ipv6_keys(&req.nlh, part);
		break;
	}

	tc_flower_add_skbedit(&req.nlh, queue_id);

	nl_attr_nest_end(&req.nlh, opts);

	if (nl_send_and_recv_ack(&nl_cmd, &req.nlh) < 0) {
		log_message(LOG_INFO, "%s(): add filter prio %d failed on ifindex %d: %m"
				    , __FUNCTION__
				    , prio, ifindex);
		return -1;
	}

	return 0;
}

static int
tc_flower_del(int ifindex, uint16_t prio, uint16_t protocol)
{
	struct {
		struct nlmsghdr nlh;
		struct tcmsg tc;
		char buf[256];
	} req = {};

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nlh.nlmsg_type = RTM_DELTFILTER;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = ++nl_cmd.seq;
	req.tc.tcm_family = AF_UNSPEC;
	req.tc.tcm_ifindex = ifindex;
	req.tc.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
	req.tc.tcm_info = TC_H_MAKE(prio << 16, htons(protocol));

	nl_attr_put(&req.nlh, TCA_KIND, "flower", sizeof("flower"));

	if (nl_send_and_recv_ack(&nl_cmd, &req.nlh) < 0) {
		if (errno == ENOENT)
			return 0;
		log_message(LOG_INFO, "%s(): del filter prio %d failed on ifindex %d: %m"
				    , __FUNCTION__
				    , prio, ifindex);
		return -1;
	}

	return 0;
}


/*
 *	Per-map helpers
 */
static void
fs_install_map(int ifindex, uint16_t vlan_id, int m,
	       struct gtp_flow_steering_policy *fsp, struct gtp_range_partition *rp)
{
	int active = min(fsp->nr_queue_ids, rp->nr_parts);
	uint16_t protocol = rp_type_to_protocol(rp->type, vlan_id);
	int i;

	for (i = 0; i < active; i++)
		tc_flower_add(ifindex, vlan_id, FS_FLOWER_PRIO_BASE + m * 256 + i,
			      protocol, rp, &rp->parts[i], (uint16_t)fsp->queue_ids[i]);
}

static void
fs_uninstall_map(int ifindex, uint16_t vlan_id, int m,
		 struct gtp_flow_steering_policy *fsp, struct gtp_range_partition *rp)
{
	int active = min(fsp->nr_queue_ids, rp->nr_parts);
	uint16_t protocol = rp_type_to_protocol(rp->type, vlan_id);
	int i;

	for (i = 0; i < active; i++)
		tc_flower_del(ifindex, FS_FLOWER_PRIO_BASE + m * 256 + i, protocol);
}

static void
fs_show_part(struct vty *vty, struct gtp_range_partition *rp,
	     struct gtp_range_part *part, int prio, uint16_t queue_id)
{
	char addr_str[INET6_ADDRSTRLEN];
	int af;

	switch (rp->type) {
	case GTP_RANGE_PARTITION_TEID:
		vty_out(vty, "        prio=%d enc_key_id 0x%08x/%d -> queue %u%s"
			   , prio, part->id_pool->base, part->id_pool->mask_bits
			   , queue_id, VTY_NEWLINE);
		break;
	case GTP_RANGE_PARTITION_IPV4:
	case GTP_RANGE_PARTITION_IPV6:
		af = (rp->type == GTP_RANGE_PARTITION_IPV6) ? AF_INET6 : AF_INET;
		inet_ntop(af,
			  (af == AF_INET6) ? (void *)&part->ip_pool->prefix.sin6.sin6_addr
					   : (void *)&part->ip_pool->prefix.sin.sin_addr,
			  addr_str, sizeof(addr_str));
		vty_out(vty, "        prio=%d dst_ip %s/%d -> queue %u%s"
			   , prio, addr_str, part->ip_pool->prefix_bits
			   , queue_id, VTY_NEWLINE);
		break;
	}
}

static void
fs_show_map(struct vty *vty, struct gtp_flow_steering_policy *fsp,
	    struct gtp_range_partition *rp, int m)
{
	int active = min(fsp->nr_queue_ids, rp->nr_parts);
	int i;

	vty_out(vty, "      [map=%d rp=%s type=%s] active=%d%s"
		   , m, rp->name, range_partition_type2str(rp->type)
		   , active, VTY_NEWLINE);

	for (i = 0; i < active; i++)
		fs_show_part(vty, rp, &rp->parts[i],
			     FS_FLOWER_PRIO_BASE + m * 256 + i,
			     (uint16_t)fsp->queue_ids[i]);
}


/*
 *	Clsact qdisc
 */
static int
tc_clsact_install(int ifindex)
{
	struct {
		struct nlmsghdr nlh;
		struct tcmsg tc;
		char buf[256];
	} req = {};

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.nlh.nlmsg_type = RTM_NEWQDISC;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = ++nl_cmd.seq;
	req.tc.tcm_family = AF_UNSPEC;
	req.tc.tcm_ifindex = ifindex;
	req.tc.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
	req.tc.tcm_parent = TC_H_CLSACT;

	nl_attr_put(&req.nlh, TCA_KIND, "clsact", sizeof("clsact"));

	if (nl_send_and_recv_ack(&nl_cmd, &req.nlh) < 0) {
		if (errno == EEXIST)
			return 0;
		log_message(LOG_INFO, "%s(): clsact install failed on ifindex %d: %m"
				    , __FUNCTION__
				    , ifindex);
		return -1;
	}

	return 0;
}


/*
 *	Flow Steering main helpers
 */
int
gtp_netlink_fs_install(struct gtp_interface *iface,
		       struct gtp_flow_steering_policy *fsp)
{
	uint16_t vlan_id;
	int ifindex, m;

	fs_resolve_target(iface, &ifindex, &vlan_id);

	if (tc_clsact_install(ifindex) < 0)
		return -1;

	for (m = 0; m < fsp->nr_maps; m++)
		fs_install_map(ifindex, vlan_id, m, fsp, fsp->maps[m].rp);

	return 0;
}

int
gtp_netlink_fs_uninstall(struct gtp_interface *iface,
			 struct gtp_flow_steering_policy *fsp)
{
	uint16_t vlan_id;
	int ifindex, m;

	fs_resolve_target(iface, &ifindex, &vlan_id);

	for (m = 0; m < fsp->nr_maps; m++)
		fs_uninstall_map(ifindex, vlan_id, m, fsp, fsp->maps[m].rp);

	return 0;
}

void
gtp_netlink_fs_show(struct vty *vty, struct gtp_interface *iface,
		    struct gtp_interface_flow_steering *ifs)
{
	struct gtp_flow_steering_policy *fsp = ifs->fsp;
	uint16_t vlan_id;
	int ifindex, m;

	fs_resolve_target(iface, &ifindex, &vlan_id);

	if (vlan_id)
		vty_out(vty, "    tc-flower: dev %s (vlan %u), clsact ingress%s"
			   , iface->link_iface->ifname, vlan_id, VTY_NEWLINE);
	else
		vty_out(vty, "    tc-flower: dev %s (physical), clsact ingress%s"
			   , iface->ifname, VTY_NEWLINE);

	for (m = 0; m < fsp->nr_maps; m++)
		fs_show_map(vty, fsp, fsp->maps[m].rp, m);
}
