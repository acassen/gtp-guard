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

#include "gtp_data.h"
#include "gtp_interface.h"
#include "gtp_bpf_rt.h"
#include "addr.h"
#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Interface helpers
 */
void
gtp_interface_metrics_foreach(int (*hdl) (struct gtp_interface *, void *, const char *, int, __u8, __u8),
			      void *arg, const char *var, int var_type, __u8 type, __u8 direction)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;

	list_for_each_entry(iface, l, next) {
		__sync_add_and_fetch(&iface->refcnt, 1);
		(*(hdl)) (iface, arg, var, var_type, type, direction);
		__sync_sub_and_fetch(&iface->refcnt, 1);
	}
}

void
gtp_interface_foreach(int (*hdl) (struct gtp_interface *, void *), void *arg)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;

	list_for_each_entry(iface, l, next) {
		__sync_add_and_fetch(&iface->refcnt, 1);
		(*(hdl)) (iface, arg);
		__sync_sub_and_fetch(&iface->refcnt, 1);
	}
}

void
gtp_interface_update_direct_tx_lladdr(struct ip_address *addr, const uint8_t *hw_addr)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;
	struct ip_address *addr_iface;
	struct gtp_bpf_prog *p;
	int i;

	list_for_each_entry(iface, l, next) {
		addr_iface = &iface->direct_tx_gw;
		if (!addr_iface->family)
			continue;

		if (addr_iface->family != addr->family)
			continue;

		switch (addr->family) {
		case AF_INET:
			if (__addr_ip4_equal(&addr_iface->u.sin_addr,
					     &addr->u.sin_addr))
				goto found;
			break;
		case AF_INET6:
			if (__addr_ip6_equal(&addr_iface->u.sin6_addr,
					     &addr->u.sin6_addr))
				goto found;
			break;
		}
	}
	return;

 found:
	if (!memcmp(iface->direct_tx_hw_addr, hw_addr, ETH_ALEN))
		return;

	memcpy(iface->direct_tx_hw_addr, hw_addr, ETH_ALEN);

	/* Update BPF prog accordingly */
	p = iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP].prog;
	if (p != NULL) {
		for (i = 0; i < p->tpl_n; i++)
			p->tpl[i]->direct_tx_lladdr_updated(p, iface);
	}
}

struct gtp_interface *
gtp_interface_get(const char *name)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;

	list_for_each_entry(iface, l, next) {
		if (!strncmp(iface->ifname, name, strlen(name))) {
			__sync_add_and_fetch(&iface->refcnt, 1);
			return iface;
		}
	}

	return NULL;
}

struct gtp_interface *
gtp_interface_get_by_ifindex(int ifindex)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;

	list_for_each_entry(iface, l, next) {
		if (iface->ifindex == ifindex) {
			__sync_add_and_fetch(&iface->refcnt, 1);
			return iface;
		}
	}

	return NULL;
}

int
gtp_interface_put(struct gtp_interface *iface)
{
	__sync_sub_and_fetch(&iface->refcnt, 1);
	return 0;
}

struct gtp_interface *
gtp_interface_alloc(const char *name, int ifindex)
{
	struct gtp_interface *new;

	PMALLOC(new);
	if (!new)
		return NULL;

	INIT_LIST_HEAD(&new->next);
	if (name)
		bsd_strlcpy(new->ifname, name, GTP_STR_MAX_LEN - 1);
	new->ifindex = ifindex;
	__set_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &new->flags);

	list_add_tail(&new->next, &daemon_data->interfaces);
	__sync_add_and_fetch(&new->refcnt, 1);

	return new;
}

int
gtp_interface_load_bpf(struct gtp_interface *iface)
{
	struct gtp_bpf_prog *p;
	struct bpf_link *lnk = NULL;
	int err;

	/* XDP */
	p = iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP].prog;
	if (p) {
		lnk = gtp_bpf_prog_attach_xdp(p, iface);
		if (!lnk)
			goto err;
		iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP].lnk = lnk;
	}

	/* TC */
	p = iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_TC].prog;
	if (p) {
		err = gtp_bpf_prog_attach_tc(p, iface);
		if (err)
			goto err;
	}

	return 0;

  err:
	log_message(LOG_INFO, "error attaching bpf-program:'%s'"
			      " to interface:'%s'"
			    , p->name, iface->ifname);
	gtp_bpf_prog_detach_xdp(lnk);
	iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP].lnk = NULL;
	return -1;
}

int
gtp_interface_unload_bpf(struct gtp_interface *iface)
{
	gtp_bpf_prog_detach_xdp(iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP].lnk);
	gtp_bpf_prog_detach_tc(iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_TC].prog,
			       iface);
	gtp_bpf_prog_attr_reset(&iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_XDP]);
	gtp_bpf_prog_attr_reset(&iface->bpf_prog_attr[GTP_BPF_PROG_TYPE_TC]);
	return 0;
}

int
__gtp_interface_destroy(struct gtp_interface *iface)
{
	gtp_interface_unload_bpf(iface);
	FREE_PTR(iface->link_metrics);
	list_head_del(&iface->next);
	FREE(iface);
	return 0;
}

int
gtp_interface_destroy(struct gtp_interface *iface)
{
	__gtp_interface_destroy(iface);
	return 0;
}

int
gtp_interfaces_destroy(void)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface, *_iface;

	list_for_each_entry_safe(iface, _iface, l, next)
		__gtp_interface_destroy(iface);
	return 0;
}
