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

struct gtp_interface_event_storage
{
	gtp_interface_event_cb_t cb;
	void *cb_ud;
};


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
	gtp_bpf_rt_lladdr_update(iface);
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

int
gtp_interface_start(struct gtp_interface *iface)
{
	struct gtp_bpf_prog *p = iface->bpf_prog;
	struct gtp_interface *if_child;
	int err;

	if (__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ||
	    __test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags))
		return 0;

	if (!p) {
		__set_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags);
		return 0;
	}

	/* Attach */
	if (gtp_bpf_prog_attach(p, iface) < 0)
		return -1;

	/* Trigger event on this iface and all sub-interfaces */
	gtp_interface_trigger_event(iface, GTP_INTERFACE_EV_PRG_BIND);
	list_for_each_entry(if_child, &daemon_data->interfaces, next) {
		if (if_child->link_iface == iface)
			gtp_interface_trigger_event(if_child,
						    GTP_INTERFACE_EV_PRG_BIND);
	}

	log_message(LOG_INFO, "Success attaching bpf-program:'%s' to interface:'%s'"
			    , p->name, iface->ifname);

	/* Metrics init */
	err = 0;
	if (__test_bit(GTP_INTERFACE_FL_METRICS_GTP_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(p,
							iface->ifindex, IF_METRICS_GTP);
	if (__test_bit(GTP_INTERFACE_FL_METRICS_PPPOE_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(p,
							iface->ifindex, IF_METRICS_PPPOE);
	if (__test_bit(GTP_INTERFACE_FL_METRICS_IPIP_BIT, &iface->flags))
		err = (err) ? : gtp_bpf_rt_metrics_init(p,
							iface->ifindex, IF_METRICS_IPIP);
	if (err) {
		log_message(LOG_WARNING, "error initializing metrics for interface:'%s'"
				       , iface->ifname);
	}

	__set_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags);
	return 0;
}

void
gtp_interface_stop(struct gtp_interface *iface)
{
	struct gtp_interface *if_child;

	if (__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ||
	    !__test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags))
		return;

	__clear_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags);

	if (iface->bpf_prog == NULL)
		return;

	/* Detach program */
	gtp_bpf_prog_detach(iface->bpf_prog, iface);

	/* Trigger event on this iface and all sub-interfaces */
	gtp_interface_trigger_event(iface, GTP_INTERFACE_EV_PRG_UNBIND);
	list_for_each_entry(if_child, &daemon_data->interfaces, next) {
		if (if_child->link_iface == iface)
			gtp_interface_trigger_event(if_child,
						    GTP_INTERFACE_EV_PRG_UNBIND);
	}
}


void
gtp_interface_register_event(struct gtp_interface *iface,
			     gtp_interface_event_cb_t cb,
			     void *ud)
{
	if (iface->ev_n >= iface->ev_msize) {
		iface->ev_msize = !iface->ev_msize ? 8 : iface->ev_msize * 2;
		iface->ev = realloc(iface->ev, iface->ev_msize * sizeof (*iface->ev));
		if (iface->ev == NULL)
			return;
	}
	iface->ev[iface->ev_n].cb = cb;
	iface->ev[iface->ev_n].cb_ud = ud;
	++iface->ev_n;
}

void
gtp_interface_unregister_event(struct gtp_interface *iface,
			       gtp_interface_event_cb_t cb)
{
	int i;

	for (i = 0; i < iface->ev_n; i++) {
		if (iface->ev[i].cb == cb) {
			if (iface->ev_n > 1)
				iface->ev[i] = iface->ev[iface->ev_n - 1];
			--iface->ev_n;
			break;
		}
	}
}


void
gtp_interface_trigger_event(struct gtp_interface *iface,
			    enum gtp_interface_event type)
{
	int i;

	for (i = 0; i < iface->ev_n; i++)
		iface->ev[i].cb(iface, type, iface->ev[i].cb_ud);
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

	log_message(LOG_INFO, "gtp_interface: adding '%s'", name);

	return new;
}

void
gtp_interface_destroy(struct gtp_interface *iface)
{
	struct gtp_interface *if_child;

	log_message(LOG_INFO, "gtp_interface: deleting '%s'", iface->ifname);

	gtp_interface_trigger_event(iface, GTP_INTERFACE_EV_DESTROYING);

	list_for_each_entry(if_child, &daemon_data->interfaces, next) {
		if (if_child->link_iface == iface)
			if_child->link_iface = NULL;
	}
	if (iface->bpf_prog) {
		gtp_bpf_prog_detach(iface->bpf_prog, iface);
		list_del(&iface->bpf_prog_list);
	}
	FREE_PTR(iface->link_metrics);
	list_head_del(&iface->next);
	free(iface->ev);
	FREE(iface);
}

int
gtp_interfaces_destroy(void)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface, *_iface;

	/* should remove sub-interfaces first (eth1.10 before eth1)
	 * parsing list in reverse is the poor man tools */
	list_for_each_entry_safe_reverse(iface, _iface, l, next)
		gtp_interface_destroy(iface);
	return 0;
}
