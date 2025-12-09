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

#include <net/if.h>

#include "gtp_data.h"
#include "gtp_interface.h"
#include "gtp_netlink.h"
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
	gtp_interface_event_cb_t	cb;
	void				*cb_ud;
};

static inline bool
_iface_running(const struct gtp_interface *iface)
{
	return __test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags);
}



/*
 *	Interface events system
 */

void
gtp_interface_trigger_event(struct gtp_interface *iface,
			    enum gtp_interface_event type, void *arg)
{
	int i;

	for (i = 0; i < iface->ev_n; i++)
		iface->ev[i].cb(iface, type, iface->ev[i].cb_ud, arg);
}

static void
_trigger_on_change(struct gtp_interface *iface, enum gtp_interface_event type)
{
	struct gtp_interface *master;

	if (iface->tunnel_mode) {
		/* for itself */
		gtp_interface_trigger_event(iface, type, iface);

		/* for each running master */
		list_for_each_entry(master, &daemon_data->interfaces, next) {
			if (master->bpf_prog && _iface_running(master))
				gtp_interface_trigger_event(master, type, iface);
		}
		return;
	}

	if (iface->bpf_prog == NULL) {
		master = iface->link_iface;
		if (master && master->bpf_prog && _iface_running(master)) {
			gtp_interface_trigger_event(iface, type, master);
			gtp_interface_trigger_event(master, type, iface);
		}
		return;
	}

	master = iface;

	/* on itself */
	if (type == GTP_INTERFACE_EV_PRG_START)
		gtp_interface_trigger_event(master, type, master);

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (!_iface_running(iface))
			continue;

		/* tunnels */
		if (iface->tunnel_mode)
			gtp_interface_trigger_event(master, type, iface);

		/* linked interfaces (vlan) */
		if (iface->link_iface == master) {
			gtp_interface_trigger_event(iface, type, master);
			gtp_interface_trigger_event(master, type, iface);
		}
	}

	if (type != GTP_INTERFACE_EV_PRG_START)
		gtp_interface_trigger_event(master, type, master);
}

void
gtp_interface_register_event(struct gtp_interface *iface,
			     gtp_interface_event_cb_t cb, void *ud)
{
	struct gtp_interface *master;

	if (iface->ev_n >= iface->ev_msize) {
		iface->ev_msize = !iface->ev_msize ? 8 : iface->ev_msize * 2;
		iface->ev = realloc(iface->ev, iface->ev_msize * sizeof (*iface->ev));
		if (iface->ev == NULL)
			return;
	}
	iface->ev[iface->ev_n].cb = cb;
	iface->ev[iface->ev_n].cb_ud = ud;
	++iface->ev_n;

	if (!_iface_running(iface))
		return;

	/* immediately trigger start event on this callback, as if this
	 * interface was just started */

	if (iface->tunnel_mode) {
		cb(iface, GTP_INTERFACE_EV_PRG_START, ud, iface);
		return;
	}

	if (iface->bpf_prog == NULL) {
		master = iface->link_iface;
		if (master && master->bpf_prog && _iface_running(master))
			cb(iface, GTP_INTERFACE_EV_PRG_START, ud, master);
		return;
	}

	cb(iface, GTP_INTERFACE_EV_PRG_START, ud, iface);
	master = iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (_iface_running(iface) && (iface->tunnel_mode ||
					      iface->link_iface == iface))
			cb(master, GTP_INTERFACE_EV_PRG_START, ud, iface);
	}
}

void
gtp_interface_unregister_event(struct gtp_interface *iface,
			       gtp_interface_event_cb_t cb,
			       void *ud)
{
	int i;

	if (!iface)
		return;

	for (i = 0; i < iface->ev_n; i++) {
		if (iface->ev[i].cb == cb && iface->ev[i].cb_ud == ud) {
			iface->ev[i] = iface->ev[--iface->ev_n];
			break;
		}
	}
}



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
gtp_interface_update_direct_tx_lladdr(const union addr *addr, const uint8_t *hw_addr)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;
	const union addr *addr_iface;

	list_for_each_entry(iface, l, next) {
		addr_iface = &iface->direct_tx_gw;
		if (addr_iface->family &&
		    !addr_cmp_ip(addr, addr_iface) &&
		    memcmp(iface->direct_tx_hw_addr, hw_addr, ETH_ALEN)) {
			memcpy(iface->direct_tx_hw_addr, hw_addr, ETH_ALEN);

			/* Update BPF prog accordingly */
			gtp_bpf_rt_lladdr_update(iface);

			return;
		}
	}
}

struct gtp_interface *
gtp_interface_get(const char *name, bool alloc)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;
	int ifindex;

	list_for_each_entry(iface, l, next) {
		if (!strcmp(iface->ifname, name)) {
			__sync_add_and_fetch(&iface->refcnt, 1);
			return iface;
		}
	}

	/* use netlink to get this link, along with necessary data (eth addr).
	 * it will alloc the gtp_interface data */
	if (alloc) {
		ifindex = if_nametoindex(name);
		if (ifindex > 0 &&
		    !gtp_netlink_if_lookup(ifindex))
			return gtp_interface_get(name, false);
	}

	return NULL;
}

struct gtp_interface *
gtp_interface_get_by_ifindex(int ifindex, bool alloc)
{
	struct list_head *l = &daemon_data->interfaces;
	struct gtp_interface *iface;

	if (ifindex <= 0)
		return NULL;

	list_for_each_entry(iface, l, next) {
		if (iface->ifindex == ifindex) {
			__sync_add_and_fetch(&iface->refcnt, 1);
			return iface;
		}
	}

	if (alloc && !gtp_netlink_if_lookup(ifindex))
		return gtp_interface_get_by_ifindex(ifindex, false);

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
	int err;

	if (__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ||
	    __test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags))
		return 0;

	/* run without bpf program */
	if (!p) {
		__set_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags);
		log_message(LOG_INFO, "gtp_interface: started '%s'", iface->ifname);
		_trigger_on_change(iface, GTP_INTERFACE_EV_PRG_START);
		return 0;
	}

	/* Attach */
	if (gtp_bpf_prog_attach(p, iface) < 0)
		return -1;

	log_message(LOG_INFO, "gtp_interface: started '%s' with bpf-program:'%s'"
			    , iface->ifname, p->name);

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
	_trigger_on_change(iface, GTP_INTERFACE_EV_PRG_START);

	return 0;
}

void
gtp_interface_stop(struct gtp_interface *iface)
{
	if (__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ||
	    !__test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags))
		return;

	__clear_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags);
	_trigger_on_change(iface, GTP_INTERFACE_EV_PRG_STOP);

	/* no bpf-program attached */
	if (iface->bpf_prog == NULL) {
		log_message(LOG_INFO, "gtp_interface: stopped '%s'", iface->ifname);
		return;
	}

	/* stop bpf-program */
	gtp_bpf_prog_detach(iface->bpf_prog, iface);

	log_message(LOG_INFO, "Success detaching bpf-program:'%s' from interface:'%s'"
			    , iface->bpf_prog->name, iface->ifname);
}

/* add 'slave' as a sub-interface of 'master' */
void
gtp_interface_link(struct gtp_interface *master, struct gtp_interface *slave)
{
	struct gtp_interface *sub;

	if (master->link_iface != NULL) {
		/* master is itself a slave of another interface.
		 * point to its master... */
		sub = master;
		master = master->link_iface;

		/* ... but doing so, 'sub' interface informations are lost.
		 * copy important parameters to slave.
		 * note: we could also keep whole relationship, used when
		 *   builing if_rule keys. this way is easier for now. */
		/* note: now that tunnel are not linked anymore, this code is
		 * seldomly used */
		if (!slave->vlan_id)
			slave->vlan_id = sub->vlan_id;
		if (!slave->tunnel_mode && sub->tunnel_mode) {
			slave->tunnel_mode = sub->tunnel_mode;
			slave->tunnel_local = sub->tunnel_local;
			slave->tunnel_remote = sub->tunnel_remote;
		}
	}

	/* see comment in gtp_interfaces_destroy(). masters sit first in list */
	list_move(&master->next, &daemon_data->interfaces);

	slave->link_iface = master;
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

	gtp_interface_stop(iface);
	gtp_interface_trigger_event(iface, GTP_INTERFACE_EV_DESTROYING, NULL);

	log_message(LOG_INFO, "gtp_interface: deleted '%s'", iface->ifname);

	list_for_each_entry(if_child, &daemon_data->interfaces, next) {
		if (if_child->link_iface == iface)
			if_child->link_iface = NULL;
	}
	if (iface->bpf_prog)
		list_del(&iface->bpf_prog_list);
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
