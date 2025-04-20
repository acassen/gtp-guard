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

/* system includes */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libbpf.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;


/*
 *	Tunneling Handling
 */
static struct gtp_iptnl_rule *
gtp_bpf_iptnl_rule_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_iptnl_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct gtp_iptnl_rule);
	return new;
}

static void
gtp_bpf_iptnl_rule_set(struct gtp_iptnl_rule *r, gtp_iptnl_t *t)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int i;

	for (i = 0; i < nr_cpus; i++) {
		r[i].selector_addr = t->selector_addr;
		r[i].local_addr = t->local_addr;
		r[i].remote_addr = t->remote_addr;
		r[i].encap_vlan_id = t->encap_vlan_id;
		r[i].decap_vlan_id = t->decap_vlan_id;
		r[i].flags = t->flags;
	}
}

int
gtp_bpf_iptnl_action(int action, gtp_iptnl_t *t, struct bpf_map *map)
{
	struct gtp_iptnl_rule *new = NULL;
	int ret = 0, err = 0;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	const char *action_str = "adding";
	uint32_t key;
	size_t sz;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	if (!t)
		return -1;

	key = t->selector_addr;

	/* Set rule */
	if (action == RULE_ADD || action == RULE_UPDATE) {
		/* fill per cpu rule */
		new = gtp_bpf_iptnl_rule_alloc(&sz);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate iptnl_rule !!!"
					    , __FUNCTION__);
			ret = -1;
			goto end;
		}
		gtp_bpf_iptnl_rule_set(new, t);

		if (action == RULE_ADD) {
			err = bpf_map__update_elem(map, &key, sizeof(uint32_t), new, sz, BPF_NOEXIST);
		} else if (action == RULE_UPDATE) {
			err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), new, sz, 0);
			if (err) {
				libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
				log_message(LOG_INFO, "%s(): Unknown iptnl_rule for local_addr:%u.%u.%u.%u (%s)"
						    , __FUNCTION__
						    , NIPQUAD(key)
						    , errmsg);
				ret = -1;
				goto end;
			}
			action_str = "updating";
			gtp_bpf_iptnl_rule_set(new, t);
			err = bpf_map__update_elem(map, &key, sizeof(uint32_t), new, sz, BPF_EXIST);
		}
	} else if (action == RULE_DEL) {
		action_str = "deleting";
		err = bpf_map__delete_elem(map, &key, sizeof(uint32_t), 0);
	} else
		return -1;
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s iptnl_rule for local_addr:%u.%u.%u.%u (%s)"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , NIPQUAD(key)
				    , errmsg);
		ret = -1;
		goto end;
	}

	log_message(LOG_INFO, "%s(): %s XDP iptunnel rule "
			      "{selector_addr:%u.%u.%u.%u local_addr:%u.%u.%u.%u, remote_addr:%u.%u.%u.%u, flags:%d}"
			    , __FUNCTION__
			    , action_str
			    , NIPQUAD(t->selector_addr), NIPQUAD(t->local_addr), NIPQUAD(t->remote_addr), t->flags);
  end:
	if (new)
		free(new);
	return ret;
}

int
gtp_bpf_iptnl_vty(vty_t *vty, struct bpf_map *map)
{
	__be32 key = 0, next_key = 0;
	struct gtp_iptnl_rule *r;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char sip[16], lip[16], rip[16];
	int err = 0;
	size_t sz;

	/* Allocate temp rule */
	r = gtp_bpf_iptnl_rule_alloc(&sz);
	if (!r) {
		vty_out(vty, "%% Cant allocate temp iptnl_rule%s", VTY_NEWLINE);
		return -1;
	}

	vty_out(vty, "+------------------+------------------+------------------+-------+----+----+%s"
		     "| Selector Address |  Local Address   |  Remote Address  | Flags |encV|decV|%s"
		     "+------------------+------------------+------------------+-------+----+----+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(uint32_t)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:0x%.4x (%s)%s"
				   , key, errmsg, VTY_NEWLINE);
			continue;
		}

		vty_out(vty, "| %16s | %16s | %16s | %5d |%4d|%4d|%s"
			   , inet_ntoa2(r[0].selector_addr, sip)
			   , inet_ntoa2(r[0].local_addr, lip)
			   , inet_ntoa2(r[0].remote_addr, rip)
			   , r[0].flags
			   , r[0].encap_vlan_id
			   , r[0].decap_vlan_id
			   , VTY_NEWLINE);
	}

	vty_out(vty, "+------------------+------------------+------------------+-------+----+----+%s"
		   , VTY_NEWLINE);
	free(r);
        return 0;
}
