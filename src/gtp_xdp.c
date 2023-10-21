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
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "logger.h"
#include "list_head.h"
#include "json_writer.h"
#include "vty.h"
#include "gtp.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_dlock.h"
#include "gtp_apn.h"
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_bpf_utils.h"
#include "gtp_xdp.h"

/* Extern data */
extern data_t *daemon_data;

/* Local data */
static const char *pin_basedir = "/sys/fs/bpf";
static xdp_exported_maps_t xdpfwd_maps[XDPFWD_MAP_CNT];

/* Local defines */
#define STRERR_BUFSIZE	128


/*
 *	XDP related
 */
static int
gtp_bpf_log_message(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(debug & 16))
		return 0;

	log_message(LOG_INFO, format, args);
	return 0;
}

static void
gtp_bpf_cleanup_maps(struct bpf_object *obj, gtp_bpf_opts_t *opts)
{
	char errmsg[STRERR_BUFSIZE];
	struct bpf_map *map;
	vty_t *vty = opts->vty;

	bpf_object__for_each_map(map, obj) {
		char buf[GTP_PATH_MAX];
		int len, err;

		len = snprintf(buf, GTP_PATH_MAX, "%s/%d/%s"
						, pin_basedir
						, opts->ifindex
						, bpf_map__name(map));
		if (len < 0) {
			vty_out(vty, "%% eBPF: error preparing path for map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (len > GTP_PATH_MAX) {
			vty_out(vty, "%% eBPF error, pathname too long to store map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (access(buf, F_OK) != -1) {
			vty_out(vty, "eBPF: unpinning previous map in %s%s"
				   , buf, VTY_NEWLINE);
			err = bpf_map__unpin(map, buf);
			if (err) {
				libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
				vty_out(vty, "%% eBPF error:%d (%s)%s"
					   , err, errmsg, VTY_NEWLINE);
				continue;
			}
		}
	}
}

static struct bpf_object *
gtp_bpf_load_file(gtp_bpf_opts_t *opts)
{
	struct bpf_object *bpf_obj;
	char errmsg[STRERR_BUFSIZE];
	vty_t *vty = opts->vty;
	int err;

	/* open eBPF file */
	bpf_obj = bpf_object__open(opts->filename);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, STRERR_BUFSIZE);
		vty_out(vty, "%% eBPF: error opening bpf file err:%d (%s)%s"
			   , errno, errmsg, VTY_NEWLINE);
		return NULL;
	}

	/* Release previously stalled maps. Our lazzy strategy here is to
	 * simply erase previous maps during startup. Maybe if we want to
	 * implement some kind of graceful-restart we need to reuse-maps
	 * and rebuild local daemon tracking. Auto-pinning is done during
	 * bpf_object__load.
	 * FIXME: Implement graceful-restart */
	gtp_bpf_cleanup_maps(bpf_obj, opts);

	/* Finally load it */
	err = bpf_object__load(bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
		vty_out(vty, "%% eBPF: error loading bpf_object err:%d (%s)%s"
			   , err, errmsg, VTY_NEWLINE);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	return bpf_obj;
}

static int
gtp_xdp_load(gtp_bpf_opts_t *opts)
{
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog = NULL;
	struct bpf_link *bpf_lnk;
	char errmsg[STRERR_BUFSIZE];
	vty_t *vty = opts->vty;
	int len;

	/* Preprare pin_dir. We decided ifindex to be part of
	 * path to be able to load same bpf program on different
	 * ifindex */
	len = snprintf(opts->pin_root_path, GTP_PATH_MAX, "%s/%d"
					  , pin_basedir, opts->ifindex);
	if (len < 0) {
		vty_out(vty, "%% Error preparing eBPF pin_dir for ifindex:%d%s"
			   , opts->ifindex
			   , VTY_NEWLINE);
		return -1;
	}

	if (len > GTP_PATH_MAX) {
		vty_out(vty, "%% Error preparing eBPF pin_dir for ifindex:%d (path_too_long)%s"
			   , opts->ifindex
			   , VTY_NEWLINE);
		return -1;
	}

	/* Load object */
	bpf_obj = gtp_bpf_load_file(opts);
	if (!bpf_obj)
		return -1;

	/* Attach prog to interface */
	if (opts->progname[0]) {
		bpf_prog = bpf_object__find_program_by_name(bpf_obj, opts->progname);
		if (!bpf_prog) {
			vty_out(vty, "%% eBPF: unknown program:%s (fallback to first one)%s"
				   , opts->progname
				   , VTY_NEWLINE);
		}
	}

	if (!bpf_prog) {
		bpf_prog = bpf_object__next_program(bpf_obj, NULL);
		if (!bpf_prog) {
			vty_out(vty, "%% eBPF: no program found in file:%s%s"
				   , opts->filename
				   , VTY_NEWLINE);
			goto err;
		}
	}

	/* Attach XDP */
	bpf_lnk = bpf_program__attach_xdp(bpf_prog, opts->ifindex);
	if (!bpf_lnk) {
		libbpf_strerror(errno, errmsg, STRERR_BUFSIZE);
		vty_out(vty, "%% XDP: error attaching program:%s to ifindex:%d err:%d (%s)%s"
			   , bpf_program__name(bpf_prog)
			   , opts->ifindex
			   , errno, errmsg, VTY_NEWLINE);
		goto err;
	}

	opts->bpf_obj = bpf_obj;
	opts->bpf_lnk = bpf_lnk;
	return 0;

  err:
	bpf_object__close(bpf_obj);
	return -1;
}

static void
gtp_xdp_unload(gtp_bpf_opts_t *opts)
{
	bpf_link__destroy(opts->bpf_lnk);
	bpf_object__close(opts->bpf_obj);
}


int
gtp_xdp_load_fwd(gtp_bpf_opts_t *opts)
{
	int err;

	err = gtp_xdp_load(opts);
	if (err < 0)
		return -1;

	/* MAP ref for faster access */
	xdpfwd_maps[XDPFWD_MAP_TEID].map = bpf_object__find_map_by_name(opts->bpf_obj,
									"teid_xlat");
	xdpfwd_maps[XDPFWD_MAP_IPTNL].map = bpf_object__find_map_by_name(opts->bpf_obj,
									 "iptnl_info");
	return 0;
}

void
gtp_xdp_unload_fwd(gtp_bpf_opts_t *opts)
{
	gtp_xdp_unload(opts);
}


/*
 *	TEID handling
 */
static 
struct gtp_teid_rule *
gtp_xdp_teid_rule_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct gtp_teid_rule);
	return new;
}

static void
gtp_xdp_teid_rule_set(struct gtp_teid_rule *r, gtp_teid_t *t, int direction)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int i;

	for (i = 0; i < nr_cpus; i++) {
		r[i].vteid = t->vid;
		r[i].teid = t->id;
		r[i].dst_addr = t->ipv4;
		r[i].direction = direction;
		r[i].packets = 0;
		r[i].bytes = 0;
	}
}

static int
gtp_xdp_teid_action(struct bpf_map *map, int action, gtp_teid_t *t, int direction)
{
	struct gtp_teid_rule *new = NULL;
	char errmsg[STRERR_BUFSIZE];
	int err = 0;
	uint32_t key;
	size_t sz;

	if (!t)
		return -1;

	key = htonl(t->vid);

	/* Set rule */
	if (action == XDPFWD_RULE_ADD) {
		/* fill per cpu rule */
		new = gtp_xdp_teid_rule_alloc(&sz);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate teid_rule !!!"
					    , __FUNCTION__);
			err = -1;
			goto end;
		}
		gtp_xdp_teid_rule_set(new, t, direction);
		err = bpf_map__update_elem(map, &key, sizeof(uint32_t), new, sz, BPF_NOEXIST);
	} else if (action == XDPFWD_RULE_DEL)
		err = bpf_map__delete_elem(map, &key, sizeof(uint32_t), 0);
	else
		return -1;
	if (err) {
		libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s rule for VTEID:0x%.8x (%s)"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , t->vid
				    , errmsg);
		err = -1;
		goto end;
	}

	log_message(LOG_INFO, "%s(): %s XDP forwarding rule "
			      "{vteid:0x%.8x, teid:0x%.8x, dst_addr:%u.%u.%u.%u}"
			    , __FUNCTION__
			    , (action) ? "deleting" : "adding"
			    , t->vid, ntohl(t->id), NIPQUAD(t->ipv4));
  end:
	if (new)
		free(new);
	return err;
}

static int
gtp_xdp_teid_vty(struct bpf_map *map, vty_t *vty, __be32 id)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__be32 key, next_key;
	struct gtp_teid_rule *r;
	char errmsg[STRERR_BUFSIZE];
	char addr_ip[16];
        int err = 0, i;
	uint64_t packets, bytes;
	size_t sz;

	/* Allocate temp rule */
	r = gtp_xdp_teid_rule_alloc(&sz);
	if (!r) {
		vty_out(vty, "%% Cant allocate temp teid_rule%s", VTY_NEWLINE);
		return -1;
	}

	/* Specific VTEID lookup */
	if (id) {
		err = bpf_map__lookup_elem(map, &id, sizeof(uint32_t), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
			vty_out(vty, "       %% No data-plane ?! (%s)%s", errmsg, VTY_NEWLINE);
			goto end;
		}

		packets = bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			packets += r[i].packets;
			bytes += r[i].bytes;
		}

		vty_out(vty, "       %.7s pkts:%ld bytes:%ld%s"
			   , r[0].direction ? "egress" : "ingress"
			   , packets, bytes, VTY_NEWLINE);
		goto end;
	}

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(uint32_t)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:0x%.8x (%s)%s"
				   , key, errmsg, VTY_NEWLINE);
			continue;
		}

		packets = bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			packets += r[i].packets;
			bytes += r[i].bytes;
		}

		vty_out(vty, "| 0x%.8x | 0x%.8x | %16s | %9s | %12ld | %19ld |%s"
			   , r[0].vteid, ntohl(r[0].teid)
			   , inet_ntoa2(r[0].dst_addr, addr_ip)
			   , r[0].direction ? "egress" : "ingress"
			   , packets, bytes, VTY_NEWLINE);
	}

  end:
	free(r);
	return 0;
}

int
gtp_xdpfwd_teid_action(int action, gtp_teid_t *t, int direction)
{
	if (!xdpfwd_maps[XDPFWD_MAP_TEID].map)
		return -1;
	return gtp_xdp_teid_action(xdpfwd_maps[XDPFWD_MAP_TEID].map, action, t, direction);
}

int
gtp_xdpfwd_teid_vty(vty_t *vty, __be32 id)
{
	if (!xdpfwd_maps[XDPFWD_MAP_TEID].map)
		return -1;
	return gtp_xdp_teid_vty(xdpfwd_maps[XDPFWD_MAP_TEID].map, vty, id);
}

int
gtp_xdpfwd_vty(vty_t *vty)
{
	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		     "|    VTEID   |    TEID    | Endpoint Address | Direction |   Packets    |        Bytes        |%s"
		     "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	gtp_xdp_teid_vty(xdpfwd_maps[XDPFWD_MAP_TEID].map, vty, 0);
	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE);
	return 0;
}


/*
 *	Tunneling Handling
 */
static 
struct gtp_iptnl_rule *
gtp_xdp_iptnl_rule_alloc(size_t *sz)
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
gtp_xdp_iptnl_rule_set(struct gtp_iptnl_rule *r, gtp_iptnl_t *t)
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
gtp_xdp_iptnl_action(int action, gtp_iptnl_t *t)
{
	struct bpf_map *map = xdpfwd_maps[XDPFWD_MAP_IPTNL].map;
	struct gtp_iptnl_rule *new = NULL;
	int ret = 0, err = 0;
	char errmsg[STRERR_BUFSIZE];
	const char *action_str = "adding";
	uint32_t key;
	size_t sz;

	if (!t)
		return -1;

	key = t->selector_addr;

	/* Set rule */
	if (action == XDPFWD_RULE_ADD || action == XDPFWD_RULE_UPDATE) {
		/* fill per cpu rule */
		new = gtp_xdp_iptnl_rule_alloc(&sz);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate iptnl_rule !!!"
					    , __FUNCTION__);
			ret = -1;
			goto end;
		}
		gtp_xdp_iptnl_rule_set(new, t);

		if (action == XDPFWD_RULE_ADD) {
			err = bpf_map__update_elem(map, &key, sizeof(uint32_t), new, sz, BPF_NOEXIST);
		} else if (action == XDPFWD_RULE_UPDATE) {
			err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), new, sz, 0);
			if (err) {
				libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
				log_message(LOG_INFO, "%s(): Unknown iptnl_rule for local_addr:%u.%u.%u.%u (%s)"
						    , __FUNCTION__
						    , NIPQUAD(key)
						    , errmsg);
				ret = -1;
				goto end;
			}
			action_str = "updating";
			gtp_xdp_iptnl_rule_set(new, t);
			err = bpf_map__update_elem(map, &key, sizeof(uint32_t), new, sz, BPF_EXIST);
		}
	} else if (action == XDPFWD_RULE_DEL) {
		action_str = "deleting";
		err = bpf_map__delete_elem(map, &key, sizeof(uint32_t), 0);
	} else
		return -1;
	if (err) {
		libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
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
gtp_xdp_iptnl_vty(vty_t *vty)
{
	struct bpf_map *map = xdpfwd_maps[XDPFWD_MAP_IPTNL].map;
	__be32 key, next_key;
	struct gtp_iptnl_rule *r;
	char errmsg[STRERR_BUFSIZE];
	char sip[16], lip[16], rip[16];
        int err = 0;
	size_t sz;

	/* Allocate temp rule */
	r = gtp_xdp_iptnl_rule_alloc(&sz);
	if (!r) {
		vty_out(vty, "%% Cant allocate temp iptnl_rule%s", VTY_NEWLINE);
		return -1;
	}

	vty_out(vty, "+------------------+------------------+------------------+-------+%s"
		     "| Selector Address |  Local Address   |  Remote Address  | Flags |%s"
		     "+------------------+------------------+------------------+-------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(uint32_t)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:0x%.4x (%s)%s"
				   , key, errmsg, VTY_NEWLINE);
			continue;
		}

		vty_out(vty, "| %16s | %16s | %16s | %5d |%s"
			   , inet_ntoa2(r[0].selector_addr, sip)
			   , inet_ntoa2(r[0].local_addr, lip)
			   , inet_ntoa2(r[0].remote_addr, rip)
			   , r[0].flags
			   , VTY_NEWLINE);
	}

	vty_out(vty, "+------------------+------------------+------------------+-------+%s"
		   , VTY_NEWLINE);
	free(r);
        return 0;
}


/*
 *	XDP init
 */
int
gtp_xdp_init(void)
{
	libbpf_set_print(gtp_bpf_log_message);
	return 0;
}

int
gtp_xdp_destroy(void)
{
	return 0;
}