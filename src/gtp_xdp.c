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
#include "gtp_resolv.h"
#include "gtp_switch.h"
#include "gtp_conn.h"
#include "gtp_session.h"
#include "gtp_bpf.h"
#include "gtp_xdp.h"

/* Extern data */
extern data_t *daemon_data;


/* Local data */
xdp_exported_maps_t xdpfwd_exported_maps[XDPFWD_MAP_CNT] = {
	{ "/sys/fs/bpf/xdpfwd_teid_xlat"	, false} ,
	{ "/sys/fs/bpf/xdpfwd_ip_frag"		, false} ,
	{ "/sys/fs/bpf/xdpfwd_iptnl_info"	, false}
};


/*
 *	XDP related
 */

/* Verify BPF-filesystem is mounted on given file path */
static int
gtp_xdp_bpf_fs_check_path(const char *path)
{
        struct statfs st_fs;
        char *dname, *dir;
        int err = 0;

        if (path == NULL)
                return -EINVAL;

        dname = strdup(path);
        if (dname == NULL)
                return -ENOMEM;

        dir = dirname(dname);
        if (statfs(dir, &st_fs)) {
                log_message(LOG_INFO, "ERR: failed to statfs %s: errno:%d (%m)\n"
                                    , dir, errno);
                err = -errno;
        }
        free(dname);

        if (!err && st_fs.f_type != BPF_FS_MAGIC) {
                log_message(LOG_INFO, "%s(): specified path %s is not on BPF FS\n\n"
                                      " You need to mount the BPF filesystem type like:\n"
                                      "  mount -t bpf bpf /sys/fs/bpf/\n\n"
                                    , __FUNCTION__
                                    , path);
                err = -EINVAL;
        }

        return err;
}

/* Load existing map via filesystem, if possible */
static int
gtp_xdp_load_map_file(const char *file, struct bpf_map_data *map_data)
{
        int fd;

        if (gtp_xdp_bpf_fs_check_path(file) < 0) {
                return -1;
        }

        fd = bpf_obj_get(file);
        if (fd > 0) {           /* Great: map file already existed use it */
                // FIXME: Verify map size etc is the same before returning it!
                // data available via map->def.XXX and fdinfo
                log_message(LOG_INFO, "%s(): Loaded bpf-map:%s from file:%s"
                                    , __FUNCTION__
                                    , map_data->name
                                    , file);
                return fd;
        }

        return -1;
}

/* This callback gets invoked for every map in ELF file */
int
xdpfwd_pre_load_maps_via_sysfs(struct bpf_map_data *map_data, int idx)
{
	char *path = xdpfwd_exported_maps[idx].path;
	int fd;

	fd = gtp_xdp_load_map_file(path, map_data);
	if (fd > 0) {
		/* Makes bpf_load.c skip creating map */
		map_data->fd = fd;
		xdpfwd_exported_maps[idx].loaded = true;
		return 0;
	}

	return -1;
}

static int
gtp_xdp_map_export(xdp_exported_maps_t *maps, int idx)
{
        char *path = maps[idx].path;

        /* Export map as a file */
        if (bpf_obj_pin(map_fd[map_data_count + idx], path) != 0) {
		log_message(LOG_INFO, "%s(): Cannot pin map(%s) file:%s errno:%d (%m)"
				    , __FUNCTION__
				    , map_data[map_data_count + idx].name, path, errno);
		return -1;
	}

	maps[idx].loaded = true;
	log_message(LOG_INFO, "%s(): Exporting bpf-map:%s to file:%s"
			    , __FUNCTION__
			    , map_data[map_data_count + idx].name
			    , path);
        return 0;
}

static int
gtp_xdp_map_load(xdp_exported_maps_t *maps, int size)
{
	int i, ret;

	for (i = 0; i < size; i++) {
		if (maps[i].loaded)
			continue;
		ret = gtp_xdp_map_export(maps, i);
		if (ret < 0)
			return -1;
	}

	return 0;
}

static int
gtp_xdp_load(const char *filename, int ifindex,
	     xdp_exported_maps_t *maps, int maps_size,
	     int (*pre_load) (struct bpf_map_data *, int))
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	int ret;

	/* Setting rlimit */
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		log_message(LOG_INFO, "%s(): Cant setrlimit !!!", __FUNCTION__);
		return -1;
	}

	ret = bpf_load_from_file(filename, pre_load);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Cant load eBPF file:%s"
				    , __FUNCTION__
				    , filename);
		return -1;
	}

	ret = gtp_xdp_map_load(maps, maps_size);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Unable to export maps for eBPF file:%s"
				    , __FUNCTION__
				    , filename);
		return -1;
	}

	bpf_map_load_ack(maps_size);

//	ret = bpf_set_link_xdp_fd(ifindex, prog_fd[prog_cnt-1], 0);
	ret = bpf_set_link_xdp_fd(ifindex, prog_fd[prog_cnt-1], XDP_FLAGS_DRV_MODE);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Cant set ifindex:%d with XDP program"
				    , __FUNCTION__
				    , ifindex);
		return -1;
	}

	return 0;
}

static void
gtp_xdp_unload(int ifindex, xdp_exported_maps_t *maps, int maps_size)
{
	int i;

//	bpf_set_link_xdp_fd(ifindex, -1, 0);
	bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);

	if (!maps || !maps_size)
		return;

	/* Remove all exported map file */
	for (i = 0; i < maps_size; i++) {
		if (!maps[i].loaded)
			continue;

		maps[i].loaded = false;
		if (unlink(maps[i].path) < 0) {
                        log_message(LOG_INFO, "%s(): cannot unlink map_file:%s errno:%d (%m)\n"
					    , __FUNCTION__
					    , maps[i].path
					    , errno);
			continue;
		}

		log_message(LOG_INFO, "%s(): Success unlinking map_file:%s\n"
				    , __FUNCTION__
				    , maps[i].path);
	}	
}


int
gtp_xdp_load_fwd(const char *filename, int ifindex)
{
	return gtp_xdp_load(filename, ifindex, xdpfwd_exported_maps, XDPFWD_MAP_CNT,
			    xdpfwd_pre_load_maps_via_sysfs);
}

void
gtp_xdp_unload_fwd(int ifindex)
{
	gtp_xdp_unload(ifindex, xdpfwd_exported_maps, XDPFWD_MAP_CNT);
}


/*
 *	TEID handling
 */
static 
struct gtp_teid_rule *
gtp_xdp_teid_rule_alloc(void)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_teid_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

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
gtp_xdp_teid_action(const char *filename, int action, gtp_teid_t *t, int direction)
{
	struct gtp_teid_rule *new = NULL;
	int fd, ret = 0;
	uint32_t key;

	if (!t)
		return -1;

	key = htonl(t->vid);

	/* Open sysfs bpf map */
	fd = bpf_obj_get(filename);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): Cant open bpf_map[%s] errno:%d (%m)"
				    , __FUNCTION__
				    , filename, errno);
		return -1;
	}

	/* Set rule */
	if (action == XDPFWD_RULE_ADD) {
		/* fill per cpu rule */
		new = gtp_xdp_teid_rule_alloc();
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate teid_rule !!!"
					, __FUNCTION__);
			ret = -1;
			goto end;
		}
		gtp_xdp_teid_rule_set(new, t, direction);
		ret = bpf_map_update_elem(fd, &key, new, BPF_NOEXIST);
	} else if (action == XDPFWD_RULE_DEL)
		ret = bpf_map_delete_elem(fd, &key);
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): Cant %s rule for VTEID:0x%.8x"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , t->vid);
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
	close(fd);
	return ret;
}

static int
gtp_xdp_teid_vty(const char *filename, vty_t *vty, __be32 id)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__be32 key, next_key;
	struct gtp_teid_rule *r;
	char addr_ip[16];
        int fd, ret = 0, i;
	uint64_t packets, bytes;

        /* Open sysfs bpf map */
        fd = bpf_obj_get(filename);
        if (fd < 0) {
		vty_out(vty, "%% Cant open bpf_map[%s] errno:%d (%m)%s"
                           , filename, errno, VTY_NEWLINE);
		return -1;
	}

	/* Allocate temp rule */
	r = gtp_xdp_teid_rule_alloc();
	if (!r) {
		vty_out(vty, "%% Cant allocate temp teid_rule%s", VTY_NEWLINE);
		close(fd);
		return -1;
	}

	/* Specific VTEID lookup */
	if (id) {
		ret = bpf_map_lookup_elem(fd, &id, r);
		if (ret != 0) {
			vty_out(vty, "       %% No data-plane ?!%s", VTY_NEWLINE);
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
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		key = next_key;
		ret = bpf_map_lookup_elem(fd, &key, r);
		if (ret != 0) {
			vty_out(vty, "%% error fetching value for key:0x%.8x%s"
				   , key, VTY_NEWLINE);
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
        close(fd);
        return 0;
}

int
gtp_xdpfwd_teid_action(int action, gtp_teid_t *t, int direction)
{
	if (!xdpfwd_exported_maps[0].loaded)
		return -1;
	return gtp_xdp_teid_action(xdpfwd_exported_maps[0].path, action, t, direction);
}

int
gtp_xdpfwd_teid_vty(vty_t *vty, __be32 id)
{
	return gtp_xdp_teid_vty(xdpfwd_exported_maps[0].path, vty, id);
}

int
gtp_xdpfwd_vty(vty_t *vty)
{
	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		     "|    VTEID   |    TEID    | Endpoint Address | Direction |   Packets    |        Bytes        |%s"
		     "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	gtp_xdp_teid_vty(xdpfwd_exported_maps[0].path, vty, 0);
	vty_out(vty, "+------------+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE);
	return 0;
}


/*
 *	Tunneling Handling
 */
static 
struct gtp_iptnl_rule *
gtp_xdp_iptnl_rule_alloc(void)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_iptnl_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

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
	struct gtp_iptnl_rule *new = NULL;
	int fd, ret = 0;
	const char *action_str = "adding";
	uint32_t key;

	if (!t)
		return -1;

	key = t->selector_addr;

	/* Open sysfs bpf map */
	fd = bpf_obj_get(xdpfwd_exported_maps[1].path);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): Cant open bpf_map[%s] errno:%d (%m)"
				    , __FUNCTION__
				    , xdpfwd_exported_maps[0].path, errno);
		return -1;
	}

	/* Set rule */
	if (action == XDPFWD_RULE_ADD || action == XDPFWD_RULE_UPDATE) {
		/* fill per cpu rule */
		new = gtp_xdp_iptnl_rule_alloc();
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate iptnl_rule !!!"
					    , __FUNCTION__);
			ret = -1;
			goto end;
		}
		gtp_xdp_iptnl_rule_set(new, t);

		if (action == XDPFWD_RULE_ADD) {
			ret = bpf_map_update_elem(fd, &key, new, BPF_NOEXIST);
		} else if (action == XDPFWD_RULE_UPDATE) {
			ret = bpf_map_lookup_elem(fd, &key, new);
			if (ret != 0) {
				log_message(LOG_INFO, "%s(): Unknown iptnl_rule for local_addr:%u.%u.%u.%u"
						    , __FUNCTION__
						    , NIPQUAD(key));
				goto end;
			}
			action_str = "updating";
			gtp_xdp_iptnl_rule_set(new, t);
			ret = bpf_map_update_elem(fd, &key, new, BPF_EXIST);
		}
	} else if (action == XDPFWD_RULE_DEL) {
		action_str = "deleting";
		ret = bpf_map_delete_elem(fd, &key);
	}
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): Cant %s iptnl_rule for local_addr:%u.%u.%u.%u"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , NIPQUAD(key));
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
	close(fd);
	return ret;
}

int
gtp_xdp_iptnl_vty(vty_t *vty)
{
	__be32 key, next_key;
	struct gtp_iptnl_rule *r;
	char sip[16], lip[16], rip[16];
        int fd, ret = 0;

        /* Open sysfs bpf map */
        fd = bpf_obj_get(xdpfwd_exported_maps[1].path);
        if (fd < 0) {
		vty_out(vty, "%% Cant open bpf_map[%s] errno:%d (%m)%s"
                           , xdpfwd_exported_maps[1].path, errno, VTY_NEWLINE);
		return -1;
	}

	/* Allocate temp rule */
	r = gtp_xdp_iptnl_rule_alloc();
	if (!r) {
		vty_out(vty, "%% Cant allocate temp iptnl_rule%s", VTY_NEWLINE);
		close(fd);
		return -1;
	}

	vty_out(vty, "+------------------+------------------+------------------+-------+%s"
		     "| Selector Address |  Local Address   |  Remote Address  | Flags |%s"
		     "+------------------+------------------+------------------+-------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	/* Walk hashtab */
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		key = next_key;
		ret = bpf_map_lookup_elem(fd, &key, r);
		if (ret != 0) {
			vty_out(vty, "%% error fetching value for key:0x%.4x%s"
				   , key, VTY_NEWLINE);
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
        close(fd);
        return 0;
}
