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

#include <arpa/inet.h>

#include "gtp_data.h"
#include "gtp_range_partition.h"
#include "command.h"
#include "table.h"
#include "addr.h"


/* Extern data */
extern struct data *daemon_data;

static const char *type_str[] = {
	[GTP_RANGE_PARTITION_TEID] = "teid",
	[GTP_RANGE_PARTITION_IPV4] = "ipv4",
	[GTP_RANGE_PARTITION_IPV6] = "ipv6",
};


/*
 *	CONFIG_NODE commands
 */
DEFUN(range_partition,
      range_partition_cmd,
      "range-partition WORD",
      "Configure range partition\n"
      "Partition name")
{
	struct gtp_range_partition *rp;

	rp = gtp_range_partition_get(argv[0]);
	rp = rp ? : gtp_range_partition_alloc(argv[0]);
	if (!rp) {
		vty_out(vty, "%% Error allocating range-partition '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = RANGE_PARTITION_NODE;
	vty->index = rp;
	return CMD_SUCCESS;
}

DEFUN(no_range_partition,
      no_range_partition_cmd,
      "no range-partition WORD",
      "Destroy range partition\n"
      "Partition name")
{
	struct gtp_range_partition *rp;

	rp = gtp_range_partition_get(argv[0]);
	if (!rp) {
		vty_out(vty, "%% unknown range-partition '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (rp->refcnt) {
		vty_out(vty, "%% range-partition '%s' is in use%s"
	  		   , rp->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_range_partition_free(rp);
	return CMD_SUCCESS;
}


/*
 *	RANGE_PARTITION_NODE commands
 */
DEFUN(range_partition_type,
      range_partition_type_cmd,
      "type (teid|ipv4|ipv6)",
      "Partition type\n"
      "TEID range\n"
      "IPv4 prefix range\n"
      "IPv6 prefix range")
{
	struct gtp_range_partition *rp = vty->index;

	if (rp->nr_parts) {
		vty_out(vty, "%% Cannot change type: parts already configured%s"
	  		   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "teid"))
		rp->type = GTP_RANGE_PARTITION_TEID;
	else if (!strcmp(argv[0], "ipv4"))
		rp->type = GTP_RANGE_PARTITION_IPV4;
	else
		rp->type = GTP_RANGE_PARTITION_IPV6;

	return CMD_SUCCESS;
}

DEFUN(range_partition_part_teid,
      range_partition_part_teid_cmd,
      "part-id <0-65535> range WORD mask <1-31>",
      "Manual TEID partition\n"
      "Partition ID\n"
      "Range base (hex uint32, e.g. 0x10000000)\n"
      "TEID base value\n"
      "Prefix bit count\n"
      "Prefix bits (pool size = 1 << (32 - bits))")
{
	struct gtp_range_partition *rp = vty->index;
	struct id_pool *pool;
	uint32_t base;
	int part_id, mask_bits;

	if (rp->type != GTP_RANGE_PARTITION_TEID) {
		vty_out(vty, "%% Command only valid for type teid%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (rp->auto_split) {
		vty_out(vty, "%% Cannot mix manual part-id with split%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("part-id", part_id, argv[0], 0, 65535);
	VTY_GET_UINT32("TEID base", base, argv[1]);
	VTY_GET_INTEGER_RANGE("mask", mask_bits, argv[2], 1, 31);

	pool = id_pool_alloc(base, mask_bits);
	if (!pool) {
		vty_out(vty, "%% Failed to alloc id_pool (base=0x%08x mask=%d)%s"
			   , base, mask_bits, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gtp_range_partition_add_part(rp, part_id, pool) < 0) {
		id_pool_destroy(pool);
		vty_out(vty, "%% Failed to add part-id %d%s", part_id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(range_partition_part_ip,
      range_partition_part_ip_cmd,
      "part-id <0-65535> prefix ADDR",
      "Manual IPv4/IPv6 partition\n"
      "Partition ID\n"
      "IP prefix\n"
      "CIDR address (e.g. 10.0.0.0/24 or 2001:db8::/48)")
{
	struct gtp_range_partition *rp = vty->index;
	struct ip_pool *pool;
	int part_id;

	if (rp->type == GTP_RANGE_PARTITION_TEID) {
		vty_out(vty, "%% Command only valid for type ipv4/ipv6%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (rp->auto_split) {
		vty_out(vty, "%% Cannot mix manual part-id with split%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("part-id", part_id, argv[0], 0, 65535);
	pool = ip_pool_alloc(argv[1]);
	if (!pool) {
		vty_out(vty, "%% Failed to alloc ip_pool for '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gtp_range_partition_add_part(rp, part_id, pool) < 0) {
		ip_pool_destroy(pool);
		vty_out(vty, "%% Failed to add part-id %d%s", part_id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(no_range_partition_part,
      no_range_partition_part_cmd,
      "no part-id <0-65535>",
      "Remove a partition entry\n"
      "Partition ID")
{
	struct gtp_range_partition *rp = vty->index;
	int part_id;

	VTY_GET_INTEGER_RANGE("part-id", part_id, argv[0], 0, 65535);

	if (rp->auto_split) {
		vty_out(vty, "%% Use 'no split' to remove auto-generated parts%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gtp_range_partition_del_part(rp, part_id) < 0) {
		vty_out(vty, "%% part-id %d not found%s", part_id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(range_partition_split,
      range_partition_split_cmd,
      "split WORD count <2-65536>",
      "Auto-split a range into equal partitions\n"
      "Range: 'base/prefix' (TEID: hex, e.g. 0x10000000/8) or CIDR (IPv4/IPv6)\n"
      "Partition count keyword\n"
      "Number of partitions (must be power of 2)")
{
	struct gtp_range_partition *rp = vty->index;
	int count = atoi(argv[1]);

	if (rp->nr_parts && !rp->auto_split) {
		vty_out(vty, "%% Cannot mix split with manual part-id%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (rp->auto_split)
		gtp_range_partition_split_clear(rp);

	if (gtp_range_partition_split(rp, argv[0], count) < 0) {
		vty_out(vty, "%% Failed to split '%s' into %d parts%s"
			   , argv[0], count, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(no_range_partition_split,
      no_range_partition_split_cmd,
      "no split",
      "Remove auto-split and all generated partitions")
{
	struct gtp_range_partition *rp = vty->index;

	if (gtp_range_partition_split_clear(rp) < 0) {
		vty_out(vty, "%% No split configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static void
range_partition_vty_show_parts(struct vty *vty, struct gtp_range_partition *rp)
{
	struct gtp_range_part *p;
	struct table *tbl;
	char addr_str[INET6_ADDRSTRLEN];
	int i;

	tbl = table_init(5, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "part-id", "base/prefix", "inuse", "total", "% used");
	table_set_column_align(tbl, ALIGN_RIGHT, ALIGN_LEFT,
			       ALIGN_RIGHT, ALIGN_RIGHT, ALIGN_RIGHT);

	for (i = 0; i < rp->nr_parts; i++) {
		p = &rp->parts[i];
		if (rp->type == GTP_RANGE_PARTITION_TEID) {
			table_add_row_fmt(tbl, "%d|0x%08x/%d|%u|%u|%.2f%%"
					     , p->part_id
					     , p->id_pool->base
					     , p->id_pool->mask_bits
					     , p->id_pool->pool.used
					     , p->id_pool->pool.size
					     , (p->id_pool->pool.used * 100.0)
					       / p->id_pool->pool.size);
			continue;
		}

		table_add_row_fmt(tbl, "%d|%s/%d|%u|%u|%.2f%%"
				     , p->part_id
				     , addr_stringify_ip(&p->ip_pool->prefix,
							addr_str,
							sizeof(addr_str))
				     , p->ip_pool->prefix_bits
				     , p->ip_pool->pool.used
				     , p->ip_pool->pool.size
				     , (p->ip_pool->pool.used * 100.0)
				       / p->ip_pool->pool.size);
	}

	table_vty_out(tbl, vty);
	table_destroy(tbl);
}

DEFUN(show_range_partition,
      show_range_partition_cmd,
      "show range-partition [WORD]",
      SHOW_STR
      "Range partition\n"
      "Partition name (optional filter)")
{
	struct gtp_range_partition *rp;
	const char *name = argc ? argv[0] : NULL;

	if (list_empty(&daemon_data->range_partition)) {
		vty_out(vty, "%% No range-partition configured%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	list_for_each_entry(rp, &daemon_data->range_partition, next) {
		if (name && strncmp(rp->name, name, GTP_NAME_MAX_LEN - 1))
			continue;

		vty_out(vty, "range-partition %s  type=%s  parts=%d  refcnt=%d%s"
			   , rp->name
			   , type_str[rp->type]
			   , rp->nr_parts
			   , rp->refcnt
			   , VTY_NEWLINE);

		if (rp->auto_split)
			vty_out(vty, "  split %s count %d%s"
				   , rp->split_range, rp->split_count, VTY_NEWLINE);

		if (rp->nr_parts)
			range_partition_vty_show_parts(vty, rp);
	}

	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static void
range_partition_config_write_parts(struct vty *vty, struct gtp_range_partition *rp)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct gtp_range_part *p;
	int i;

	for (i = 0; i < rp->nr_parts; i++) {
		p = &rp->parts[i];
		if (rp->type == GTP_RANGE_PARTITION_TEID) {
			vty_out(vty, " part-id %d range 0x%08x mask %d%s"
				   , p->part_id
				   , p->id_pool->base
				   , p->id_pool->mask_bits
				   , VTY_NEWLINE);
			continue;
		}

		vty_out(vty, " part-id %d prefix %s/%d%s"
			   , p->part_id
			   , addr_stringify_ip(&p->ip_pool->prefix,
					       addr_str, sizeof(addr_str))
			   , p->ip_pool->prefix_bits
			   , VTY_NEWLINE);
	}
}

static int
gtp_range_partition_config_write(struct vty *vty)
{
	struct gtp_range_partition *rp;

	list_for_each_entry(rp, &daemon_data->range_partition, next) {
		vty_out(vty, "range-partition %s%s", rp->name, VTY_NEWLINE);
		vty_out(vty, " type %s%s", type_str[rp->type], VTY_NEWLINE);

		if (rp->auto_split)
			vty_out(vty, " split %s count %d%s"
				   , rp->split_range, rp->split_count, VTY_NEWLINE);
		else
			range_partition_config_write_parts(vty, rp);

		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_range_partition_install(void)
{
	install_element(CONFIG_NODE, &range_partition_cmd);
	install_element(CONFIG_NODE, &no_range_partition_cmd);

	install_default(RANGE_PARTITION_NODE);
	install_element(RANGE_PARTITION_NODE, &range_partition_type_cmd);
	install_element(RANGE_PARTITION_NODE, &range_partition_part_teid_cmd);
	install_element(RANGE_PARTITION_NODE, &range_partition_part_ip_cmd);
	install_element(RANGE_PARTITION_NODE, &no_range_partition_part_cmd);
	install_element(RANGE_PARTITION_NODE, &range_partition_split_cmd);
	install_element(RANGE_PARTITION_NODE, &no_range_partition_split_cmd);

	install_element(VIEW_NODE, &show_range_partition_cmd);
	install_element(ENABLE_NODE, &show_range_partition_cmd);

	return 0;
}

struct cmd_node range_partition_node = {
	.node = RANGE_PARTITION_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(range-partition)# ",
	.config_write = gtp_range_partition_config_write,
};

static struct cmd_ext cmd_ext_range_partition = {
	.node = &range_partition_node,
	.install = cmd_ext_range_partition_install,
};

static void __attribute__((constructor))
gtp_range_partition_vty_init(void)
{
	cmd_ext_register(&cmd_ext_range_partition);
}
