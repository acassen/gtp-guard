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

#include "gtp_data.h"
#include "gtp_ip_pool.h"
#include "ip_pool.h"
#include "command.h"
#include "bitops.h"
#include "table.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Command
 */
DEFUN(ip_pool,
      ip_pool_cmd,
      "ip pool WORD",
      "Configure IP Pool\n"
      "Pool Name")
{
	struct gtp_ip_pool *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = gtp_ip_pool_get(argv[0]);
	if (!new)
		new = gtp_ip_pool_alloc(argv[0]);

	vty->node = IP_POOL_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_ip_pool,
      no_ip_pool_cmd,
      "no ip pool WORD",
      "Destroy IP Pool\n"
      "Pool Name")
{
	struct gtp_ip_pool *p;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	p = gtp_ip_pool_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown ip-pool '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (p->refcnt) {
		vty_out(vty, "%% ip-pool '%s' is inuse... cant release pool inuse%s"
			   , p->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_ip_pool_free(p);

	return CMD_SUCCESS;
}

DEFUN(ip_pool_description,
      ip_pool_description_cmd,
      "description WORD",
      "IP Pool Description\n"
      "Description String")
{
	struct gtp_ip_pool *p = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strncat(p->description, argv[0], GTP_STR_MAX_LEN - 1);

	return CMD_SUCCESS;
}

DEFUN(ip_pool_prefix,
      ip_pool_prefix_cmd,
      "prefix ADDR",
      "IP prefix defining Pool range\n"
      "prefix String in form of (A.B.C.D|X:X::X:X)/P")
{
	struct gtp_ip_pool *p = vty->index;
	struct ip_pool *pool;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (p->pool) {
		vty_out(vty, "%% ip-pool:'%s' prefix already configured%s"
	  		   , p->name
	  		   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	pool = ip_pool_alloc(argv[0]);
	if (!pool) {
		vty_out(vty, "%% unable to create pool for:'%s'%s"
	  		   , argv[0]
	  		   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	p->pool = pool;
	return CMD_SUCCESS;
}

DEFUN(ip_pool_no_prefix,
      ip_pool_no_prefix_cmd,
      "no prefix",
      "Desactivate IP Pool prefix")
{
	struct gtp_ip_pool *p = vty->index;

	if (!p->pool) {
		vty_out(vty, "%% ip-pool:'%s' no prefix configured%s"
	  		   , p->name
	  		   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ip_pool_destroy(p->pool);
	p->pool = NULL;

	return CMD_SUCCESS;
}

DEFUN(ip_pool_shutdown,
      ip_pool_shutdown_cmd,
      "shutdown",
      "Shutdown IP Pool\n")
{
	struct gtp_ip_pool *p = vty->index;

	if (__test_bit(GTP_IP_POOL_FL_SHUTDOWN, &p->flags)) {
		vty_out(vty, "%% ip-pool:'%s' is already shutdown%s"
			   , p->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(GTP_IP_POOL_FL_SHUTDOWN, &p->flags);
	return CMD_SUCCESS;
}

DEFUN(ip_pool_no_shutdown,
      ip_pool_no_shutdown_cmd,
      "no shutdown",
      "Activate IP Pool\n")
{
	struct gtp_ip_pool *p = vty->index;

	if (!__test_bit(GTP_IP_POOL_FL_SHUTDOWN, &p->flags)) {
		vty_out(vty, "%% ip-pool:'%s' is already activated%s"
			   , p->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(GTP_IP_POOL_FL_SHUTDOWN, &p->flags);
	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
DEFUN(show_ip_pool,
      show_ip_pool_cmd,
      "show ip pool [STRING]",
      SHOW_STR
      "IP Pool\n"
      "Pool name")
{
	struct gtp_ip_pool *p;
	const char *name = NULL;
	struct table *tbl;
	struct ip_pool *pool;
	char addr_str[INET6_ADDRSTRLEN];

	if (list_empty(&daemon_data->ip_pool)) {
		vty_out(vty, "%% No ip-pool configured...");
		return CMD_SUCCESS;
	}

	if (argc == 1)
		name = argv[0];

	tbl = table_init(6, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "Name", "Prefix", "inuse", "total",
			 "% used", "% fill-up");
	table_set_column_align(tbl, ALIGN_CENTER, ALIGN_RIGHT,
			       ALIGN_RIGHT, ALIGN_RIGHT,
			       ALIGN_RIGHT, ALIGN_RIGHT);

	list_for_each_entry(p, &daemon_data->ip_pool, next) {
		if (name && !strstr(p->name, name))
			continue;

		pool = p->pool;
		table_add_row_fmt(tbl, "%s|%s/%d|%u|%u|%.2f%%|%.2f%%"
				     , p->name
				     , addr_stringify(&pool->prefix, addr_str, INET6_ADDRSTRLEN)
				     , pool->prefix_bits
				     , pool->used
				     , pool->size
				     , (pool->used * 100.0) / pool->size
				     , (pool->next_lease_idx * 100.0) / pool->size);
	}
	table_vty_out(tbl, vty);
	table_destroy(tbl);

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
gtp_config_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->ip_pool;
	struct gtp_ip_pool *p;
	char addr_str[INET6_ADDRSTRLEN];

	list_for_each_entry(p, l, next) {
		vty_out(vty, "ip pool %s%s", p->name, VTY_NEWLINE);
		if (p->description[0])
			vty_out(vty, " description %s%s"
	   			   , p->description, VTY_NEWLINE);
		if (p->pool)
			vty_out(vty, " prefix %s/%d%s"
				   , addr_stringify_ip(&p->pool->prefix, addr_str,
						       INET6_ADDRSTRLEN)
				   , p->pool->prefix_bits
				   , VTY_NEWLINE);
		vty_out(vty, " %sshutdown%s"
			   , __test_bit(GTP_IP_POOL_FL_SHUTDOWN, &p->flags) ? "" : "no "
			   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_ip_pool_install(void)
{
	/* Install PDN commands. */
	install_element(CONFIG_NODE, &ip_pool_cmd);
	install_element(CONFIG_NODE, &no_ip_pool_cmd);

	install_default(IP_POOL_NODE);
	install_element(IP_POOL_NODE, &ip_pool_description_cmd);
	install_element(IP_POOL_NODE, &ip_pool_prefix_cmd);
	install_element(IP_POOL_NODE, &ip_pool_no_prefix_cmd);
	install_element(IP_POOL_NODE, &ip_pool_shutdown_cmd);
	install_element(IP_POOL_NODE, &ip_pool_no_shutdown_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_ip_pool_cmd);
	install_element(ENABLE_NODE, &show_ip_pool_cmd);

	return 0;
}

struct cmd_node ip_pool_node = {
	.node = IP_POOL_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(ip-pool)# ",
	.config_write = gtp_config_write,
};

static struct cmd_ext cmd_ext_ip_pool = {
	.node = &ip_pool_node,
	.install = cmd_ext_ip_pool_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_ip_pool);
}
