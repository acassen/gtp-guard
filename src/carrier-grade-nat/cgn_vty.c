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

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


static int config_cgn_write(vty_t *);
cmd_node_t cgn_node = {
	.node = CGN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(carrier-grade-nat)# ",
	.config_write = config_cgn_write,
};

/*
 *	Carrier-Grade-NAT Commands
 */
DEFUN(cgn,
      cgn_cmd,
      "carrier-grade-nat STRING",
      "Configure Carrier-Grade-NAT Instance\n"
      "CGN Instance Name")
{
	cgn_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = cgn_get_by_name(argv[0]);
	if (new) {
		vty->node = CGN_NODE;
		vty->index = new;
		return CMD_SUCCESS;
	}

	new = cgn_alloc(argv[0]);
	if (!new) {
		vty_out(vty, "%% Error allocating carrier-grade-nat:%s !!!%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = CGN_NODE;
	vty->index = new;
	__set_bit(CGN_FL_SHUTDOWN_BIT, &new->flags);
	return CMD_SUCCESS;
}

DEFUN(no_cgn,
      no_cgn_cmd,
      "no carrier-grade-nat STRING",
      "Destroy Carrier-Grade-NAT Instance\n"
      "Instance Name")
{
	cgn_t *c;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	c = cgn_get_by_name(argv[0]);
	if (!c) {
		vty_out(vty, "%% unknown carrier-grade-nat instance %s%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	cgn_release(c);
	return CMD_SUCCESS;
}

DEFUN(cgn_desciption,
      cgn_description_cmd,
      "description STRING",
      "Set Carrier-Grade-NAT description\n"
      "description\n")
{
	cgn_t *c = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(c->description, argv[0], GTP_PATH_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(cgn_shutdown,
      cgn_shutdown_cmd,
      "shutdown",
      "Desactivate Carrier Grade NAT instance\n")
{
	cgn_t *c = vty->index;

	if (__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' is already shutdown%s"
			   , c->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	/*... Stop stuffs ...*/

	__set_bit(CGN_FL_SHUTDOWN_BIT, &c->flags);
	return CMD_SUCCESS;
}

DEFUN(cgn_no_shutdown,
      cgn_no_shutdown_cmd,
      "no shutdown",
      "Activate Carrier Grade NAT instance\n")
{
	cgn_t *c = vty->index;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' is already running%s"
			   , c->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}


	/*... Start stuffs ...
	 *
	 * To submit I/O MUX : scheduler.h :
	 *   thread_add_event(master, ....);
	 *   thread_add_read(master, ...);
	 *   thread_add_write(master, ...);
	 *   thread_add_timer(master, ...);
	 */

	__clear_bit(CGN_FL_SHUTDOWN_BIT, &c->flags);
	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static int
cgn_vty(vty_t *vty, cgn_t *c)
{
	if (!c)
		return -1;

	vty_out(vty, " carrier-grate-nat(%s): '%s'%s"
		   , c->name
		   , c->description
		   , VTY_NEWLINE);
	return 0;
}

DEFUN(show_cgn,
      show_cgn_cmd,
      "show carrier-grade-nat [STRING]",
      SHOW_STR
      "Carrier Grade NAT\n"
      "Instance name")
{
	cgn_t *c;
	const char *name = NULL;

	if (list_empty(&daemon_data->cgn)) {
		vty_out(vty, "%% No carrier-grade-nat instance configured...");
		return CMD_SUCCESS;
	}

	if (argc == 1)
		name = argv[0];

	list_for_each_entry(c, &daemon_data->cgn, next) {
		if (name && strncmp(c->name, name, GTP_NAME_MAX_LEN))
			continue;

		cgn_vty(vty, c);
	}

	return CMD_SUCCESS;
}

/*
 *	Configuration writer
 */
static int
config_cgn_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->cgn;
	cgn_t *c;

	list_for_each_entry(c, l, next) {
		vty_out(vty, "carrier-grade-nat %s%s", c->name, VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
cgn_vty_init(void)
{
	/* Install Carrier Grade NAT commands. */
	install_node(&cgn_node);
	install_element(CONFIG_NODE, &cgn_cmd);
	install_element(CONFIG_NODE, &no_cgn_cmd);

	install_default(CGN_NODE);
	install_element(CGN_NODE, &cgn_description_cmd);
	install_element(CGN_NODE, &cgn_shutdown_cmd);
	install_element(CGN_NODE, &cgn_no_shutdown_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_cgn_cmd);
	install_element(ENABLE_NODE, &show_cgn_cmd);

	return 0;
}
