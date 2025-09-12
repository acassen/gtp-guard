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
#include "gtp_bpf_prog.h"
#include "command.h"
#include "bitops.h"
#include "utils.h"
#include "logger.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	VTY helpers
 */
static int
gtp_bpf_prog_show(struct gtp_bpf_prog *p, void *arg)
{
	struct vty *vty = arg;
	int i;

	vty_out(vty, "gtp-program '%s' [%s] "
		   , p->name, p->path);
	if (p->tpl_n)
	for (i = 0; i < p->tpl_n; i++)
		vty_out(vty, "%s%s", p->tpl[i]->description, i - 1 < p->tpl_n ? "," : "");
	vty_out(vty, " %s%s"
		   , __test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags) ? "unloaded" : "loaded"
		   , VTY_NEWLINE);
	return 0;
}


/*
 *	VTY command
 */
DEFUN(bpf_prog,
      bpf_prog_cmd,
      "bpf-program STRING",
      "Configure BPF Program data\n"
      "Program name\n")
{
	struct gtp_bpf_prog *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_bpf_prog_get(argv[0]);
	if (new) {
		vty->node = BPF_PROG_NODE;
		vty->index = new;
		gtp_bpf_prog_put(new);
		return CMD_SUCCESS;
	}

	new = gtp_bpf_prog_alloc(argv[0]);
	if (!new) {
		vty_out(vty, "%% Error allocating bpf-program:%s !!!%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = BPF_PROG_NODE;
	vty->index = new;
	__set_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &new->flags);
	return CMD_SUCCESS;
}

DEFUN(no_bpf_prog,
      no_bpf_prog_cmd,
      "no bpf-program STRING",
      "Configure BPF Program data\n"
      "Program name\n")
{
	struct gtp_bpf_prog *p;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_bpf_prog_put(p);
	err = gtp_bpf_prog_destroy(p);
	if (err) {
		vty_out(vty, "%% bpf-program:'%s' is used by at least one interface%s"
			   , p->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(bpf_prog_description,
      bpf_prog_description_cmd,
      "description STRING",
      "Set BPF Program description\n"
      "description\n")
{
	struct gtp_bpf_prog *p = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(p->description, argv[0], GTP_STR_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_path,
      bpf_prog_path_cmd,
      "path STRING",
      "Set BPF Program path\n"
      "path\n")
{
	struct gtp_bpf_prog *p = vty->index;
	int err;

	bsd_strlcpy(p->path, argv[0], GTP_PATH_MAX_LEN - 1);

	/* we need to open bpf file as soon as possible (when we have
	 * filename) to setup prog template and prog udata memory */
	err = gtp_bpf_prog_open(p);
	if (err) {
		vty_out(vty, "%% unable to open bpf-program:'%s'%s"
			   , p->path, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(bpf_prog_progname,
      bpf_prog_progname_cmd,
      "prog-name (xdp|tc) NAME",
      "Set BPF Program name\n"
      "name\n")
{
	struct gtp_bpf_prog *p = vty->index;

	if (!strcmp(argv[0], "xdp"))
		bsd_strlcpy(p->xdp_progname, argv[0], GTP_STR_MAX_LEN - 1);
	else
		bsd_strlcpy(p->tc_progname, argv[0], GTP_STR_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_shutdown,
      bpf_prog_shutdown_cmd,
      "shutdown",
      "Unload BPF program\n")
{
	struct gtp_bpf_prog *p = vty->index;

	if (__test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags)) {
		vty_out(vty, "%% bpf-program:'%s' is already shutdown%s"
			   , p->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_bpf_prog_unload(p);
	__set_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_no_shutdown,
      bpf_prog_no_shutdown_cmd,
      "no shutdown",
      "Open and load BPF program\n")
{
	struct gtp_bpf_prog *p = vty->index;
	int err;

	if (!__test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags)) {
		vty_out(vty, "%% bpf-program:'%s' is already running%s"
			   , p->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = gtp_bpf_prog_open(p);
	if (err) {
		vty_out(vty, "%% unable to open bpf-program:'%s'%s"
			   , p->path, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags);
	return CMD_SUCCESS;
}


/* Show */
DEFUN(show_bpf_prog,
      show_bpf_prog_cmd,
      "show bpf-program [STRING]",
      SHOW_STR
      "BPF Progam\n")
{
	struct gtp_bpf_prog *p = NULL;

	if (!argc) {
		gtp_bpf_prog_foreach_prog(gtp_bpf_prog_show, vty, NULL);
		return CMD_SUCCESS;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% Unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_bpf_prog_show(p, vty);
	gtp_bpf_prog_put(p);
	return CMD_SUCCESS;
}



/* Configuration writer */
static int
bpf_prog_config_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->bpf_progs;
	struct gtp_bpf_prog *p;

	list_for_each_entry(p, l, next) {
		vty_out(vty, "bpf-program %s%s", p->name, VTY_NEWLINE);
		if (p->description[0])
			vty_out(vty, " description %s%s", p->description, VTY_NEWLINE);
		vty_out(vty, " path %s%s", p->path, VTY_NEWLINE);
		if (p->xdp_progname[0])
			vty_out(vty, " prog-name xdp %s%s", p->xdp_progname, VTY_NEWLINE);
		if (p->tc_progname[0])
			vty_out(vty, " prog-name tc %s%s", p->tc_progname, VTY_NEWLINE);
  		vty_out(vty, " %sshutdown%s"
			   , __test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags) ? "" : "no "
			   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_bpf_prog_install(void)
{
	/* Install BPF_PROG commands. */
	install_element(CONFIG_NODE, &bpf_prog_cmd);
	install_element(CONFIG_NODE, &no_bpf_prog_cmd);

	install_default(BPF_PROG_NODE);
	install_element(BPF_PROG_NODE, &bpf_prog_description_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_path_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_progname_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_shutdown_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_no_shutdown_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_bpf_prog_cmd);
	install_element(ENABLE_NODE, &show_bpf_prog_cmd);

	return 0;
}

struct cmd_node bpf_prog_node = {
	.node = BPF_PROG_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(bpf-program)# ",
	.config_write = bpf_prog_config_write,
};

static struct cmd_ext cmd_ext_bpf_prog = {
	.node = &bpf_prog_node,
	.install = cmd_ext_bpf_prog_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_bpf_prog);
}
