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
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netdb.h>
#include <resolv.h>
#include <fnmatch.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int bpf_prog_config_write(vty_t *vty);
cmd_node_t bpf_prog_node = {
	.node = BPF_PROG_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(bpf-program)# ",
	.config_write = bpf_prog_config_write,
};


/*
 *	VTY helpers
 */
static int
gtp_bpf_prog_show(gtp_bpf_prog_t *p, void *arg)
{
	vty_t *vty = arg;

	vty_out(vty, "gtp-program '%s' [%s] %s %s%s"
		   , p->name, p->path
		   , __test_bit(GTP_BPF_PROG_FL_RT_BIT, &p->flags) ? "route" : "forward"
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
	gtp_bpf_prog_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_bpf_prog_get(argv[0]);
	if (new) {
		vty->node = APN_NODE;
		vty->index = new;
		gtp_bpf_prog_put(new);
		return CMD_SUCCESS;
	}

	new = gtp_bpf_prog_alloc(argv[0]);
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
	gtp_bpf_prog_t *p;
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

DEFUN(bpf_prog_desciption,
      bpf_prog_description_cmd,
      "description STRING",
      "Set BPF Program description\n"
      "description\n")
{
	gtp_bpf_prog_t *p = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(p->description, argv[0], GTP_PATH_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_path,
      bpf_prog_path_cmd,
      "path STRING",
      "Set BPF Program path\n"
      "path\n")
{
	gtp_bpf_prog_t *p = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(p->path, argv[0], GTP_PATH_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_progname,
      bpf_prog_progname_cmd,
      "prog-name STRING",
      "Set BPF Program name\n"
      "name\n")
{
	gtp_bpf_prog_t *p = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(p->progname, argv[0], GTP_PATH_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_mode_rt,
      bpf_prog_mode_rt_cmd,
      "mode-gtp-route",
      "Use GTP Routing mode\n")
{
	gtp_bpf_prog_t *p = vty->index;

	if (__test_bit(GTP_BPF_PROG_FL_FWD_BIT, &p->flags)) {
		vty_out(vty, "%% bpf-program:'%s' already in 'mode-gtp-forward'%s"
			   , p->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(GTP_BPF_PROG_FL_RT_BIT, &p->flags);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_mode_proxy,
      bpf_prog_mode_proxy_cmd,
      "mode-gtp-forward",
      "Use GTP Forward/Proxy mode\n")
{
	gtp_bpf_prog_t *p = vty->index;

	if (__test_bit(GTP_BPF_PROG_FL_RT_BIT, &p->flags)) {
		vty_out(vty, "%% bpf-program:'%s' already in 'mode-gtp-route'%s"
			   , p->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(GTP_BPF_PROG_FL_FWD_BIT, &p->flags);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_shutdown,
      bpf_prog_shutdown_cmd,
      "shutdown",
      "Unload BPF program\n")
{
	gtp_bpf_prog_t *p = vty->index;

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
      "Load BPF program\n")
{
	gtp_bpf_prog_t *p = vty->index;
	int err;

	if (!__test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags)) {
		vty_out(vty, "%% bpf-program:'%s' is already running%s"
			   , p->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = gtp_bpf_prog_load(p);
	if (err) {
		vty_out(vty, "%% unable to load bpf-program:'%s'%s"
			   , p->path, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_BPF_PROG_FL_RT_BIT, &p->flags))
		err = gtp_bpf_rt_load_maps(p);
	else if (__test_bit(GTP_BPF_PROG_FL_FWD_BIT, &p->flags))
		err = gtp_bpf_fwd_load_maps(p);
	else {
		vty_out(vty, "%% you MUST specify 'mode-gtp-route' or 'mode-gtp-forward'"
			     " for bpf_program:'%s'%s"
			   , p->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (err) {
		vty_out(vty, "%% unable to load maps from bpf-program:'%s'%s"
			   , p->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "Success loading bpf-programs:'%s'%s"
		   , p->name, VTY_NEWLINE);
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
	gtp_bpf_prog_t *p = NULL;

	if (argc >= 1) {
		p = gtp_bpf_prog_get(argv[0]);
		if (!p) {
			vty_out(vty, "%% Unknown bpf-program:%s%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}

		gtp_bpf_prog_show(p, vty);
		gtp_bpf_prog_put(p);
		return CMD_SUCCESS;
	}

	gtp_bpf_prog_foreach_prog(gtp_bpf_prog_show, vty);
	return CMD_SUCCESS;
}




/* Configuration writer */
static int
bpf_prog_config_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->bpf_progs;
	gtp_bpf_prog_t *p;

	list_for_each_entry(p, l, next) {
		vty_out(vty, "bpf-program %s%s", p->name, VTY_NEWLINE);
		if (p->description[0])
			vty_out(vty, " description %s%s", p->description, VTY_NEWLINE);
		vty_out(vty, " path %s%s", p->path, VTY_NEWLINE);
		if (p->progname[0])
			vty_out(vty, " prog-name %s%s", p->progname, VTY_NEWLINE);
		if (__test_bit(GTP_BPF_PROG_FL_RT_BIT, &p->flags))
			vty_out(vty, " mode-gtp-route%s", VTY_NEWLINE);
		if (__test_bit(GTP_BPF_PROG_FL_FWD_BIT, &p->flags))
			vty_out(vty, " mode-gtp-forward%s", VTY_NEWLINE);
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
int
gtp_bpf_prog_vty_init(void)
{
	/* Install BPF_PROG commands. */
	install_node(&bpf_prog_node);
	install_element(CONFIG_NODE, &bpf_prog_cmd);
	install_element(CONFIG_NODE, &no_bpf_prog_cmd);

	install_default(BPF_PROG_NODE);
	install_element(BPF_PROG_NODE, &bpf_prog_description_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_path_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_progname_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_mode_rt_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_mode_proxy_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_no_shutdown_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_bpf_prog_cmd);
	install_element(ENABLE_NODE, &show_bpf_prog_cmd);

	return 0;
}
