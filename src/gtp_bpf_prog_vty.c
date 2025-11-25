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
#include "gtp_interface.h"
#include "command.h"
#include "bitops.h"
#include "utils.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	VTY helpers
 */
static void
_show_bpf(struct vty *vty, struct gtp_bpf_prog_obj *po)
{
	struct bpf_object *obj = po->obj;
	struct bpf_map *map;
	struct bpf_program *prg;
	bool have_tc = false, have_xdp = false;

	vty_out(vty, "    maps:\n");
	bpf_object__for_each_map(map, obj) {
		vty_out(vty, "     - %s; type=%s max_e=%d numa=%d size={k:%d v:%d}\n",
			bpf_map__name(map),
			libbpf_bpf_map_type_str(bpf_map__type(map)),
			bpf_map__max_entries(map),
			bpf_map__numa_node(map),
			bpf_map__key_size(map),
			bpf_map__value_size(map));
	}

	vty_out(vty, "    programs:\n");
	bpf_object__for_each_program(prg, obj) {
		char loaded = '-';
		switch (bpf_program__expected_attach_type(prg)) {
		case BPF_XDP:
			if (!have_xdp &&
			    (!po->xdp_progname[0] ||
			     !strcmp(bpf_program__name(prg), po->xdp_progname))) {
				have_xdp = true;
				loaded = '*';
			}
			break;
		case BPF_TCX_INGRESS:
			if (!have_tc &&
			    (!po->tc_progname[0] ||
			     !strcmp(bpf_program__name(prg), po->tc_progname))) {
				have_tc = true;
				loaded = '*';
			}
			break;
		default:
			break;
		}

		vty_out(vty, "     %c %s; type=%s attach=%s instr:%ld\n",
			loaded,
			bpf_program__name(prg),
			libbpf_bpf_prog_type_str(bpf_program__type(prg)),
			libbpf_bpf_attach_type_str(bpf_program__expected_attach_type(prg)),
			bpf_program__insn_cnt(prg));
	}
}

static int
gtp_bpf_prog_show(struct gtp_bpf_prog *p, void *arg)
{
	struct gtp_interface *iface;
	struct vty *vty = arg;
	char buf[64];
	int i;

	vty_out(vty, "gtp-program '%s':\n", p->name);
	vty_out(vty, "  flags               :");
	if (p->flags & GTP_BPF_PROG_FL_SHUTDOWN_BIT)
		vty_out(vty, " no_shutdown");
	if (p->flags & GTP_BPF_PROG_FL_LOAD_PREPARED_BIT)
		vty_out(vty, " load_prepared");
	if (p->flags & GTP_BPF_PROG_FL_LOAD_ERR_BIT)
		vty_out(vty, " load_error");
	vty_out(vty, "\r\n");
	vty_out(vty, "  path                : %s", p->path);
	if (p->watch_id)
		vty_out(vty, ", inotify watch %d", p->watch_id);
	vty_out(vty, "%s  template modes      :\n", VTY_NEWLINE);
	for (i = 0; i < p->tpl_n; i++)
		vty_out(vty, "    - %s\n", p->tpl[i]->description);
	if (p->load.obj) {
		vty_out(vty, "  opened bpf          :\n");
		_show_bpf(vty, &p->load);
	}
	if (p->run.obj) {
		vty_out(vty, "  running bpf         :\n");
		_show_bpf(vty, &p->run);
	}
	vty_out(vty, "  attached interfaces :\n");
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		if (iface->flags & GTP_INTERFACE_FL_SHUTDOWN_BIT)
			sprintf(buf, "interface down");
		else if (iface->bpf_prog == p)
			sprintf(buf, "bpf running");
		else
			sprintf(buf, "bpf not loaded");
		vty_out(vty, "     - %s; %s\n", iface->ifname, buf);
	}
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
	return CMD_SUCCESS;
}

DEFUN(no_bpf_prog,
      no_bpf_prog_cmd,
      "no bpf-program STRING",
      "Configure BPF Program data\n"
      "Program name\n")
{
	struct gtp_bpf_prog *p;

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_bpf_prog_put(p);
	gtp_bpf_prog_destroy(p);

	return CMD_SUCCESS;
}

DEFUN(bpf_prog_description,
      bpf_prog_description_cmd,
      "description STRING",
      "Set BPF Program description\n"
      "description\n")
{
	struct gtp_bpf_prog *p = vty->index;

	snprintf(p->description, sizeof (p->description), "%s", argv[0]);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_path,
      bpf_prog_path_cmd,
      "path STRING",
      "Set BPF Program path\n"
      "path\n")
{
	struct gtp_bpf_prog *p = vty->index;

	snprintf(p->path, sizeof (p->path), "%s", argv[0]);
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
		bsd_strlcpy(p->load.xdp_progname, argv[1], GTP_STR_MAX_LEN - 1);
	else
		bsd_strlcpy(p->load.tc_progname, argv[1], GTP_STR_MAX_LEN - 1);
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

DEFUN(show_bpf_interface_rule,
      show_bpf_interface_rule_cmd,
      "show interface-rule (all|input|output) [BPFPROG]",
      SHOW_STR
      "Interface rules\n"
      "Show installed rules\n"
      "Show all rules, with more details\n"
      "Specific bpf program\n")
{
	struct gtp_bpf_prog *p = NULL;

	if (argc >= 2) {
		p = gtp_bpf_prog_get(argv[1]);
		if (!p) {
			vty_out(vty, "%% Unknown bpf-prog:'%s'%s", argv[1], VTY_NEWLINE);
			return CMD_WARNING;
		}

		if (!strcmp(argv[0], "installed"))
			gtp_interface_rule_show(p, vty);
		else
			gtp_interface_rule_show_stored(p, vty);
		return CMD_SUCCESS;
	}

	gtp_bpf_prog_foreach_prog(!strcmp(argv[0], "input") ?
				  gtp_interface_rule_show :
				  !strcmp(argv[0], "output") ?
				  gtp_interface_rule_show_attr :
				  gtp_interface_rule_show_stored,
				  vty, "if_rules");

	return CMD_SUCCESS;
}


DEFUN(bpf_prog_shutdown,
      bpf_prog_shutdown_cmd,
      "shutdown",
      "Unload BPF program\n")
{
	struct gtp_bpf_prog *p = vty->index;

	if (__test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags))
		return CMD_SUCCESS;

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

	if (!__test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags)) {
		vty_out(vty, "%% bpf-program:'%s' is already running%s"
			   , p->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags);
	if (gtp_bpf_prog_load(p) < 0)
		return CMD_WARNING;
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
		if (p->load.xdp_progname[0])
			vty_out(vty, " prog-name xdp %s%s", p->load.xdp_progname, VTY_NEWLINE);
		if (p->load.tc_progname[0])
			vty_out(vty, " prog-name tc %s%s", p->load.tc_progname, VTY_NEWLINE);
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
	install_element(VIEW_NODE, &show_bpf_interface_rule_cmd);
	install_element(ENABLE_NODE, &show_bpf_interface_rule_cmd);

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
