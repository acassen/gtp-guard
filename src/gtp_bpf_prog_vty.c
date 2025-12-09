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

#include <unistd.h>
#include <bpf.h>

#include "logger.h"
#include "command.h"
#include "bitops.h"
#include "utils.h"
#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	VTY helpers
 */
static void
_show_bpf(struct vty *vty, struct gtp_bpf_prog *p, struct bpf_object *obj)
{
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
			    (!p->xdp_progname[0] ||
			     !strcmp(bpf_program__name(prg), p->xdp_progname))) {
				have_xdp = true;
				loaded = '*';
			}
			break;
		case BPF_TCX_INGRESS:
			if (!have_tc &&
			    (!p->tc_progname[0] ||
			     !strcmp(bpf_program__name(prg), p->tc_progname))) {
				have_tc = true;
				loaded = '*';
			}
			break;
		default:
			loaded = '?';
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
_get_prg_info(struct bpf_link *lnk, struct bpf_prog_info *info)
{
	struct bpf_link_info lnk_info = {};
	uint32_t info_len = sizeof(*info);
	int ret, fd;

	if (lnk == NULL)
		return 0;

	info_len = sizeof(lnk_info);
	ret = bpf_link_get_info_by_fd(bpf_link__fd(lnk), &lnk_info, &info_len);
	if (ret < 0) {
		log_message(LOG_INFO, "bpf_link_get_info_by_fd: %m");
		return 0;
	}

	fd = bpf_prog_get_fd_by_id(lnk_info.prog_id);
	if (fd < 0) {
		log_message(LOG_INFO, "bpf_prog_get_fd_by_id: %m");
		return 0;
	}

	memset(info, 0x00, sizeof (*info));
	info_len = sizeof(*info);
	ret = bpf_prog_get_info_by_fd(fd, info, &info_len);
	if (ret < 0) {
		log_message(LOG_INFO, "bpf_prog_get_info_by_fd: %m");
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}

static int
gtp_bpf_prog_show(struct gtp_bpf_prog *p, void *arg)
{
	struct gtp_interface *iface;
	struct bpf_prog_info pi;
	struct vty *vty = arg;
	char buf[64];
	int i, k;

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
	if (p->obj_load) {
		vty_out(vty, "  opened bpf          :\n");
		_show_bpf(vty, p, p->obj_load);
	}
	if (p->obj_run) {
		vty_out(vty, "  running bpf         :\n");
		_show_bpf(vty, p, p->obj_run);
	}
	vty_out(vty, "  attached interfaces :\n");
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		if (iface->flags & GTP_INTERFACE_FL_SHUTDOWN_BIT)
			snprintf(buf, sizeof(buf), "interface down");
		else if (!iface->bpf_prog)
			snprintf(buf, sizeof(buf), "bpf not loaded");
		else if (iface->bpf_prog != p)
			snprintf(buf, sizeof(buf), "!!! bpf load BUG !!!");
		else {
			k = scnprintf(buf, sizeof (buf), "bpf run");
			if (_get_prg_info(iface->bpf_xdp_lnk, &pi)) {
				k += snprintf(buf + k, sizeof (buf) - k,
					      " xdp=%s", pi.name);
			}
			if (_get_prg_info(iface->bpf_tc_lnk, &pi)) {
				k += snprintf(buf + k, sizeof (buf) - k,
					      " tcx=%s", pi.name);
			}
		}
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
      "Set default bpf program name\n"
      "XDP program\n"
      "TC program on ingress\n"
      "Program name\n")
{
	struct gtp_bpf_prog *p = vty->index;

	if (!strcmp(argv[0], "xdp"))
		snprintf(p->xdp_progname, sizeof (p->xdp_progname), "%s", argv[1]);
	else
		snprintf(p->tc_progname, sizeof (p->tc_progname), "%s", argv[1]);
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
      "show interface-rule (all|input|output)",
      SHOW_STR
      "Interface rules\n"
      "Show installed rules\n"
      "Show all rules, with more details\n")
{
	gtp_bpf_prog_foreach_vty("if_rules", vty, argc, argv);
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

	if (!__test_bit(GTP_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags) && p->obj_run) {
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
