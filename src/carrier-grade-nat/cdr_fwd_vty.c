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
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include "utils.h"
#include "command.h"
#include "list_head.h"
#include "cdr_fwd.h"

/*
 *	CDR Commands
 */
DEFUN(cdr_fwd,
      cdr_fwd_cmd,
      "cdr-fwd STRING",
      "Configure CDR Forward\n"
      "Spool name")
{
	struct cdr_fwd_entry *e;

	e = cdr_fwd_entry_get(argv[0], true);
	vty->node = CDRFWD_NODE;
	vty->index = e;
	return CMD_SUCCESS;
}

DEFUN(no_cdr_fwd,
      no_cdr_fwd_cmd,
      "no cdr-fwd STRING",
      "Destroy CDR Forward\n"
      "Spool Name")
{
	struct cdr_fwd_entry *e;

	e = cdr_fwd_entry_get(argv[0], false);
	if (!e) {
		vty_out(vty, "%% unknown cdr-fwd %s\n", argv[0]);
		return CMD_WARNING;
	}
	if (e->refcount) {
		vty_out(vty, "%% cdr-fwd %s is referenced\n", argv[0]);
		return CMD_WARNING;
	}

	cdr_fwd_entry_destroy(e);

	return CMD_SUCCESS;
}

DEFUN(cdr_spool_path,
      cdr_spool_path_cmd,
      "spool-path STRING",
      "Configure Spooling Path\n"
      "Path")
{
	struct cdr_fwd_entry *e = vty->index;

	if (e->ctx != NULL) {
		vty_out(vty, "%% cdr-fwd:%s cannot configure running instance\n",
			e->name);
		return CMD_WARNING;
	}

	bsd_strlcpy(e->cfc.spool_path, argv[0], sizeof (e->cfc.spool_path));
	return CMD_SUCCESS;
}


DEFUN(cdr_roll_period,
      cdr_roll_period_cmd,
      "roll-period <10-14400>",
      "Configure CDR Spool Roll period\n"
      "Number of seconds")
{
	struct cdr_fwd_entry *e = vty->index;
	int sec;

	if (e->ctx != NULL) {
		vty_out(vty, "%% cdr-fwd:%s cannot configure running instance\n",
			e->name);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Number of seconds", sec, argv[0], 10, 14400);
	e->cfc.roll_period = sec;
	return CMD_SUCCESS;
}

DEFUN(cdr_rr_roll_period,
      cdr_rr_roll_period_cmd,
      "rr-roll-period <60-14400>",
      "Configure Round-robin Roll period\n"
      "Number of seconds")
{
	struct cdr_fwd_entry *e = vty->index;
	int sec;

	if (e->ctx != NULL) {
		vty_out(vty, "%% cdr-fwd:%s cannot configure running instance\n",
			e->name);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Number of seconds", sec, argv[0], 60, 14400);
	e->cfc.rr_roll_period = sec;
	return CMD_SUCCESS;
}


DEFUN(cdr_lb_mode,
      cdr_lb_mode_cmd,
      "lb-mode (active-active|fail-over|round-robin)",
      "Configure Load balancing mode\n")
{
	struct cdr_fwd_entry *e = vty->index;

	if (e->ctx != NULL) {
		vty_out(vty, "%% cdr-fwd:%s cannot configure running instance\n",
			e->name);
		return CMD_WARNING;
	}

	e->cfc.lb_mode = str_to_cdr_fwd_lb_mode(argv[0]);
	if (e->cfc.lb_mode < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN(cdr_instance_id,
      cdr_instance_id_cmd,
      "instance-id <0-999>",
      "Configure Instance-id\n"
      "Instance Id")
{
	struct cdr_fwd_entry *e = vty->index;
	int i;

	if (e->ctx != NULL) {
		vty_out(vty, "%% cdr-fwd:%s cannot configure running instance\n",
			e->name);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Instance Id", i, argv[0], 0, 999);
	e->cfc.instance_id = i;
	return CMD_SUCCESS;
}


DEFUN(cdr_bind_addr,
      cdr_bind_addr_cmd,
      "bind-addr (A.B.C.D|X:X:X:X)",
      "Configure Bind addr\n"
      "Local IP")
{
	struct cdr_fwd_entry *e = vty->index;

	if (e->ctx != NULL) {
		vty_out(vty, "%% cdr-fwd:%s cannot configure running instance\n",
			e->name);
		return CMD_WARNING;
	}

	if (addr_parse(argv[0], &e->cfc.addr_ip_bound))
		return CMD_WARNING;

	return CMD_SUCCESS;
}


DEFUN(cdr_remote_addr,
      cdr_remote_addr_cmd,
      "remote (A.B.C.D|X:X:X:X)",
      "Add a remote server\n"
      "Remote IP:port")
{
	struct cdr_fwd_entry *e = vty->index;
	struct cdr_fwd_config *c = &e->cfc;
	union addr a;
	int i;

	if (e->ctx != NULL) {
		vty_out(vty, "%% cdr-fwd:%s cannot configure running instance\n",
			e->name);
		return CMD_WARNING;
	}

	if (addr_parse(argv[0], &a) || !addr_get_port(&a)) {
		vty_out(vty, "%% cannot parse remote '%s', must be ipv4/ipv6 "
			"address with port\n", argv[0]);
		return CMD_WARNING;
	}

	if (c->remote_n >= e->remote_msize) {
		e->remote_msize = (c->remote_n ?: 4) * 2;
		c->remote = realloc(c->remote, e->remote_msize *
				    sizeof (*c->remote));
	}

	for (i = 0; i < c->remote_n; i++)
		if (!addr_cmp(&c->remote[i], &a))
			return CMD_SUCCESS;

	c->remote[c->remote_n++] = a;
	return CMD_SUCCESS;
}


DEFUN(cdr_fwd_shutdown,
      cdr_fwd_shutdown_cmd,
      "shutdown",
      "Shutdown CDR fwd\n")
{
	struct cdr_fwd_entry *e = vty->index;

	if (e->ctx == NULL) {
		vty_out(vty, "%% spool:%s is already shutdown\n", e->name);
		return CMD_WARNING;
	}

	cdr_fwd_ctx_release(e->ctx);
	e->ctx = NULL;
	return CMD_SUCCESS;
}

DEFUN(cdr_fwd_no_shutdown,
      cdr_fwd_no_shutdown_cmd,
      "no shutdown",
      "Activate CDR fwd\n")
{
	struct cdr_fwd_entry *e = vty->index;

	if (e->ctx != NULL) {
		vty_out(vty, "%% spool:%s is already running\n", e->name);
		return CMD_WARNING;
	}

	if (!e->cfc.remote_n) {
		vty_out(vty, "%% remote(s) must be added\n");
		return CMD_WARNING;
	}

	e->ctx = cdr_fwd_ctx_create(&e->cfc);
	if (e->ctx == NULL)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

static void
show_entry(struct vty *vty, struct cdr_fwd_entry *e)
{
	if (e->ctx == NULL) {
		vty_out(vty, "  state: shutdown\n");
	} else {
		char buf[50000];
		cdr_fwd_ctx_dump(e->ctx, buf, sizeof (buf));
		vty_out(vty, "%s", buf);
	}
}

DEFUN(show_cdr_fwd,
      show_cdr_fwd_cmd,
      "show cdr-fwd [STRING]",
      SHOW_STR
      "CDR Fwd\n"
      "Spool name")
{
	struct cdr_fwd_entry *e;

	if (argc > 0) {
		e = cdr_fwd_entry_get(argv[0], false);
		if (!e) {
			vty_out(vty, "%% unknown cdr-fwd entry %s\n", argv[0]);
			return CMD_WARNING;
		}
		show_entry(vty, e);
	} else {
		list_for_each_entry(e, cdr_fwd_entry_get_list(), list) {
			vty_out(vty, "====== cdr-fwd %s ======\n", e->name);
			show_entry(vty, e);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}

	return CMD_SUCCESS;
}

/* Configuration writer */
static int
cdr_fwd_config_cdr_write(struct vty *vty)
{
	struct list_head *l = cdr_fwd_entry_get_list();
	struct cdr_fwd_entry *e;
	char buf[64];
	int i;

	list_for_each_entry(e, l, list) {
		vty_out(vty, "cdr-fwd %s\n", e->name);
		vty_out(vty, " spool-path %s\n", e->cfc.spool_path);
		vty_out(vty, " roll-period %d\n", e->cfc.roll_period);
		if (e->cfc.lb_mode)
			vty_out(vty, " lb-mode %s\n",
				cdr_fwd_lb_mode_to_str(e->cfc.lb_mode));
		if (e->cfc.lb_mode == CDR_FWD_MODE_ROUND_ROBIN)
			vty_out(vty, " rr-roll-period %d\n", e->cfc.rr_roll_period);
		if (e->cfc.instance_id)
			vty_out(vty, " instance-id %d\n", e->cfc.instance_id);
		if (addr_len(&e->cfc.addr_ip_bound))
			vty_out(vty, " bind-addr %s\n",
				addr_stringify_ip(&e->cfc.addr_ip_bound, buf, 64));
		for (i = 0; i < e->cfc.remote_n; i++) {
			vty_out(vty, " remote %s\n",
				addr_stringify(&e->cfc.remote[i], buf, 64));
		}
		vty_out(vty, " %sshutdown\n"
			   , e->ctx == NULL ? "" : "no ");
		vty_out(vty, "!\n");
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_cdr_fwd_install(void)
{
	/* Install CDR commands. */
	install_element(CONFIG_NODE, &cdr_fwd_cmd);
	install_element(CONFIG_NODE, &no_cdr_fwd_cmd);

	install_element(CDRFWD_NODE, &cdr_spool_path_cmd);
	install_element(CDRFWD_NODE, &cdr_roll_period_cmd);
	install_element(CDRFWD_NODE, &cdr_rr_roll_period_cmd);
	install_element(CDRFWD_NODE, &cdr_lb_mode_cmd);
	install_element(CDRFWD_NODE, &cdr_instance_id_cmd);
	install_element(CDRFWD_NODE, &cdr_bind_addr_cmd);
	install_element(CDRFWD_NODE, &cdr_remote_addr_cmd);
	install_element(CDRFWD_NODE, &cdr_fwd_shutdown_cmd);
	install_element(CDRFWD_NODE, &cdr_fwd_no_shutdown_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_cdr_fwd_cmd);
	install_element(ENABLE_NODE, &show_cdr_fwd_cmd);

	return 0;
}

struct cmd_node cdr_fwd_node = {
	.node = CDRFWD_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(cdr-fwd)# ",
	.config_write = cdr_fwd_config_cdr_write,
};

static struct cmd_ext cmd_ext_cdr = {
	.node = &cdr_fwd_node,
	.install = cmd_cdr_fwd_install,
};

static void __attribute__((constructor))
cgn_blog_vty_init(void)
{
	cmd_ext_register(&cmd_ext_cdr);
}
