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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com> 
 */

#include "gtp_data.h"
#include "pfcp_router.h"
#include "command.h"
#include "bitops.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	PFCP commands
 */
DEFUN(pfcp_router,
      pfcp_router_cmd,
      "pfcp-router STRING",
      "Configure PFCP Router Instance\n"
      "PFCP Instance Name")
{
	pfcp_router_t *c;

	c = pfcp_router_get_by_name(argv[0]);
	if (c == NULL) {
		c = pfcp_router_alloc(argv[0]);
		__set_bit(PFCP_ROUTER_FL_SHUTDOWN_BIT, &c->flags);
	}
	vty->node = PFCP_ROUTER_NODE;
	vty->index = c;

	return CMD_SUCCESS;
}

DEFUN(no_pfcp_router,
      no_pfcp_router_cmd,
      "no pfcp-router STRING",
      "Destroy PFCP Router Instance\n"
      "Instance Name")
{
	pfcp_router_t *c;

	/* Already existing ? */
	c = pfcp_router_get_by_name(argv[0]);
	if (c == NULL) {
		vty_out(vty, "%% unknown pfcp-router instance '%s'",
			argv[0]);
		return CMD_WARNING;
	}
	pfcp_router_release(c);

	return CMD_SUCCESS;
}

DEFUN(pfcp_router_desciption,
      pfcp_router_description_cmd,
      "description STRING",
      "Set PFCP Router description\n"
      "description\n")
{
	pfcp_router_t *c = vty->index;

	snprintf(c->description, GTP_STR_MAX_LEN, "%s", argv[0]);

	return CMD_SUCCESS;
}

DEFUN(pfcp_router_shutdown,
      pfcp_router_shutdown_cmd,
      "shutdown",
      "Desactivate PFCP Router instance\n")
{
	pfcp_router_t *c = vty->index;

	if (__test_bit(PFCP_ROUTER_FL_SHUTDOWN_BIT, &c->flags))
		return CMD_WARNING;

	/*... Stop stuffs ...*/

	__set_bit(PFCP_ROUTER_FL_SHUTDOWN_BIT, &c->flags);

	return CMD_SUCCESS;
}

DEFUN(pfcp_router_no_shutdown,
      pfcp_router_no_shutdown_cmd,
      "no shutdown",
      "Activate PFCP Router instance\n")
{
	pfcp_router_t *c = vty->index;

	if (!__test_bit(PFCP_ROUTER_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% pfcp-router:'%s' is already running\n",
			c->name);
		return CMD_WARNING;
	}


	/* TODO: ... Start stuffs here ... */

	__clear_bit(PFCP_ROUTER_FL_SHUTDOWN_BIT, &c->flags);

	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static int
pfcp_vty(vty_t *vty, pfcp_router_t *c)
{
	char buf[4096];

	vty_out(vty, " pfcp-router(%s): '%s'\n",
		c->name, c->description);

	pfcp_router_dump(c, buf, sizeof (buf));
	vty_out(vty, "%s", buf);

	return 0;
}

DEFUN(show_pfcp_router,
      show_pfcp_router_cmd,
      "show pfcp-router [STRING]",
      SHOW_STR
      "PFCP Router\n"
      "Instance name")
{
	pfcp_router_t *c;
	const char *name = NULL;

	if (list_empty(&daemon_data->pfcp_router_ctx)) {
		vty_out(vty, "%% No pfcp-router instance configured...");
		return CMD_SUCCESS;
	}

	if (argc == 1)
		name = argv[0];

	list_for_each_entry(c, &daemon_data->pfcp_router_ctx, next) {
		if (name != NULL && strncmp(c->name, name, GTP_NAME_MAX_LEN))
			continue;

		pfcp_vty(vty, c);
	}

	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static int
config_pfcp_router_write(vty_t *vty)
{
	struct list_head *l = &daemon_data->pfcp_router_ctx;
	pfcp_router_t *c;

	list_for_each_entry(c, l, next) {
		vty_out(vty, "pfcp-router %s\n", c->name);
		if (c->description[0])
			vty_out(vty, " description %s\n", c->description);
  		vty_out(vty, " %sshutdown\n"
	    		   , __test_bit(PFCP_ROUTER_FL_SHUTDOWN_BIT, &c->flags) ? "" : "no ");
		vty_out(vty, "!\n");
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_pfcp_router_install(void)
{
	/* Install PFCP Router commands. */
	install_element(CONFIG_NODE, &pfcp_router_cmd);
	install_element(CONFIG_NODE, &no_pfcp_router_cmd);

	install_default(PFCP_ROUTER_NODE);
	install_element(PFCP_ROUTER_NODE, &pfcp_router_description_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_router_shutdown_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_router_no_shutdown_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_pfcp_router_cmd);
	install_element(ENABLE_NODE, &show_pfcp_router_cmd);

	return 0;
}

cmd_node_t pfcp_router_node = {
	.node = PFCP_ROUTER_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(pfcp)# ",
	.config_write = config_pfcp_router_write,
};

static cmd_ext_t cmd_ext_pfcp_router = {
	.node = &pfcp_router_node,
	.install = cmd_ext_pfcp_router_install,
};

static void __attribute__((constructor))
pfcp_router_vty_init(void)
{
	cmd_ext_register(&cmd_ext_pfcp_router);
}
