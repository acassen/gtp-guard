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

#include <string.h>
#include <assert.h>

#include "gtp_bpf_prog.h"
#include "gtp_data.h"
#include "inet_server.h"
#include "pfcp_router.h"
#include "pfcp.h"
#include "inet_utils.h"
#include "command.h"
#include "bitops.h"
#include "memory.h"

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	PFCP commands
 */
DEFUN(pfcp_router,
      pfcp_router_cmd,
      "pfcp-router STRING",
      "Configure PFCP Router Instance\n"
      "PFCP Instance Name")
{
	struct pfcp_router *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = pfcp_router_get(argv[0]);
	new = (new) ? : pfcp_router_init(argv[0]);
	if (!new) {
		vty_out(vty, "%% Error allocating pfcp-router:%s !!!%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = PFCP_ROUTER_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_pfcp_router,
      no_pfcp_router_cmd,
      "no pfcp-router STRING",
      "Destroy PFCP Router Instance\n"
      "Instance Name")
{
	struct pfcp_router *c;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	c = pfcp_router_get(argv[0]);
	if (!c) {
		vty_out(vty, "%% unknown gtp-router %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	pfcp_router_ctx_destroy(c);
	FREE(c);

	return CMD_SUCCESS;
}

DEFUN(pfcp_router_desciption,
      pfcp_router_description_cmd,
      "description STRING",
      "Set PFCP Router description\n"
      "description\n")
{
	struct pfcp_router *c = vty->index;

	snprintf(c->description, GTP_STR_MAX_LEN, "%s", argv[0]);

	return CMD_SUCCESS;
}

DEFUN(pfcp_router_bpf_prog,
      pfcp_router_bpf_prog_cmd,
      "bpf-program WORD",
      "Use BPF Program\n"
      "BPF Program name")
{
        struct pfcp_router *c = vty->index;
	struct gtp_bpf_prog *p;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	c->bpf_prog = p;
	return CMD_SUCCESS;
}

DEFUN(pfcp_listen,
      pfcp_listen_cmd,
      "listen (A.B.C.D|X:X:X:X) port <1024-65535>",
      "PFCP Session channel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 8805)\n"
      "Number\n")
{
	struct pfcp_router *c = vty->index;
	struct pfcp_server *srv = &c->s;
	struct sockaddr_storage *addr = &srv->s.addr;
	int port = PFCP_PORT, err = 0;

        if (argc < 1) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

        if (__test_bit(PFCP_ROUTER_FL_LISTEN_BIT, &c->flags)) {
                vty_out(vty, "%% PFCP listener already configured!%s"
			   , VTY_NEWLINE);
                return CMD_WARNING;
        }

        if (argc == 2)
                VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);

	err = inet_stosockaddr(argv[0], port, addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	err = pfcp_server_init(srv, c, pfcp_router_ingress_init,
			       pfcp_router_ingress_process);
	if (err) {
		vty_out(vty, "%% Error initializing PFCP Listener on [%s]:%d%s"
			   , argv[0], port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(PFCP_ROUTER_FL_LISTEN_BIT, &c->flags);
	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static int
pfcp_vty(struct vty *vty, struct pfcp_router *c)
{
	char buf[4096];
	size_t nbytes;

	vty_out(vty, " pfcp-router(%s): '%s'\n",
		c->name, c->description);

	nbytes = pfcp_router_dump(c, buf, sizeof (buf));
	if (nbytes)
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
	struct pfcp_router *c;
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
config_pfcp_router_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->pfcp_router_ctx;
	struct pfcp_router *c;

	list_for_each_entry(c, l, next) {
		vty_out(vty, "pfcp-router %s\n", c->name);
		if (c->description[0])
			vty_out(vty, " description %s\n", c->description);
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

	/* Install show commands. */
	install_element(VIEW_NODE, &show_pfcp_router_cmd);
	install_element(ENABLE_NODE, &show_pfcp_router_cmd);

	return 0;
}

struct cmd_node pfcp_router_node = {
	.node = PFCP_ROUTER_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(pfcp)# ",
	.config_write = config_pfcp_router_write,
};

static struct cmd_ext cmd_ext_pfcp_router = {
	.node = &pfcp_router_node,
	.install = cmd_ext_pfcp_router_install,
};

static void __attribute__((constructor))
pfcp_router_vty_init(void)
{
	cmd_ext_register(&cmd_ext_pfcp_router);
}
