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
 *              Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include <arpa/inet.h>

#include "bitops.h"
#include "addr.h"
#include "tools.h"
#include "list_head.h"
#include "command.h"
#include "gtp_data.h"
#include "cgn.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Carrier-Grade-NAT Commands
 */
DEFUN(cgn,
      cgn_cmd,
      "carrier-grade-nat STRING",
      "Configure Carrier-Grade-NAT Instance\n"
      "CGN Instance Name")
{
	struct cgn_ctx *c;

	c = cgn_ctx_get_by_name(argv[0]);
	if (c == NULL) {
		c = cgn_ctx_alloc(argv[0]);
		__set_bit(CGN_FL_SHUTDOWN_BIT, &c->flags);
	}
	vty->node = CGN_NODE;
	vty->index = c;

	return CMD_SUCCESS;
}

DEFUN(no_cgn,
      no_cgn_cmd,
      "no carrier-grade-nat STRING",
      "Destroy Carrier-Grade-NAT Instance\n"
      "Instance Name")
{
	struct cgn_ctx *c;

	/* Already existing ? */
	c = cgn_ctx_get_by_name(argv[0]);
	if (c == NULL) {
		vty_out(vty, "%% unknown carrier-grade-nat instance %s",
			argv[0]);
		return CMD_WARNING;
	}
	cgn_ctx_release(c);

	return CMD_SUCCESS;
}

DEFUN(cgn_desciption,
      cgn_description_cmd,
      "description STRING",
      "Set Carrier-Grade-NAT description\n"
      "description\n")
{
	struct cgn_ctx *c = vty->index;

	snprintf(c->description, GTP_STR_MAX_LEN, "%s", argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cgn_shutdown,
      cgn_shutdown_cmd,
      "shutdown",
      "Desactivate Carrier Grade NAT instance\n")
{
	struct cgn_ctx *c = vty->index;

	if (__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags))
		return CMD_WARNING;

	/*... Stop stuffs ...*/

	__set_bit(CGN_FL_SHUTDOWN_BIT, &c->flags);

	return CMD_SUCCESS;
}

DEFUN(cgn_no_shutdown,
      cgn_no_shutdown_cmd,
      "no shutdown",
      "Activate Carrier Grade NAT instance\n")
{
	struct cgn_ctx *c = vty->index;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' is already running\n",
			c->name);
		return CMD_WARNING;
	}


	/*... Start stuffs ...
	 *
	 * To submit I/O MUX : thread.h :
	 *   thread_add_event(master, ....);
	 *   thread_add_read(master, ...);
	 *   thread_add_write(master, ...);
	 *   thread_add_timer(master, ...);
	 */

	__clear_bit(CGN_FL_SHUTDOWN_BIT, &c->flags);

	return CMD_SUCCESS;
}


DEFUN(cgn_ip_pool,
      cgn_ip_pool_cmd,
      "ipv4-pool ADDR",
      "Add ipv4 address(es) in pool\n")
{
	struct cgn_ctx *c = vty->index;
	union addr addr;
	uint64_t count;
	uint32_t base, ns, i;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot modify this "
			"setting while running\n", c->name);
		return CMD_WARNING;
	}

	if (addr_parse_ip(argv[0], &addr, NULL, &count, 1)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot "
			"parse ipv4-pool %s\n", c->name, argv[0]);
		return CMD_WARNING;
	}

	base = ntohl(addr.sin.sin_addr.s_addr);
	for (i = 0; i < c->cgn_addr_n; i++) {
		if (c->cgn_addr[i] == base) {
			vty_out(vty, "%% carrier-grade-nat:'%s' skip "
				"duplicate address %s\n", c->name, argv[0]);
			return CMD_WARNING;
		}
	}

	ns = c->cgn_addr_n + count;
	c->cgn_addr = realloc(c->cgn_addr, ns * sizeof (uint32_t));
	for (i = 0; i < count; i++)
		c->cgn_addr[i + c->cgn_addr_n] = base + i;
	c->cgn_addr_n = ns;

	/* XXX sort c->cgn_addr */

	return CMD_SUCCESS;
}


DEFUN(cgn_block_conf_pool,
      cgn_block_conf_cmd,
      "block-port-config start START end END size SIZE",
      "Configure block ports\n")
{
	struct cgn_ctx *c = vty->index;
	uint16_t port_start, port_end, block_size;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot modify this "
			"setting while running", c->name);
		return CMD_WARNING;
	}

	port_start = atoi(argv[0]);
	port_end = atoi(argv[1]);
	block_size = atoi(argv[2]);

	if (!block_size || port_end <= port_start ||
	    block_size < port_end - port_start) {
		vty_out(vty, "%% carrier-grade-nat:'%s' invalid "
			"block_size/port_start/port_end config\n",
			c->name);
		return CMD_WARNING;
	}

	c->port_start = port_start;
	c->block_size = block_size;
	c->block_count = (port_end - port_start) / block_size;
	c->port_end = c->port_start + c->block_size * c->block_count;

	return CMD_SUCCESS;
}


DEFUN(cgn_protocol_conf_pool,
      cgn_protocol_conf_cmd,
      "protocol (icmp|udp) TIMEOUT",
      "Configure protocol timeout\n")
{
	struct cgn_ctx *c = vty->index;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot modify this "
			"setting while running", c->name);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "icmp"))
		c->timeout_icmp = max(atoi(argv[1]), 20);
	else
		c->timeout.udp = max(atoi(argv[1]), 20);

	return CMD_SUCCESS;
}

DEFUN(cgn_protocol_tcp_conf_pool,
      cgn_protocol_tcp_conf_cmd,
      "protocol tcp TIMEOUT synfin STO",
      "Configure tcp protocol timeout\n")
{
	struct cgn_ctx *c = vty->index;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot modify this "
			"setting while running", c->name);
		return CMD_WARNING;
	}

	c->timeout.tcp_est = max(atoi(argv[0]), 60);
	c->timeout.tcp_synfin = max(atoi(argv[1]), 20);

	return CMD_SUCCESS;
}

DEFUN(cgn_protocol_udp_port_conf_pool,
      cgn_protocol_udp_port_conf_cmd,
      "protocol udp TIMEOUT port PORT",
      "Configure udp protocol timeout by port\n")
{
	struct cgn_ctx *c = vty->index;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot modify this "
			"setting while running", c->name);
		return CMD_WARNING;
	}

	uint16_t port = atoi(argv[1]);
	if (port)
		c->timeout_by_port[port].udp = max(atoi(argv[0]), 20);

	return CMD_SUCCESS;
}


DEFUN(cgn_protocol_tcp_port_conf_pool,
      cgn_protocol_tcp_port_conf_cmd,
      "protocol tcp TIMEOUT synfin STO port PORT",
      "Configure tcp protocol timeout by port\n")
{
	struct cgn_ctx *c = vty->index;

	if (!__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags)) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot modify this "
			"setting while running", c->name);
		return CMD_WARNING;
	}

	uint16_t port = atoi(argv[2]);
	if (port) {
		c->timeout_by_port[port].tcp_est = max(atoi(argv[0]), 60);
		c->timeout_by_port[port].tcp_synfin = max(atoi(argv[1]), 20);
	}

	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static int
cgn_vty(vty_t *vty, struct cgn_ctx *c)
{
	char buf[65000];

	vty_out(vty, " carrier-grade-nat(%s): '%s'\n",
		c->name, c->description);

	cgn_ctx_dump(c, buf, sizeof (buf));
	vty_out(vty, "%s", buf);

	return 0;
}

DEFUN(show_cgn,
      show_cgn_cmd,
      "show carrier-grade-nat [STRING]",
      SHOW_STR
      "Carrier Grade NAT\n"
      "Instance name")
{
	struct cgn_ctx *c;
	const char *name = NULL;

	if (list_empty(&daemon_data->cgn)) {
		vty_out(vty, "%% No carrier-grade-nat instance configured...");
		return CMD_SUCCESS;
	}

	if (argc == 1)
		name = argv[0];

	list_for_each_entry(c, &daemon_data->cgn, next) {
		if (name != NULL && strncmp(c->name, name, GTP_NAME_MAX_LEN))
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
	struct list_head *l = &daemon_data->cgn;
	struct cgn_ctx *c;
	int i, k, p;

	list_for_each_entry(c, l, next) {
		vty_out(vty, "carrier-grade-nat %s\n", c->name);
		if (c->description[0])
			vty_out(vty, " description %s\n", c->description);
		vty_out(vty, " block-port-config start %d end %d size %d\n",
			c->port_start, c->port_end, c->block_size);
		uint64_t cgn_addr[c->cgn_addr_n];
		k = cgn_ctx_compact_cgn_addr(c, cgn_addr);
		for (i = 0; i < k; i++) {
			uint32_t addr = htonl(cgn_addr[i]);
			vty_out(vty, " ipv4-pool %s/%d\n",
				inet_ntoa(*(struct in_addr *)&addr),
				(int)(cgn_addr[i] >> 32));
		}
		if (c->timeout.tcp_est != CGN_PROTO_TIMEOUT_TCP_EST ||
		    c->timeout.tcp_synfin != CGN_PROTO_TIMEOUT_TCP_SYNFIN)
			vty_out(vty, " protocol tcp %d synfin %d\n",
				c->timeout.tcp_est, c->timeout.tcp_synfin);
		for (p = 0; p < UINT16_MAX; p++)
			if (c->timeout_by_port[p].tcp_synfin ||
			    c->timeout_by_port[p].tcp_est) {
				vty_out(vty, " protocol tcp %d synfin %d port %d\n",
					c->timeout_by_port[p].tcp_est,
					c->timeout_by_port[p].tcp_synfin, p);
			}
		if (c->timeout.udp != CGN_PROTO_TIMEOUT_UDP)
			vty_out(vty, " protocol udp %d\n", c->timeout.udp);
		for (p = 0; p < UINT16_MAX; p++)
			if (c->timeout_by_port[p].udp)
				vty_out(vty, " protocol udp %d port %d\n",
					c->timeout_by_port[p].udp, p);
		if (c->timeout_icmp != CGN_PROTO_TIMEOUT_ICMP)
			vty_out(vty, " protocol icmp %d\n", c->timeout_icmp);
  		vty_out(vty, " %sshutdown\n",
			__test_bit(CGN_FL_SHUTDOWN_BIT, &c->flags) ? "" : "no ");
		vty_out(vty, "!\n");
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_cgn_install(void)
{
	/* Install Carrier Grade NAT commands. */
	install_element(CONFIG_NODE, &cgn_cmd);
	install_element(CONFIG_NODE, &no_cgn_cmd);

	install_default(CGN_NODE);
	install_element(CGN_NODE, &cgn_description_cmd);
	install_element(CGN_NODE, &cgn_shutdown_cmd);
	install_element(CGN_NODE, &cgn_no_shutdown_cmd);
	install_element(CGN_NODE, &cgn_ip_pool_cmd);
	install_element(CGN_NODE, &cgn_block_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_tcp_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_udp_port_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_tcp_port_conf_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_cgn_cmd);
	install_element(ENABLE_NODE, &show_cgn_cmd);

	return 0;
}

cmd_node_t cgn_node = {
	.node = CGN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(carrier-grade-nat)# ",
	.config_write = config_cgn_write,
};

static cmd_ext_t cmd_ext_cgn = {
	.node = &cgn_node,
	.install = cmd_ext_cgn_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_cgn);
}
