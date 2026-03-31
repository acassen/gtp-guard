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

/* system includes */
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <errno.h>

/* local includes */
#include "utils.h"
#include "inet_server.h"
#include "inet_utils.h"
#include "bitops.h"
#include "addr.h"
#include "tools.h"
#include "list_head.h"
#include "command.h"
#include "gtp_data.h"
#include "gtp_bpf_ifrules.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "cdr_fwd.h"
#include "cgn.h"
#include "cgn-priv.h"
#include "bpf/lib/cgn-def.h"


/* Extern data */
extern struct data *daemon_data;


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
		if (c == NULL)
			return CMD_WARNING;
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
		vty_out(vty, "%% unknown carrier-grade-nat instance %s\n",
			argv[0]);
		return CMD_WARNING;
	}
	cgn_ctx_release(c);

	return CMD_SUCCESS;
}

DEFUN(cgn_description,
      cgn_description_cmd,
      "description STRING",
      "Set Carrier-Grade-NAT description\n"
      "description\n")
{
	struct cgn_ctx *c = vty->index;

	snprintf(c->description, sizeof (c->description), "%s", argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cgn_bpf_program,
      cgn_bpf_program_cmd,
      "bpf-program NAME",
      "Use BPF Program\n"
      "BPF Program name\n")
{
	struct cgn_ctx *c = vty->index;
	struct gtp_bpf_prog *p;

	if (c->bpf_data != NULL) {
		vty_out(vty, "%% bpf-program already set\n");
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program '%s'\n", argv[0]);
		return CMD_WARNING;
	}

	c->bpf_data = gtp_bpf_prog_tpl_data_get(p, "cgn");
	c->bpf_ifrules = gtp_bpf_prog_tpl_data_get(p, "if_rules");
	if (c->bpf_data == NULL || c->bpf_ifrules == NULL) {
		vty_out(vty, "%% bpf-program '%s' is not implementing "
			"template 'cgn' and 'if_rules'\n", argv[0]);
		return CMD_WARNING;
	}
	list_add(&c->bpf_list, &c->bpf_data->cgn_list);

	return CMD_SUCCESS;
}

DEFUN(cgn_interface,
      cgn_interface_cmd,
      "interface (ingress|egress) .IFACES",
      "Configure interface to listen for trafic\n"
      "Use interfaces in ingress\n"
      "Use interfaces in egress\n"
      "Interfaces name\n")
{
	struct gtp_interface *iface;
	bool ingress = !strcmp(argv[0], "ingress");
	int i, ret;

	for (i = 1; i < argc; i++) {
		iface = gtp_interface_get(argv[i], true);
		if (iface == NULL) {
			vty_out(vty, "%% iface '%s' not found\n", argv[i]);
			continue;
		}
		struct gtp_if_rule ifr = {
			.from = iface,
			.prio = ingress ? 100 : 500,
			.action = ingress ? XDP_CGN_FROM_PRIV : XDP_CGN_FROM_PUB,
		};
		ret = gtp_bpf_ifrules_set(&ifr, true);
		if (ret < 0 && ret != -EEXIST)
			vty_out(vty, "%% error binding interface '%s' to cgn\n", argv[i]);
	}
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

	if (c->initialized) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot configure, "
			"already initialized\n", c->name);
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

DEFUN(cgn_user_conf,
      cgn_user_conf_cmd,
      "user max <1-2000000> block <1-63> flow <10-16000>",
      "Configure CGN users\n"
      "Set maximum users allowed\n"
      "Value\n"
      "Set maximum ipblock allowed per users\n"
      "Value\n"
      "Set maximum flow allowed per users\n"
      "Value\n")
{
	struct cgn_ctx *c = vty->index;

	if (c->initialized) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot configure, "
			"already initialized\n", c->name);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Max user", c->max_user,
			      argv[1], 1, 2000000);
	c->max_user = atoi(argv[0]);
	VTY_GET_INTEGER_RANGE("Max block per user", c->block_per_user,
			      argv[1], 1, 63);
	VTY_GET_INTEGER_RANGE("Max flow per user", c->flow_per_user,
			      argv[2], 1, 16000);

	c->max_flow = (c->max_user * c->flow_per_user) / 100;

	return CMD_SUCCESS;
}

DEFUN(cgn_block_conf_pool,
      cgn_block_conf_cmd,
      "block-port start START end END size SIZE",
      "Configure block ports\n")
{
	struct cgn_ctx *c = vty->index;
	uint16_t port_start, port_end, block_size;

	if (c->initialized) {
		vty_out(vty, "%% carrier-grade-nat:'%s' cannot configure, "
			"already initialized\n", c->name);
		return CMD_WARNING;
	}

	port_start = atoi(argv[0]);
	port_end = atoi(argv[1]);
	block_size = atoi(argv[2]);

	if (!block_size || port_end <= port_start ||
	    block_size > port_end - port_start) {
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
      "protocol timeout (icmp|udp) TIMEOUT",
      "Configure protocol timeout\n")
{
	struct cgn_ctx *c = vty->index;

	if (!strcmp(argv[0], "icmp"))
		c->timeout_icmp = max(atoi(argv[1]), 3);
	else
		c->timeout.udp = max(atoi(argv[1]), 3);

	return CMD_SUCCESS;
}

DEFUN(cgn_protocol_tcp_conf_pool,
      cgn_protocol_tcp_conf_cmd,
      "protocol timeout tcp TIMEOUT synfin STO",
      "Configure tcp protocol timeout\n")
{
	struct cgn_ctx *c = vty->index;

	c->timeout.tcp_est = max(atoi(argv[0]), 10);
	c->timeout.tcp_synfin = max(atoi(argv[1]), 3);

	return CMD_SUCCESS;
}

DEFUN(cgn_protocol_udp_port_conf_pool,
      cgn_protocol_udp_port_conf_cmd,
      "protocol timeout udp TIMEOUT port PORT",
      "Configure udp protocol timeout by port\n")
{
	struct cgn_ctx *c = vty->index;

	uint16_t port = atoi(argv[1]);
	if (port)
		c->timeout_by_port[port].udp = max(atoi(argv[0]), 3);

	return CMD_SUCCESS;
}

DEFUN(cgn_protocol_tcp_port_conf_pool,
      cgn_protocol_tcp_port_conf_cmd,
      "protocol timeout tcp TIMEOUT synfin STO port PORT",
      "Configure tcp protocol timeout by port\n")
{
	struct cgn_ctx *c = vty->index;

	uint16_t port = atoi(argv[2]);
	if (port) {
		c->timeout_by_port[port].tcp_est = max(atoi(argv[0]), 10);
		c->timeout_by_port[port].tcp_synfin = max(atoi(argv[1]), 3);
	}

	return CMD_SUCCESS;
}

DEFUN(cgn_cdr_fwd,
      cgn_cdr_fwd_cmd,
      "cdr-fwd NAME",
      "Configure cdr-forward instance to attached\n"
      "Cdr-Forward instance name\n")
{
	struct cgn_ctx *c = vty->index;
	struct cdr_fwd_entry *e;

	e = cdr_fwd_entry_get(argv[0], false);
	if (e == NULL) {
		vty_out(vty, "%% cdr-fwd:%s not found\n", argv[0]);
		return CMD_WARNING;
	}
	++e->refcount;

	if (c->blog_cdr_fwd != NULL)
		--c->blog_cdr_fwd->refcount;
	c->blog_cdr_fwd = e;

	return CMD_SUCCESS;
}

DEFUN(cgn_no_cdr_fwd,
      cgn_no_cdr_fwd_cmd,
      "no cdr-fwd",
      "Detach\n"
      "Configure cdr-forward instance to be detached\n"
      "Cdr-Forward instance name\n")
{
	struct cgn_ctx *c = vty->index;

	if (c->blog_cdr_fwd == NULL) {
		vty_out(vty, "%% no cdr-fwd instance attached\n");
		return CMD_WARNING;
	}

	--c->blog_cdr_fwd->refcount;
	c->blog_cdr_fwd = NULL;

	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static int
cgn_vty(struct vty *vty, struct cgn_ctx *c)
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
      "show carrier-grade-nat config [INSTANCE]",
      SHOW_STR
      "Carrier Grade NAT\n"
      "Instance name")
{
	const char *name = argc == 1 ? argv[0] : NULL;
	struct cgn_ctx *c;

	list_for_each_entry(c, &daemon_data->cgn, next) {
		if (name != NULL && strcmp(c->name, name))
			continue;

		cgn_vty(vty, c);
	}

	return CMD_SUCCESS;
}

DEFUN(show_cgn_block_alloc,
      show_cgn_block_alloc_cmd,
      "show carrier-grade-nat block-alloc [INSTANCE]",
      SHOW_STR
      "Carrier Grade NAT\n"
      "Show block allocation\n"
      "Instance name")
{
	const char *name = argc == 1 ? argv[0] : NULL;
	char buf[50000];
	struct cgn_ctx *c;

	list_for_each_entry(c, &daemon_data->cgn, next) {
		if (name != NULL && strcmp(c->name, name))
			continue;

		cgn_flow_dump_block_alloc(c, buf, sizeof (buf));
		vty_out(vty, "%s", buf);
	}

	return CMD_SUCCESS;
}


DEFUN(show_cgn_user_flow,
      show_cgn_user_flow_cmd,
      "show carrier-grade-nat flows A.B.C.D [INSTANCE]",
      SHOW_STR
      "Carrier Grade NAT\n"
      "Show block allocation\n"
      "Instance name")
{
	const char *name = argc == 2 ? argv[1] : NULL;
	struct cgn_ctx *c;
	char buf[50000];
	union addr a;
	uint32_t addr;

	if (addr_parse(argv[0], &a))
		return CMD_WARNING;
	addr = ntohl(a.sin.sin_addr.s_addr);

	list_for_each_entry(c, &daemon_data->cgn, next) {
		if (name != NULL && strcmp(c->name, name))
			continue;

		cgn_flow_dump_user_full(c, addr, buf, sizeof (buf));
		vty_out(vty, "%s", buf);
	}

	return CMD_SUCCESS;
}



/*
 *	Configuration writer
 */
static int
config_cgn_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->cgn;
	struct cgn_ctx *c;
	int i, k, p;

	list_for_each_entry(c, l, next) {
		vty_out(vty, "carrier-grade-nat %s\n", c->name);
		if (c->description[0])
			vty_out(vty, " description %s\n", c->description);
		if (c->block_size != CGN_BLOCK_SIZE_DEF ||
		    c->port_start != 1025 ||  c->port_end != 65535)
			vty_out(vty, " block-port start %d end %d size %d\n",
				c->port_start, c->port_end, c->block_size);
		if (c->max_user != CGN_USER_MAX_DEF ||
		    c->block_per_user != CGN_BLOCK_PER_USER_DEF ||
		    c->flow_per_user != CGN_FLOW_PER_USER_DEF)
			vty_out(vty, "user max %d block-per-user %d flow-per-user %d\n",
				c->max_user, c->block_per_user, c->flow_per_user);
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
		if (c->blog_cdr_fwd != NULL)
			vty_out(vty, " cdr-fwd %s\n", c->blog_cdr_fwd->name);
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
	install_element(CGN_NODE, &cgn_bpf_program_cmd);
	install_element(CGN_NODE, &cgn_interface_cmd);
	install_element(CGN_NODE, &cgn_ip_pool_cmd);
	install_element(CGN_NODE, &cgn_block_conf_cmd);
	install_element(CGN_NODE, &cgn_user_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_tcp_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_udp_port_conf_cmd);
	install_element(CGN_NODE, &cgn_protocol_tcp_port_conf_cmd);
	install_element(CGN_NODE, &cgn_cdr_fwd_cmd);
	install_element(CGN_NODE, &cgn_no_cdr_fwd_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_cgn_cmd);
	install_element(ENABLE_NODE, &show_cgn_cmd);
	install_element(ENABLE_NODE, &show_cgn_block_alloc_cmd);
	install_element(ENABLE_NODE, &show_cgn_user_flow_cmd);

	return 0;
}

struct cmd_node cgn_node = {
	.node = CGN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(carrier-grade-nat)# ",
	.config_write = config_cgn_write,
};

static struct cmd_ext cmd_ext_cgn = {
	.node = &cgn_node,
	.install = cmd_ext_cgn_install,
};

static void __attribute__((constructor))
cgn_vty_init(void)
{
	cmd_ext_register(&cmd_ext_cgn);
}
