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
#include "gtp_interface.h"
#include "gtp_interface_rule.h"
#include "gtp_data.h"
#include "gtp.h"
#include "include/pfcp_router.h"
#include "inet_server.h"
#include "pfcp_assoc.h"
#include "pfcp.h"
#include "inet_utils.h"
#include "command.h"
#include "bitops.h"
#include "memory.h"
#include "logger.h"
#include "utils.h"

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
	new = (new) ? : pfcp_router_alloc(argv[0]);
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

DEFUN(pfcp_node_id,
      pfcp_node_id_cmd,
      "node-id STRING",
      "Set PFCP Router Node-ID\n"
      "Node-ID FQDN\n")
{
	struct pfcp_router *c = vty->index;
	ssize_t len;

	len = inet_str2fqdn(c->node_id, GTP_STR_MAX_LEN, argv[0]);
	if (len < 0) {
		vty_out(vty, "%% invalid Node-ID%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	c->node_id_len = len;
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
	c->bpf_data = gtp_bpf_prog_tpl_data_get(p, "upf");
	if (!c->bpf_data) {
		vty_out(vty, "%% unknown template 'upf' for bpf-program '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	list_add(&c->bpf_list, &c->bpf_data->pfcp_router_list);

	return CMD_SUCCESS;
}

DEFUN(pfcp_listen,
      pfcp_listen_cmd,
      "listen (A.B.C.D|X:X::X:X) port <1024-65535>",
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

	if (__test_bit(PFCP_ROUTER_FL_LISTEN, &c->flags)) {
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

	log_message(LOG_INFO, "PFCP start listening on [%s]:%d"
			    , inet_sockaddrtos(addr)
			    , ntohs(inet_sockaddrport(addr)));
	__set_bit(PFCP_ROUTER_FL_LISTEN, &c->flags);
	return CMD_SUCCESS;
}

DEFUN(pfcp_debug,
      pfcp_debug_cmd,
      "debug STRING",
      "activate PFCP debug option\n"
      "valid mode is a combinaison of [ingress_msg|egress_msg]\n")
{
	struct pfcp_router *c = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strstr(argv[0], "ingress_msg"))
		__set_bit(PFCP_DEBUG_FL_INGRESS_MSG, &c->debug);
	if (strstr(argv[0], "egress_msg"))
		__set_bit(PFCP_DEBUG_FL_EGRESS_MSG, &c->debug);

	return CMD_SUCCESS;
}

DEFUN(no_pfcp_debug,
      no_pfcp_debug_cmd,
      "no debug",
      "Disable debug mode\n")
{
	struct pfcp_router *c = vty->index;

	c->debug = 0;
	return CMD_SUCCESS;
}

DEFUN(pfcp_strict_apn,
      pfcp_strict_apn_cmd,
      "strict-apn",
      "Use Strict APN binding for Session Establishment\n")
{
	struct pfcp_router *c = vty->index;

	__set_bit(PFCP_ROUTER_FL_STRICT_APN, &c->flags);
	return CMD_SUCCESS;
}

DEFUN(pfcp_gtpu_tunnel_endpoint,
      pfcp_gtpu_tunnel_endpoint_cmd,
      "gtpu-tunnel-endpoint (all|s1|s5|s8|n9) (A.B.C.D|X:X::X:X) port <1024-65535> interfaces .IFACES",
      "3GPP GTP-U interface\n"
      "All interface\n"
      "S1-U interface\n"
      "S5-U interface\n"
      "S8-U interface\n"
      "N9-U interface\n"
      "Ingress side\n"
      "Egress side\n"
      "Both sides\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "Interfaces to bind\n")
{
	struct pfcp_router *c = vty->index;
	const char *ifname_3gpp = argv[0];
	const char *addr_str = argv[1];
	struct gtp_interface *iface;
	union addr bind_addr;
	int port = GTP_U_PORT;
	int i, err = 0;

	/* endpoint ip address */
	VTY_GET_INTEGER_RANGE("UDP Port", port, argv[2], 1024, 65535);
	err = addr_parse(addr_str, &bind_addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s\n", addr_str);
		return CMD_WARNING;
	}
	addr_set_port(&bind_addr, port);

	/* protocol interface */
	if (!strcmp(ifname_3gpp, "all")) {
		if (__test_bit(PFCP_ROUTER_FL_ALL, &c->flags)) {
			vty_out(vty, "%% Default GTP-U endpoint already set\n");
			return CMD_WARNING;
		}
		__set_bit(PFCP_ROUTER_FL_ALL, &c->flags);
		addr_copy(&c->gtpu, &bind_addr);
	} else if (!strcmp(ifname_3gpp, "s1")) {
		if (__test_bit(PFCP_ROUTER_FL_S1U, &c->flags)) {
			vty_out(vty, "%% 3GPP-S1-U endpoint already set\n");
			return CMD_WARNING;
		}
		__set_bit(PFCP_ROUTER_FL_S1U, &c->flags);
		addr_copy(&c->gtpu_s1, &bind_addr);
	} else if (!strcmp(ifname_3gpp, "s5")) {
		if (__test_bit(PFCP_ROUTER_FL_S5U, &c->flags)) {
			vty_out(vty, "%% 3GPP-S5-U endpoint already set\n");
			return CMD_WARNING;
		}
		__set_bit(PFCP_ROUTER_FL_S5U, &c->flags);
		addr_copy(&c->gtpu_s5, &bind_addr);
	} else if (!strcmp(ifname_3gpp, "s8")) {
		if (__test_bit(PFCP_ROUTER_FL_S8U, &c->flags)) {
			vty_out(vty, "%% 3GPP-S8-U endpoint already set\n");
			return CMD_WARNING;
		}
		__set_bit(PFCP_ROUTER_FL_S8U, &c->flags);
		addr_copy(&c->gtpu_s8, &bind_addr);
	} else if (!strcmp(ifname_3gpp, "n9")) {
		if (__test_bit(PFCP_ROUTER_FL_N9U, &c->flags)) {
			vty_out(vty, "%% 3GPP-N9-U endpoint already set\n");
			return CMD_WARNING;
		}
		__set_bit(PFCP_ROUTER_FL_N9U, &c->flags);
		addr_copy(&c->gtpu_n9, &bind_addr);
	} else {
		return CMD_WARNING;
	}

	/* interfaces to bind */
	for (i = 3; i < argc; i++) {
		iface = gtp_interface_get(argv[i], true);
		if (iface == NULL) {
			vty_out(vty, "%% cannot find interface %s\n", argv[i]);
			return CMD_WARNING;
		}

		err = gtp_interface_rules_ctx_add(c->irules, iface, true);
		if (err && errno == EEXIST) {
			vty_out(vty, "%% interface %s already added as ingress\n",
				argv[i]);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}


DEFUN(pfcp_egress_endpoint,
      pfcp_egress_endpoint_cmd,
      "egress-endpoint interfaces .IFACES",
      "Interfaces to bind\n")
{
	struct pfcp_router *c = vty->index;
	struct gtp_interface *iface;
	int i, err = 0;

	/* interfaces to bind */
	for (i = 0; i < argc; i++) {
		iface = gtp_interface_get(argv[i], true);
		if (iface == NULL) {
			vty_out(vty, "%% cannot find interface %s\n", argv[i]);
			return CMD_WARNING;
		}

		err = gtp_interface_rules_ctx_add(c->irules, iface, false);
		if (err && errno == EEXIST) {
			vty_out(vty, "%% interface %s already added as egress\n",
				argv[i]);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static int
pfcp_router_vty(struct vty *vty, struct pfcp_router *c)
{
	char buf[4096];
	size_t nbytes;

	nbytes = pfcp_router_dump(c, buf, sizeof(buf));
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

		pfcp_router_vty(vty, c);
	}

	return CMD_SUCCESS;
}

DEFUN(show_pfcp_assoc,
      show_pfcp_assoc_cmd,
      "show pfcp association [STRING]",
      SHOW_STR
      "PFCP Association\n"
      "NodeID")
{
//	const char *name = NULL;

	if (list_empty(&daemon_data->pfcp_router_ctx)) {
		vty_out(vty, "%% No pfcp-router instance configured...");
		return CMD_SUCCESS;
	}

	/* TODO: support selective assoc dump */
#if 0
	if (argc == 1)
		name = argv[0];
#endif

	pfcp_assoc_vty(vty, NULL);

	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static int
config_pfcp_router_debug(struct vty *vty, struct pfcp_router *c)
{
	if (!c->debug)
		return -1;

	vty_out(vty, " debug ");
	if (__test_bit(PFCP_DEBUG_FL_INGRESS_MSG, &c->debug))
		vty_out(vty, "ingress_msg");
	if (__test_bit(PFCP_DEBUG_FL_EGRESS_MSG, &c->debug))
		vty_out(vty, "|egress_msg");
	vty_out(vty, "\n");
	return 0;
}

static int
config_pfcp_router_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->pfcp_router_ctx;
	char node_id[GTP_STR_MAX_LEN];
	char addr_str[INET6_ADDRSTRLEN], port_str[10];
	struct pfcp_router *c;
	struct pfcp_server *srv;
	struct gtp_interface *iflist[8];
	char ifbuf[200];
	int i, n, k;

	list_for_each_entry(c, l, next) {
		vty_out(vty, "pfcp-router %s%s", c->name, VTY_NEWLINE);
		config_pfcp_router_debug(vty, c);
		if (c->description[0])
			vty_out(vty, " description %s%s"
				   , c->description, VTY_NEWLINE);
		if (c->node_id_len)
			vty_out(vty, " node-id %s%s"
				   , inet_fqdn2str(node_id, GTP_STR_MAX_LEN,
						   c->node_id, c->node_id_len)
				   , VTY_NEWLINE);
		if (c->bpf_prog)
			vty_out(vty, " bpf-program %s%s"
				   , c->bpf_prog->name, VTY_NEWLINE);
		srv = &c->s;
		if (srv->s.addr.ss_family)
			vty_out(vty, " listen %s port %d%s"
				   , inet_sockaddrtos(&srv->s.addr)
				   , ntohs(inet_sockaddrport(&srv->s.addr))
				   , VTY_NEWLINE);
		if (__test_bit(PFCP_ROUTER_FL_STRICT_APN, &c->flags))
			vty_out(vty, " strict-apn%s", VTY_NEWLINE);

		n = gtp_interface_rules_ctx_list(c->irules, false, iflist,
						 ARRAY_SIZE(iflist));
		ifbuf[0] = 0;
		for (k = 0, i = 0; i < n; i++)
			k += scnprintf(ifbuf + k, sizeof (ifbuf) - k, " %s",
				       iflist[i]->ifname);

		if (__test_bit(PFCP_ROUTER_FL_ALL, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint all %s port %s interfaces%s\n"
				   , addr_stringify_ip(&c->gtpu, addr_str, INET6_ADDRSTRLEN)
				   , addr_stringify_port(&c->gtpu, port_str, 10)
				   , ifbuf);
		if (__test_bit(PFCP_ROUTER_FL_S1U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint s1 %s port %s interfaces%s\n"
				   , addr_stringify_ip(&c->gtpu_s1, addr_str, INET6_ADDRSTRLEN)
				   , addr_stringify_port(&c->gtpu_s1, port_str, 10)
				   , ifbuf);
		if (__test_bit(PFCP_ROUTER_FL_S5U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint s5 %s port %s interfaces%s\n"
				   , addr_stringify_ip(&c->gtpu_s5, addr_str, INET6_ADDRSTRLEN)
				   , addr_stringify_port(&c->gtpu_s5, port_str, 10)
				   , ifbuf);
		if (__test_bit(PFCP_ROUTER_FL_S8U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint s8 %s port %s interfaces%s\n"
				   , addr_stringify_ip(&c->gtpu_s8, addr_str, INET6_ADDRSTRLEN)
				   , addr_stringify_port(&c->gtpu_s8, port_str, 10)
				   , ifbuf);
		if (__test_bit(PFCP_ROUTER_FL_N9U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint n9 %s port %s interfaces%s\n"
				   , addr_stringify_ip(&c->gtpu_n9, addr_str, INET6_ADDRSTRLEN)
				   , addr_stringify_port(&c->gtpu_n9, port_str, 10)
				   , ifbuf);
		n = gtp_interface_rules_ctx_list(c->irules, false, iflist,
						 ARRAY_SIZE(iflist));
		if (n > 0) {
			vty_out(vty, " egress-endpoint interfaces");
			for (i = 0; i < n; i++)
				vty_out(vty, " %s", iflist[i]->ifname);
			vty_out(vty, "%s", VTY_NEWLINE);
		}

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
	install_element(PFCP_ROUTER_NODE, &pfcp_node_id_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_router_bpf_prog_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_listen_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_debug_cmd);
	install_element(PFCP_ROUTER_NODE, &no_pfcp_debug_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_strict_apn_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_gtpu_tunnel_endpoint_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_egress_endpoint_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_pfcp_assoc_cmd);
	install_element(VIEW_NODE, &show_pfcp_router_cmd);
	install_element(ENABLE_NODE, &show_pfcp_assoc_cmd);
	install_element(ENABLE_NODE, &show_pfcp_router_cmd);

	return 0;
}

struct cmd_node pfcp_router_node = {
	.node = PFCP_ROUTER_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(pfcp-router)# ",
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
