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
#include "gtp.h"
#include "gtp_bpf_utils.h"
#include "pfcp_router.h"
#include "inet_server.h"
#include "pfcp_assoc.h"
#include "pfcp_proto_hdl.h"
#include "pfcp.h"
#include "inet_utils.h"
#include "command.h"
#include "bitops.h"
#include "logger.h"

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
		vty_out(vty, "%% Error allocating pfcp-router:'%s' !!!%s"
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
		vty_out(vty, "%% unknown pfcp-router:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	pfcp_router_ctx_destroy(c);

	return CMD_SUCCESS;
}

DEFUN(pfcp_router_desciption,
      pfcp_router_description_cmd,
      "description STRING",
      "Set PFCP Router description\n"
      "description\n")
{
	struct pfcp_router *c = vty->index;

	snprintf(c->description, sizeof (c->description), "%s", argv[0]);

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
	struct pfcp_bpf_data *bpf_data;
	struct gtp_bpf_prog *p;

	if (c->bpf_prog != NULL) {
		vty_out(vty, "%% bpf-program already set\n");
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bpf_data = gtp_bpf_prog_tpl_data_get(p, "upf");
	if (!bpf_data) {
		vty_out(vty, "%% unknown template 'upf' for bpf-program '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	c->bpf_prog = p;
	c->bpf_data = bpf_data;
	list_add(&c->bpf_list, &bpf_data->pfcp_router_list);

	return CMD_SUCCESS;
}

DEFUN(pfcp_router_peer_list,
      pfcp_router_peer_list_cmd,
      "pfcp-peer-list STRING",
      "Use Specific PFCP Peer list\n"
      "PFCP Peer list name")
{
	struct pfcp_router *c = vty->index;
	struct pfcp_peer_list *plist;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	plist = pfcp_peer_list_get(argv[0]);
	if (!plist) {
		vty_out(vty, "%% unknown pfcp-peer-list:'%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	c->peer_list = plist;
	thread_add_event(master, pfcp_assoc_setup_request_send, c, 0);

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
      "debug (ingress_msg|egress_msg)",
      "activate PFCP debug option\n"
      "dump ingress messages\n"
      "dump egress messages\n")
{
	struct pfcp_router *c = vty->index;

	if (!strcmp(argv[0], "ingress_msg"))
		__set_bit(PFCP_DEBUG_FL_INGRESS_MSG, &c->debug);
	if (!strcmp(argv[0], "egress_msg"))
		__set_bit(PFCP_DEBUG_FL_EGRESS_MSG, &c->debug);

	return CMD_SUCCESS;
}

DEFUN(pfcp_debug_teid,
      pfcp_debug_teid_cmd,
      "debug teid (add|del) (egress|ingress) TEID ENDPTADDR [UEADDR UEADDR2]",
      "Debug command\n"
      "Add or delete teid\n"
      "Teid\n"
      "Gtp-u endpoint address:port\n")
{
	struct pfcp_router *c = vty->index;
	struct pfcp_teid t = {};
	struct ue_ip_address ue = {};
	union addr endpt_addr, ue_addr, ue2_addr;
	uint32_t teid = atoi(argv[2]);
	int r;

	if (addr_parse(argv[3], &endpt_addr) || endpt_addr.family != AF_INET) {
		vty_out(vty, "%% cannot parse endpt addresses %s\n", argv[3]);
		return CMD_WARNING;
	}
	t.id = teid;
	if (!strcmp(argv[1], "ingress"))
		__set_bit(PFCP_TEID_F_INGRESS, &t.flags);
	if (!strcmp(argv[1], "egress"))
		__set_bit(PFCP_TEID_F_EGRESS, &t.flags);
	t.ipv4 = endpt_addr.sin.sin_addr;

	if (argc >= 5) {
		if (addr_parse(argv[4], &ue_addr)) {
			vty_out(vty, "%% cannot parse ue addresses %s\n", argv[4]);
			return CMD_WARNING;
		}
		ue.flags |= ue_addr.family == AF_INET ? UE_IPV4 : UE_IPV6;
		if (ue_addr.family == AF_INET)
			ue.v4 = ue_addr.sin.sin_addr;
		else
			memcpy(&ue.v6, &ue_addr.sin6.sin6_addr, sizeof (ue.v6));
	}

	if (argc >= 6) {
		if (addr_parse(argv[5], &ue2_addr) ||
		    ue2_addr.family == ue_addr.family) {
			vty_out(vty, "%% cannot parse secondary ue addresses %s\n",
				argv[5]);
			return CMD_WARNING;
		}
		ue.flags |= ue2_addr.family == AF_INET ? UE_IPV4 : UE_IPV6;
		if (ue2_addr.family == AF_INET)
			ue.v4 = ue2_addr.sin.sin_addr;
		else
			memcpy(&ue.v6, &ue2_addr.sin6.sin6_addr, sizeof (ue.v6));
	}

	r = pfcp_bpf_teid_action(c, !strcmp(argv[0], "add") ? RULE_ADD : RULE_DEL,
				 &t, &ue);
	if (r) {
		vty_out(vty, "%% cannot %s teid 0x%08x\n", argv[0], teid);
		return CMD_WARNING;
	}

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
      "gtpu-tunnel-endpoint (all|s1|s5|s8|n9) (A.B.C.D|X:X::X:X) port <1024-65535>",
      "3GPP GTP-U interface\n"
      "All interface\n"
      "S1-U interface\n"
      "S5-U interface\n"
      "S8-U interface\n"
      "N9-U interface\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "UDP port to listen to\n"
      "Number between 1024 and 65535\n")
{
	struct pfcp_router *c = vty->index;
	const char *ifname_3gpp = argv[0];
	const char *addr_str = argv[1];
	struct gtp_server *srv;
	unsigned int fl;
	int port = GTP_U_PORT;
	int err = 0;

	/* protocol interface */
	if (!strcmp(ifname_3gpp, "all")) {
		if (__test_bit(PFCP_ROUTER_FL_ALL, &c->flags)) {
			vty_out(vty, "%% Default GTP-U endpoint already set\n");
			return CMD_WARNING;
		}
		fl = PFCP_ROUTER_FL_ALL;
		srv = &c->gtpu;
	} else if (!strcmp(ifname_3gpp, "s1")) {
		if (__test_bit(PFCP_ROUTER_FL_S1U, &c->flags)) {
			vty_out(vty, "%% 3GPP-S1-U endpoint already set\n");
			return CMD_WARNING;
		}
		fl = PFCP_ROUTER_FL_S1U;
		srv = &c->gtpu_s1;
	} else if (!strcmp(ifname_3gpp, "s5")) {
		if (__test_bit(PFCP_ROUTER_FL_S5U, &c->flags)) {
			vty_out(vty, "%% 3GPP-S5-U endpoint already set\n");
			return CMD_WARNING;
		}
		fl = PFCP_ROUTER_FL_S5U;
		srv = &c->gtpu_s5;
	} else if (!strcmp(ifname_3gpp, "s8")) {
		if (__test_bit(PFCP_ROUTER_FL_S8U, &c->flags)) {
			vty_out(vty, "%% 3GPP-S8-U endpoint already set\n");
			return CMD_WARNING;
		}
		fl = PFCP_ROUTER_FL_S8U;
		srv = &c->gtpu_s8;
	} else if (!strcmp(ifname_3gpp, "n9")) {
		if (__test_bit(PFCP_ROUTER_FL_N9U, &c->flags)) {
			vty_out(vty, "%% 3GPP-N9-U endpoint already set\n");
			return CMD_WARNING;
		}
		fl = PFCP_ROUTER_FL_N9U;
		srv = &c->gtpu_n9;
	} else {
		return CMD_WARNING;
	}

	/* endpoint ip address */
	VTY_GET_INTEGER_RANGE("UDP Port", port, argv[2], 1024, 65535);
	err = inet_stosockaddr(addr_str, port, &srv->s.addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s\n", addr_str);
		memset(&srv->s.addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	err = gtp_server_init(srv, c, pfcp_gtpu_ingress_init,
			      pfcp_gtpu_ingress_process);
	if (err) {
		vty_out(vty, "%% Error initializing GTP-U listener on [%s]:%d%s"
			   , addr_str, port, VTY_NEWLINE);
		memset(&srv->s.addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}
	__set_bit(fl, &c->flags);

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
	pfcp_assoc_vty(vty, (argc >= 1) ? argv[0] : NULL);

	return CMD_SUCCESS;
}


/*
 *	PFCP Peers command
 */
DEFUN(pfcp_peer_list,
      pfcp_peer_list_cmd,
      "pfcp-peer-list STRING",
      "Configure PFCP Peer List\n"
      "PFCP Peer list Name")
{
	struct pfcp_peer_list *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = pfcp_peer_list_get(argv[0]);
	new = (new) ? : pfcp_peer_list_alloc(argv[0]);
	if (!new) {
		vty_out(vty, "%% Error allocating pfcp-peer:'%s' !!!%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = PFCP_PEER_LIST_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_pfcp_peer_list,
      no_pfcp_peer_list_cmd,
      "no pfcp-peer-list STRING",
      "Destroy PFCP Peer List\n"
      "PFCP Peer list Name")
{
	struct pfcp_peer_list *p;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	p = pfcp_peer_list_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown pfcp-peer:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	pfcp_peer_list_ctx_destroy(p);

	return CMD_SUCCESS;
}

DEFUN(pfcp_peer_list_desciption,
      pfcp_peer_list_description_cmd,
      "description STRING",
      "Set PFCP Peer list description\n"
      "description\n")
{
	struct pfcp_peer_list *p = vty->index;

	snprintf(p->description, sizeof(p->description), "%s", argv[0]);

	return CMD_SUCCESS;
}

DEFUN(pfcp_peer,
      pfcp_peer_cmd,
      "peer (A.B.C.D|X:X::X:X)",
      "Create a PFCP Peer\n"
      "PFCP IPv4 Peer\n"
      "PFCP IPv6 Peer\n")
{
	struct pfcp_peer_list *p = vty->index;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = addr_parse(argv[0], &p->addr[p->nr_addr]);
	if (err) {
		vty_out(vty, "%% invalid peer:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (p->nr_addr >= PFCP_PEER_MAX) {
		vty_out(vty, "%% Maximum peer per list reached:%d%s"
			   , p->nr_addr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	switch (p->addr[p->nr_addr].family) {
	case AF_INET:
		if (!p->addr[p->nr_addr].sin.sin_port)
			p->addr[p->nr_addr].sin.sin_port = htons(PFCP_PORT);
	case AF_INET6:
		if (!p->addr[p->nr_addr].sin6.sin6_port)
			p->addr[p->nr_addr].sin6.sin6_port = htons(PFCP_PORT);
	}

	p->nr_addr++;

	return CMD_SUCCESS;
}


/* Show */
DEFUN(show_pfcp_bpf,
      show_pfcp_bpf_cmd,
      "show bpf pfcp",
      SHOW_STR
      "BPF UPF Dataplane ruleset\n")
{
	gtp_bpf_prog_foreach_vty("upf", vty, argc, argv);
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
	vty_out(vty, "%s", VTY_NEWLINE);
	return 0;
}

static int
config_pfcp_router_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->pfcp_router_ctx;
	char node_id[GTP_STR_MAX_LEN];
	struct pfcp_router *c;
	struct pfcp_server *srv;

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
		if (c->peer_list)
			vty_out(vty, " pfcp-peer-list %s%s"
				   , c->peer_list->name, VTY_NEWLINE);
		srv = &c->s;
		if (srv->s.addr.ss_family)
			vty_out(vty, " listen %s port %d%s"
				   , inet_sockaddrtos(&srv->s.addr)
				   , ntohs(inet_sockaddrport(&srv->s.addr))
				   , VTY_NEWLINE);
		if (__test_bit(PFCP_ROUTER_FL_STRICT_APN, &c->flags))
			vty_out(vty, " strict-apn%s", VTY_NEWLINE);

		if (__test_bit(PFCP_ROUTER_FL_ALL, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint all %s port %d\n"
				   , inet_sockaddrtos(&c->gtpu.s.addr)
				   , ntohs(inet_sockaddrport(&c->gtpu.s.addr)));
		if (__test_bit(PFCP_ROUTER_FL_S1U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint s1 %s port %d\n"
				   , inet_sockaddrtos(&c->gtpu_s1.s.addr)
				   , ntohs(inet_sockaddrport(&c->gtpu_s1.s.addr)));
		if (__test_bit(PFCP_ROUTER_FL_S5U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint s5 %s port %d\n"
				   , inet_sockaddrtos(&c->gtpu_s5.s.addr)
				   , ntohs(inet_sockaddrport(&c->gtpu_s5.s.addr)));
		if (__test_bit(PFCP_ROUTER_FL_S8U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint s8 %s port %d\n"
				   , inet_sockaddrtos(&c->gtpu_s8.s.addr)
				   , ntohs(inet_sockaddrport(&c->gtpu_s8.s.addr)));
		if (__test_bit(PFCP_ROUTER_FL_N9U, &c->flags))
			vty_out(vty, " gtpu-tunnel-endpoint n9 %s port %d\n"
				   , inet_sockaddrtos(&c->gtpu_n9.s.addr)
				   , ntohs(inet_sockaddrport(&c->gtpu_n9.s.addr)));

		vty_out(vty, "!\n");
	}

	return CMD_SUCCESS;
}

static int
config_pfcp_peer_list_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->pfcp_peers;
	struct pfcp_peer_list *p;
	char addr_str[64];
	int i;

	list_for_each_entry(p, l, next) {
		vty_out(vty, "pfcp-peer-list %s%s", p->name, VTY_NEWLINE);
		if (p->description[0])
			vty_out(vty, " description %s%s"
				   , p->description, VTY_NEWLINE);
		for (i = 0; i < p->nr_addr; i++) {
			vty_out(vty, " peer %s%s"
				   , addr_stringify(&p->addr[i], addr_str, sizeof(addr_str))
				   , VTY_NEWLINE);
		}

		vty_out(vty, "!\n");
	}

	return 0;
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
	install_element(PFCP_ROUTER_NODE, &pfcp_router_peer_list_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_listen_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_debug_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_debug_teid_cmd);
	install_element(PFCP_ROUTER_NODE, &no_pfcp_debug_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_strict_apn_cmd);
	install_element(PFCP_ROUTER_NODE, &pfcp_gtpu_tunnel_endpoint_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_pfcp_assoc_cmd);
	install_element(VIEW_NODE, &show_pfcp_router_cmd);
	install_element(VIEW_NODE, &show_pfcp_bpf_cmd);
	install_element(ENABLE_NODE, &show_pfcp_assoc_cmd);
	install_element(ENABLE_NODE, &show_pfcp_router_cmd);
	install_element(ENABLE_NODE, &show_pfcp_bpf_cmd);

	return 0;
}

static int
cmd_ext_pfcp_peer_list_install(void)
{
	/* Install PFCP Router commands. */
	install_element(CONFIG_NODE, &pfcp_peer_list_cmd);
	install_element(CONFIG_NODE, &no_pfcp_peer_list_cmd);

	install_default(PFCP_PEER_LIST_NODE);
	install_element(PFCP_PEER_LIST_NODE, &pfcp_peer_list_description_cmd);
	install_element(PFCP_PEER_LIST_NODE, &pfcp_peer_cmd);

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

struct cmd_node pfcp_peer_list_node = {
	.node = PFCP_PEER_LIST_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(pfcp-peer-list)# ",
	.config_write = config_pfcp_peer_list_write,
};

static struct cmd_ext cmd_ext_pfcp_peer_list = {
	.node = &pfcp_peer_list_node,
	.install = cmd_ext_pfcp_peer_list_install,
};

static void __attribute__((constructor))
pfcp_router_vty_init(void)
{
	cmd_ext_register(&cmd_ext_pfcp_router);
	cmd_ext_register(&cmd_ext_pfcp_peer_list);
}
