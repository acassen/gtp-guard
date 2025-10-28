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

#include <net/if.h>

#include "gtp_data.h"
#include "gtp_bpf_utils.h"
#include "gtp_bpf_mirror.h"
#include "gtp_mirror.h"
#include "command.h"
#include "inet_utils.h"
#include "bitops.h"
#include "utils.h"
#include "memory.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	VTY helpers
 */
static int
gtp_mirror_show(struct gtp_mirror *m, void *arg)
{
	return gtp_bpf_mirror_vty((struct vty *) arg, m->bpf_prog);
}


/*
 *	VTY command
 */
DEFUN(mirror,
      mirror_cmd,
      "mirror STRING",
      "Configure mirror\n"
      "mirror name\n")
{
	struct gtp_mirror *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_mirror_get(argv[0]);
	if (new) {
		vty->node = MIRROR_NODE;
		vty->index = new;
		gtp_mirror_put(new);
		return CMD_SUCCESS;
	}

	new = gtp_mirror_alloc(argv[0]);
	vty->node = MIRROR_NODE;
	vty->index = new;
	gtp_mirror_put(new);
	return CMD_SUCCESS;
}

DEFUN(no_mirror,
      no_mirror_cmd,
      "no interface STRING",
      "Configure interface\n"
      "Local system interface name\n")
{
	struct gtp_mirror *m;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	m = gtp_mirror_get(argv[0]);
	if (!m) {
		vty_out(vty, "%% unknown mirror:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_mirror_put(m);
	gtp_mirror_destroy(m);
	return CMD_SUCCESS;
}

DEFUN(mirror_bpf_prog,
      mirror_bpf_prog_cmd,
      "bpf-program STRING",
      "Attach a BPF program to the mirror\n"
      "BPF program name\n")
{
	struct gtp_mirror *m = vty->index;
	struct gtp_bpf_prog *p;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program:'%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (m->bpf_prog) {
		vty_out(vty, "%% bpf-program:'%s' already in-use%s"
			   , m->bpf_prog->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!gtp_bpf_prog_has_tpl_mode(p, "gtp_mirror")) {
		vty_out(vty, "%% bpf-program:'%s' mode MUST be 'gtp_mirror'%s"
			   , p->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	m->bpf_prog = p;
	return CMD_SUCCESS;
}

DEFUN(mirror_description,
      mirror_description_cmd,
      "mirror STRING",
      "Set mirror description\n"
      "description\n")
{
	struct gtp_mirror *m = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(m->description, argv[0], GTP_PATH_MAX_LEN - 1);
	return CMD_SUCCESS;
}

DEFUN(mirror_shutdown,
      mirror_shutdown_cmd,
      "mirror",
      "Shutdown mirror\n")
{
	struct gtp_mirror *m = vty->index;

	if (__test_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &m->flags)) {
		vty_out(vty, "%% mirror:'%s' is already shutdown%s"
			   , m->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_mirror_unload_bpf(m);
	__set_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &m->flags);
	return CMD_SUCCESS;
}

DEFUN(mirror_no_shutdown,
      mirror_no_shutdown_cmd,
      "no shutdown",
      "Activate mirror\n")
{
	struct gtp_mirror *m = vty->index;

	if (!__test_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &m->flags)) {
		vty_out(vty, "%% mirror:'%s' is already running%s"
			   , m->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!m->bpf_prog) {
		vty_out(vty, "%% no bpf-program attached to mirror:'%s'%s"
			   , m->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_mirror_load_bpf(m);
	__clear_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &m->flags);
	return CMD_SUCCESS;
}

static int
mirror_prepare(int argc, const char **argv, struct vty *vty,
	       struct sockaddr_storage *addr, uint8_t *protocol, int *ifindex)
{
	int err, port;

	if (argc < 4) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Port", port, argv[1], 1024, 65535);

	err = inet_stosockaddr(argv[0], port, addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* FIXME: complete support to IPv6 mirroring */
	if (addr->ss_family != AF_INET) {
		vty_out(vty, "%% shame on me, only IPv4 is currently supported%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strstr(argv[2], "UDP"))
		*protocol = IPPROTO_UDP;
	else if (strstr(argv[2], "TCP"))
		*protocol = IPPROTO_TCP;
	else {
		vty_out(vty, "%% Protocol %s not supported%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	*ifindex = if_nametoindex(argv[3]);
	if (!*ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[3]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(mirror_rule,
      mirror_rule_cmd,
      "ip-src-dst (A.B.C.D|X:X:X:X) port-src-dst <1024-65535> protocol STRING interface STRING",
      "Mirroring rule\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Port\n"
      "Number\n"
      "IP Protocol\n"
      "UDP or TCP\n"
      "Interface to redirect mirrored traffic to\n"
      "Name\n")
{
	struct gtp_mirror *m = vty->index;
	struct gtp_mirror_rule *r;
	struct sockaddr_storage addr;
	uint8_t protocol;
	int ifindex, err;

	if (!m->bpf_prog) {
		vty_out(vty, "%% No bpf-program configured for mirror:'%s'. Ignoring%s"
			   , m->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = mirror_prepare(argc, argv, vty, &addr, &protocol, &ifindex);
	if (err != CMD_SUCCESS)
		return err;

	r = gtp_mirror_rule_get(m, &addr, protocol, ifindex);
	if (r) {
		vty_out(vty, "%% Same mirroring rule already set%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	r = gtp_mirror_rule_add(m, &addr, protocol, ifindex);

	if (__test_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &m->flags))
		return CMD_SUCCESS;

	err = gtp_bpf_mirror_action(RULE_ADD, r, m->bpf_prog);
	if (err) {
		vty_out(vty, "%% Error while setting XDP mirroring rule%s"
			   , VTY_NEWLINE);
		gtp_mirror_rule_del(r);
		FREE(r);
		return CMD_WARNING;
	}

	r->active = true;

	return CMD_SUCCESS;
}

DEFUN(mirror_no_rule,
      mirror_no_rule_cmd,
      "no ip-src-dst (A.B.C.D|X:X:X:X) port-src-dst <1024-65535> protocol STRING interface STRING",
      "Mirroring rule\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "Port\n"
      "Number\n"
      "IP Protocol\n"
      "UDP or TCP\n"
      "Interface to redirect mirrored traffic to\n"
      "Name\n")
{
	struct gtp_mirror *m = vty->index;
	struct gtp_mirror_rule *r;
	struct sockaddr_storage addr;
	uint8_t protocol;
	int ifindex, err;

	if (!m->bpf_prog) {
		vty_out(vty, "%% No bpf-program configured for mirror:'%s'. Ignoring%s"
			   , m->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = mirror_prepare(argc, argv, vty, &addr, &protocol, &ifindex);
	if (err != CMD_SUCCESS)
		return err;

	r = gtp_mirror_rule_get(m, &addr, protocol, ifindex);
	if (!r) {
		vty_out(vty, "%% No mathing rule%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!__test_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &m->flags)) {
		err = gtp_bpf_mirror_action(RULE_DEL, r, m->bpf_prog);
		if (err) {
			vty_out(vty, "%% Error while removing XDP mirroring rule%s"
				, VTY_NEWLINE);
		}
	}

	gtp_mirror_rule_del(r);
	FREE(r);
	return CMD_SUCCESS;
}


/* Show */
DEFUN(show_bpf_mirror,
      show_bpf_mirror_cmd,
      "show bpf mirror [STRING]",
      SHOW_STR
      "mirror\n")
{
	struct gtp_mirror *m = NULL;

	if (argc >= 1) {
		m = gtp_mirror_get(argv[0]);
		if (!m) {
			vty_out(vty, "%% Unknown mirror:'%s'%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}

		gtp_mirror_show(m, vty);
		gtp_mirror_put(m);
		return CMD_SUCCESS;
	}

	gtp_mirror_foreach(gtp_mirror_show, vty);
	return CMD_SUCCESS;
}


/* Configuration writer */
static int
mirror_config_rules_write(struct vty *vty, struct gtp_mirror *m)
{
	struct list_head *l = &m->rules;
	char addr_str[INET6_ADDRSTRLEN];
	char ifname[IF_NAMESIZE];
	struct gtp_mirror_rule *r;

	list_for_each_entry(r, l, next) {
		vty_out(vty, " ip-src-dst %s port %d protocol %s interface %s%s"
			   , inet_sockaddrtos2(&r->addr, addr_str)
			   , ntohs(inet_sockaddrport(&r->addr))
			   , (r->protocol == IPPROTO_UDP) ? "UDP" : "TCP"
			   , if_indextoname(r->ifindex, ifname)
			   , VTY_NEWLINE);
	}

	return 0;
}

static int
mirror_config_write(struct vty *vty)
{
	struct list_head *l = &daemon_data->mirror;
	struct gtp_mirror *m;

	list_for_each_entry(m, l, next) {
		vty_out(vty, "mirror %s%s", m->name, VTY_NEWLINE);
		if (m->description[0])
			vty_out(vty, " description %s%s", m->description, VTY_NEWLINE);
		if (m->bpf_prog)
			vty_out(vty, " bpf-program %s%s", m->bpf_prog->name, VTY_NEWLINE);
		mirror_config_rules_write(vty, m);
  		vty_out(vty, " %sshutdown%s"
			   , __test_bit(GTP_MIRROR_FL_SHUTDOWN_BIT, &m->flags) ? "" : "no "
			   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_mirror_install(void)
{
	/* Install Interface commands. */
	install_element(CONFIG_NODE, &mirror_cmd);
	install_element(CONFIG_NODE, &no_mirror_cmd);

	install_default(MIRROR_NODE);
	install_element(MIRROR_NODE, &mirror_description_cmd);
	install_element(MIRROR_NODE, &mirror_bpf_prog_cmd);
	install_element(MIRROR_NODE, &mirror_shutdown_cmd);
	install_element(MIRROR_NODE, &mirror_no_shutdown_cmd);
	install_element(MIRROR_NODE, &mirror_rule_cmd);
	install_element(MIRROR_NODE, &mirror_no_rule_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_bpf_mirror_cmd);
	install_element(ENABLE_NODE, &show_bpf_mirror_cmd);

	return 0;
}

struct cmd_node mirror_node = {
	.node = MIRROR_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(mirror)# ",
	.config_write = mirror_config_write,
};

static struct cmd_ext cmd_ext_mirror = {
	.node = &mirror_node,
	.install = cmd_ext_mirror_install,
};

static void __attribute__((constructor))
gtp_vty_init(void)
{
	cmd_ext_register(&cmd_ext_mirror);
}
