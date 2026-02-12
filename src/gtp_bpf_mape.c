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
 * Copyright (C) 2026 Olivier Gournet, <gournet.olivier@gmail.com>
 */

/* system includes */
#include <arpa/inet.h>
#include <errno.h>

/* local includes */
#include "utils.h"
#include "list_head.h"
#include "addr.h"
#include "command.h"
#include "logger.h"
#include "gtp_bpf_prog.h"
#include "bpf/lib/mape-def.h"

struct mape_bpf_ctx
{
	struct gtp_bpf_prog	*p;
	struct list_head	mape_rule_list;
	struct bpf_map		*rules_map;
};

struct mape_rule
{
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	struct list_head	list;

	/* bpf data */
	struct mape_bpf_ctx	*bpf_data;
	struct list_head	bpf_list;

	/* basic matching rule */
	struct mape_bmr		r;
	uint32_t		share_ratio;
	uint32_t		v4_prefix;
	uint8_t			v6_nslen;
	uint8_t			v4_nslen;
};


/* locals */
static LIST_HEAD(mape_rule_list);



/*
 *	Helpers
 */

static void
mape_bpf_update_map(struct mape_rule *r)
{
	struct mape_bpf_ctx *x = r->bpf_data;
	int idx = 0;
	int ret;

	if (x == NULL || x->rules_map == NULL)
		return;

	ret = bpf_map__update_elem(x->rules_map, &idx, sizeof (idx),
				   &r->r, sizeof (r->r), 0);
	if (ret)
		log_message(LOG_INFO, "map insert{mape_bmr}: %m %d", ret);
}

static void
mape_bpf_delete_map(struct mape_rule *r)
{
	struct mape_bpf_ctx *x = r->bpf_data;
	int idx = 0;
	int ret;

	ret = bpf_map__delete_elem(x->rules_map, &idx, sizeof (idx),
				   0);
	if (ret)
		log_message(LOG_INFO, "map delete{mape_bmr}: %m %d", ret);
}


static struct mape_rule *
mape_rule_get_by_name(const char *name, bool create)
{
	struct mape_rule *r;

	list_for_each_entry(r, &mape_rule_list, list) {
		if (!strcmp(r->name, name))
			return r;
	}
	if (!create)
		return NULL;

	r = calloc(1, sizeof (*r));
	if (r == NULL)
		return NULL;
	snprintf(r->name, sizeof (r->name), "%s", name);
	list_add(&r->list, &mape_rule_list);
	return r;
}

static void
mape_rule_release(struct mape_rule *r)
{
	if (r->bpf_data) {
		mape_bpf_delete_map(r);
		list_del(&r->bpf_list);
	}
	list_del(&r->list);
	free(r);
}


/*
 *	eBPF Template
 */

static void *
mape_bpf_alloc(struct gtp_bpf_prog *p)
{
	struct mape_bpf_ctx *x;

	x = calloc(1, sizeof (struct mape_bpf_ctx));
	if (x == NULL)
		return NULL;
	x->p = p;
	INIT_LIST_HEAD(&x->mape_rule_list);

	return x;
}

static void
mape_bpf_release(struct gtp_bpf_prog *p, void *udata)
{
	struct mape_bpf_ctx *x = udata;
	struct mape_rule *r, *r_tmp;

	list_for_each_entry_safe(r, r_tmp, &x->mape_rule_list, bpf_list) {
		r->bpf_data = NULL;
		list_del_init(&r->bpf_list);
	}
	free(x);
}

static int
mape_bpf_loaded(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct mape_bpf_ctx *x = udata;
	struct mape_rule *r;

	x->rules_map = gtp_bpf_prog_load_map(p->obj_load, "mape_bmr");
	if (!x->rules_map)
		return -1;

	list_for_each_entry(r, &x->mape_rule_list, bpf_list) {
		mape_bpf_update_map(r);
	}

	return 0;
}

static struct gtp_bpf_prog_tpl gtp_bpf_mape_module = {
	.name = "mape",
	.description = "MAP-E",
	.alloc = mape_bpf_alloc,
	.release = mape_bpf_release,
	.loaded = mape_bpf_loaded,
};

static void __attribute__((constructor))
gtp_bpf_mape_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_mape_module);
}

static void __attribute__((destructor))
gtp_bpf_mape_release(void)
{
	struct mape_rule *r, *r_tmp;

	list_for_each_entry_safe(r, r_tmp, &mape_rule_list, list)
		mape_rule_release(r);
}



/*
 *	MAP-E VTY Commands
 */
DEFUN(mape,
      mape_cmd,
      "mape-rule STRING",
      "Configure MAP-E Rule\n"
      "MAP-E Rule Name")
{
	struct mape_rule *r;

	r = mape_rule_get_by_name(argv[0], true);
	if (r == NULL)
		return CMD_WARNING;
	vty->node = MAPE_NODE;
	vty->index = r;
	return CMD_SUCCESS;
}

DEFUN(no_mape,
      no_mape_cmd,
      "no mape-rule STRING",
      "Destroy MAP-E Rule\n"
      "MAP-E Rule Name")
{
	struct mape_rule *r;

	/* Already existing ? */
	r = mape_rule_get_by_name(argv[0], false);
	if (r == NULL) {
		vty_out(vty, "%% unknown map-e rule %s\n", argv[0]);
		return CMD_WARNING;
	}
	mape_rule_release(r);

	return CMD_SUCCESS;
}

DEFUN(mape_description,
      mape_description_cmd,
      "description STRING",
      "Set MAP-E description\n"
      "description\n")
{
	struct mape_rule *r = vty->index;

	snprintf(r->description, sizeof (r->description), "%s", argv[0]);

	return CMD_SUCCESS;
}

DEFUN(mape_bpf_program,
      mape_bpf_program_cmd,
      "bpf-program NAME",
      "Use BPF Program\n"
      "BPF Program name\n")
{
	struct mape_rule *r = vty->index;
	struct gtp_bpf_prog *p;

	if (r->bpf_data != NULL) {
		vty_out(vty, "%% bpf-program already set\n");
		return CMD_WARNING;
	}

	p = gtp_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% unknown bpf-program '%s'\n", argv[0]);
		return CMD_WARNING;
	}

	r->bpf_data = gtp_bpf_prog_tpl_data_get(p, "mape");
	if (r->bpf_data == NULL) {
		vty_out(vty, "%% bpf-program '%s' is not implementing "
			"template 'mape'\n", argv[0]);
		return CMD_WARNING;
	}
	list_add(&r->bpf_list, &r->bpf_data->mape_rule_list);

	mape_bpf_update_map(r);

	return CMD_SUCCESS;
}


DEFUN(mape_border_relay_address,
      mape_border_relay_address_cmd,
      "border-relay-address X:X::X:X",
      "Set ipv6 source address when encapsulating in map-e\n")
{
	struct mape_rule *r = vty->index;
	union addr addr;

	if (addr_parse_ip(argv[0], &addr, NULL, NULL, 1) ||
	    addr.family != AF_INET6) {
		vty_out(vty, "%% mape:'%s' cannot parse encap-source %s\n",
			r->name, argv[0]);
		return CMD_WARNING;
	}

	r->r.br_addr = *addr_toip6(&addr);

	mape_bpf_update_map(r);

	return CMD_SUCCESS;
}

DEFUN(mape_ipv6_prefix,
      mape_ipv6_prefix_cmd,
      "ipv6-prefix ADDR",
      "Set ipv6 prefix\n")
{
	struct mape_rule *r = vty->index;
	union addr addr;
	uint32_t ns;

	if (addr_parse_ip(argv[0], &addr, &ns, NULL, 1) ||
	    addr.family != AF_INET6) {
		vty_out(vty, "%% mape:'%s' cannot parse ipv6-prefix %s\n",
			r->name, argv[0]);
		return CMD_WARNING;
	}

	r->r.v6_prefix = *addr_toip6(&addr);
	r->v6_nslen = ns;

	mape_bpf_update_map(r);

	return CMD_SUCCESS;
}


DEFUN(mape_ipv4_prefix,
      mape_ipv4_prefix_cmd,
      "ipv4-prefix ADDR",
      "Set ipv4 prefix\n")
{
	struct mape_rule *r = vty->index;
	union addr addr;
	uint32_t ns;

	if (addr_parse_ip(argv[0], &addr, &ns, NULL, 1) ||
	    addr.family != AF_INET) {
		vty_out(vty, "%% mape:'%s' cannot parse ipv4-prefix %s\n",
			r->name, argv[0]);
		return CMD_WARNING;
	}

	r->v4_prefix = addr_toip4(&addr);
	r->v4_nslen = ns;
	r->r.v4_suffix_mask = (1 << (32 - ns)) - 1;
	r->r.v4_suffix_bits = 32 - ns;

	mape_bpf_update_map(r);

	return CMD_SUCCESS;
}

DEFUN(mape_port_parameters,
      mape_port_parameters_cmd,
      "port-parameters share-ratio NUMBER",
      "Configure port parameters\n"
      "Set Max number of users per ipv4)\n"
      "Value in range [1-4096]\n")
{
	struct mape_rule *r = vty->index;
	int n = atoi(argv[0]);
	int x = 0;

	n = max(1, min(n, 4096));
	while ((1 << x) < n)
		x++;
	r->share_ratio = n;
	r->r.psid_bits = x;

	mape_bpf_update_map(r);

	return CMD_SUCCESS;
}

DEFUN(show_mape,
      show_mape_cmd,
      "show mape",
      SHOW_STR
      "Show all map-e rules\n")
{
	struct mape_rule *r;
	char buf[60];

	list_for_each_entry(r, &mape_rule_list, list) {
		vty_out(vty, "%s (%s):\n", r->name, r->description);
		vty_out(vty, "  local_addr  : %s\n",
			inet_ntop(AF_INET6, &r->r.br_addr, buf, sizeof (buf)));
		vty_out(vty, "  v6_prefix   : %s/%d\n",
			inet_ntop(AF_INET6, &r->r.v6_prefix, buf, sizeof (buf)),
			r->v6_nslen);
		vty_out(vty, "  v4_prefix   : %s/%d\n",
			inet_ntop(AF_INET, &r->v4_prefix, buf, sizeof (buf)),
			r->v4_nslen);
		vty_out(vty, "  share_ratio : %d (bits:%d)\n",
			r->share_ratio, r->r.psid_bits);
	}

	return CMD_SUCCESS;
}


static int
config_mape_write(struct vty *vty)
{
	struct mape_rule *r;
	char buf[60];

	list_for_each_entry(r, &mape_rule_list, list) {
		vty_out(vty, "mape-rule %s\n", r->name);
		if (*r->description)
			vty_out(vty, " description %s\n", r->description);
		if (r->bpf_data != NULL)
			vty_out(vty, " bpf-program %s\n", r->bpf_data->p->name);
		vty_out(vty, " border-relay-address %s\n",
			inet_ntop(AF_INET6, &r->r.br_addr, buf, sizeof (buf)));
		vty_out(vty, " ipv6-prefix %s/%d\n",
			inet_ntop(AF_INET6, &r->r.v6_prefix, buf, sizeof (buf)),
			r->v6_nslen);
		vty_out(vty, " ipv4-prefix %s/%d\n",
			inet_ntop(AF_INET, &r->v4_prefix, buf, sizeof (buf)),
			r->v4_nslen);
		if (r->share_ratio)
			vty_out(vty, " port-parameters share-ratio %d\n",
				r->share_ratio);
		vty_out(vty, "!\n");
	}

	return CMD_SUCCESS;
}


static int
cmd_ext_mape_install(void)
{
	/* Install MAP-E commands. */
	install_element(CONFIG_NODE, &mape_cmd);
	install_element(CONFIG_NODE, &no_mape_cmd);

	install_default(MAPE_NODE);
	install_element(MAPE_NODE, &mape_description_cmd);
	install_element(MAPE_NODE, &mape_bpf_program_cmd);
	install_element(MAPE_NODE, &mape_border_relay_address_cmd);
	install_element(MAPE_NODE, &mape_ipv6_prefix_cmd);
	install_element(MAPE_NODE, &mape_ipv4_prefix_cmd);
	install_element(MAPE_NODE, &mape_port_parameters_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_mape_cmd);
	install_element(ENABLE_NODE, &show_mape_cmd);

	return 0;
}

struct cmd_node mape_node = {
	.node = MAPE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(map-e)# ",
	.config_write = config_mape_write,
};

static struct cmd_ext cmd_ext_mape = {
	.node = &mape_node,
	.install = cmd_ext_mape_install,
};

static void __attribute__((constructor))
mape_vty_init(void)
{
	cmd_ext_register(&cmd_ext_mape);
}
