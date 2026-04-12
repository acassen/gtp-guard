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

#include "gtp_data.h"
#include "gtp_range_partition.h"
#include "gtp_flow_steering.h"
#include "command.h"
#include "cpu.h"
#include "utils.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	CONFIG_NODE commands
 */
DEFUN(flow_steering_policy,
      flow_steering_policy_cmd,
      "flow-steering-policy WORD",
      "Configure flow steering policy\n"
      "Policy name")
{
	struct gtp_flow_steering_policy *fsp;

	fsp = gtp_flow_steering_get(argv[0]);
	fsp = fsp ? : gtp_flow_steering_alloc(argv[0]);
	if (!fsp) {
		vty_out(vty, "%% Error allocating flow-steering-policy '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = FLOW_STEERING_NODE;
	vty->index = fsp;
	return CMD_SUCCESS;
}

DEFUN(no_flow_steering_policy,
      no_flow_steering_policy_cmd,
      "no flow-steering-policy WORD",
      "Destroy flow steering policy\n"
      "Policy name")
{
	struct gtp_flow_steering_policy *fsp;

	fsp = gtp_flow_steering_get(argv[0]);
	if (!fsp) {
		vty_out(vty, "%% unknown flow-steering-policy '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (fsp->refcnt) {
		vty_out(vty, "%% flow-steering-policy '%s' is in use%s"
			   , fsp->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_flow_steering_free(fsp);
	return CMD_SUCCESS;
}


/*
 *	FLOW_STEERING_NODE commands
 */
DEFUN(flow_steering_queue_id,
      flow_steering_queue_id_cmd,
      "queue-id STRING",
      "Set NIC queue IDs for this policy\n"
      "Queue ID list (cpumask format, e.g. 0-3,8-11)")
{
	struct gtp_flow_steering_policy *fsp = vty->index;
	uint32_t *new_ids;
	cpu_set_t set;
	int cpu, n;

	CPU_ZERO(&set);
	cpulist_to_set(argv[0], &set);

	n = CPU_COUNT(&set);
	if (!n)
		return CMD_SUCCESS;

	new_ids = realloc(fsp->queue_ids, n * sizeof(*new_ids));
	if (!new_ids) {
		vty_out(vty, "%% out-of-memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	fsp->queue_ids = new_ids;

	n = 0;
	cpuset_for_each(cpu, set, CPU_SETSIZE)
		fsp->queue_ids[n++] = (uint32_t)cpu;
	fsp->nr_queue_ids = n;

	return CMD_SUCCESS;
}

DEFUN(flow_steering_bind_rp,
      flow_steering_bind_rp_cmd,
      "queue-id bind range-partition WORD",
      "Queue ID binding\n"
      "Bind keyword\n"
      "Range partition keyword\n"
      "Range partition name")
{
	struct gtp_flow_steering_policy *fsp = vty->index;
	struct gtp_range_partition *rp;

	rp = gtp_range_partition_get(argv[0]);
	if (!rp) {
		vty_out(vty, "%% unknown range-partition '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gtp_flow_steering_bind_rp(fsp, rp) < 0) {
		vty_out(vty, "%% Failed to bind range-partition '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (fsp->nr_queue_ids && rp->nr_parts &&
	    fsp->nr_queue_ids != rp->nr_parts)
		vty_out(vty, "%% Warning: queue-id count (%d) != parts count (%d), "
			     "only min(%d,%d) mappings active%s"
			   , fsp->nr_queue_ids, rp->nr_parts
			   , fsp->nr_queue_ids, rp->nr_parts
			   , VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(no_flow_steering_bind_rp,
      no_flow_steering_bind_rp_cmd,
      "no queue-id bind range-partition WORD",
      "Remove binding\n"
      "Queue ID binding\n"
      "Bind keyword\n"
      "Range partition keyword\n"
      "Range partition name")
{
	struct gtp_flow_steering_policy *fsp = vty->index;

	if (gtp_flow_steering_unbind_rp(fsp, argv[0]) < 0) {
		vty_out(vty, "%% range-partition '%s' not bound%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
static void
fsp_queue_ids_str(struct gtp_flow_steering_policy *fsp, char *buf, size_t sz)
{
	int i, len = 0;

	for (i = 0; i < fsp->nr_queue_ids; i++)
		len += scnprintf(buf + len, sz - len, "%s%u"
					  , i ? "," : ""
					  , fsp->queue_ids[i]);
}

DEFUN(show_flow_steering_policy,
      show_flow_steering_policy_cmd,
      "show flow-steering-policy [WORD]",
      SHOW_STR
      "Flow steering policy\n"
      "Policy name (optional filter)")
{
	struct gtp_flow_steering_policy *fsp;
	const char *name = argc ? argv[0] : NULL;
	int i;

	if (list_empty(&daemon_data->flow_steering)) {
		vty_out(vty, "%% No flow-steering-policy configured%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	list_for_each_entry(fsp, &daemon_data->flow_steering, next) {
		char q_str[256] = {};

		if (name && strncmp(fsp->name, name, GTP_NAME_MAX_LEN - 1))
			continue;

		fsp_queue_ids_str(fsp, q_str, sizeof(q_str));
		vty_out(vty, "flow-steering-policy %s  queues=[%s] (%d)  maps=%d  refcnt=%d%s"
			   , fsp->name, q_str, fsp->nr_queue_ids
			   , fsp->nr_maps, fsp->refcnt
			   , VTY_NEWLINE);

		for (i = 0; i < fsp->nr_maps; i++) {
			struct gtp_range_partition *rp = fsp->maps[i].rp;
			int min_count = (fsp->nr_queue_ids < rp->nr_parts) ?
					fsp->nr_queue_ids : rp->nr_parts;
			vty_out(vty, "  map[%d] range-partition=%s  parts=%d  active-maps=%d%s"
				   , i, rp->name, rp->nr_parts, min_count, VTY_NEWLINE);
		}
	}

	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static int
gtp_flow_steering_config_write(struct vty *vty)
{
	struct gtp_flow_steering_policy *fsp;
	int i;

	list_for_each_entry(fsp, &daemon_data->flow_steering, next) {
		vty_out(vty, "flow-steering-policy %s%s", fsp->name, VTY_NEWLINE);

		if (fsp->nr_queue_ids) {
			char q_str[256] = {};
			fsp_queue_ids_str(fsp, q_str, sizeof(q_str));
			vty_out(vty, " queue-id %s%s", q_str, VTY_NEWLINE);
		}

		for (i = 0; i < fsp->nr_maps; i++)
			vty_out(vty, " queue-id bind range-partition %s%s"
				   , fsp->maps[i].rp->name, VTY_NEWLINE);

		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_flow_steering_install(void)
{
	install_element(CONFIG_NODE, &flow_steering_policy_cmd);
	install_element(CONFIG_NODE, &no_flow_steering_policy_cmd);

	install_default(FLOW_STEERING_NODE);
	install_element(FLOW_STEERING_NODE, &flow_steering_queue_id_cmd);
	install_element(FLOW_STEERING_NODE, &flow_steering_bind_rp_cmd);
	install_element(FLOW_STEERING_NODE, &no_flow_steering_bind_rp_cmd);

	install_element(VIEW_NODE, &show_flow_steering_policy_cmd);
	install_element(ENABLE_NODE, &show_flow_steering_policy_cmd);

	return 0;
}

struct cmd_node flow_steering_node = {
	.node = FLOW_STEERING_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(flow-steering)# ",
	.config_write = gtp_flow_steering_config_write,
};

static struct cmd_ext cmd_ext_flow_steering = {
	.node = &flow_steering_node,
	.install = cmd_ext_flow_steering_install,
};

static void __attribute__((constructor))
gtp_flow_steering_vty_init(void)
{
	cmd_ext_register(&cmd_ext_flow_steering);
}
