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

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include "command.h"
#include "vty.h"
#include "thread.h"
#include "timer.h"
#include "buffer.h"
#include "gtp_cpu.h"

/* Extern data */
extern struct thread_master *master;

/* ANSI escape sequences */
#define MONITOR_CLEAR_SCREEN	"\033[2J\033[H"
#define MONITOR_CURSOR_HOME	"\033[H"
#define MONITOR_ERASE_TAIL	"\033[0J"

/* Private data */
struct gtp_monitor {
	struct vty	*vty;
	int		(*show) (struct vty *);
	uint64_t	timer;
};

static void
gtp_monitor_stop(struct gtp_monitor *m)
{
	struct vty *vty = m->vty;

	vty->index = NULL;
	vty_prompt_restore(vty);
	vty_read_resume(vty);
	free(m);
}

static void
gtp_monitor_refresh(struct thread *t)
{
	struct gtp_monitor *m = THREAD_ARG(t);
	struct vty *vty = m->vty;
	unsigned char buf[64];

	/* VTY is closing */
	if (vty->status == VTY_CLOSE) {
		free(m);
		return;
	}

	/* vty_read() re-registers itself after the command handler
	 * returns. cancel it each time to be sure.
	 */
	if (vty->t_read) {
		thread_del(vty->t_read);
		vty->t_read = NULL;
	}

	/* Any keypress stops the monitor */
	if (recv(vty->fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
		gtp_monitor_stop(m);
		return;
	}

	vty_send_out(vty, MONITOR_CURSOR_HOME);
	m->show(vty);
	vty_out(vty, "%s-- press any key to stop --%s", VTY_NEWLINE, VTY_NEWLINE);
	buffer_flush_all(vty->obuf, vty->fd);
	vty_send_out(vty, MONITOR_ERASE_TAIL);

	thread_add_timer(master, gtp_monitor_refresh, m, m->timer);
}

static int
gtp_monitor_start(struct vty *vty, int interval, int (*show) (struct vty *))
{
	struct gtp_monitor *m;

	m = calloc(1, sizeof(*m));
	if (!m) {
		vty_out(vty, "%% out of memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	m->vty = vty;
	m->show = show;
	m->timer = interval * TIMER_HZ;

	vty->index = m;
	vty_prompt_hold(vty);
	vty_send_out(vty, MONITOR_CLEAR_SCREEN);
	buffer_reset(vty->obuf);

	thread_add_event(master, gtp_monitor_refresh, m, 0);
	return CMD_SUCCESS;
}


/*
 *	VTY commands
 */
DEFUN(monitor_system_cpu,
      monitor_system_cpu_cmd,
      "monitor <1-60> system cpu",
      "Refresh display\n"
      "Refresh interval in seconds\n"
      "System information\n"
      "Per-core CPU utilization\n")
{
	int interval;

	VTY_GET_INTEGER_RANGE("interval", interval, argv[0], 1, 60);
	return gtp_monitor_start(vty, interval, gtp_cpu_show);
}

DEFUN(monitor_interface_rxq,
      monitor_interface_rxq_cmd,
      "monitor <1-60> interface rx-queue",
      "Refresh display\n"
      "Refresh interval in seconds\n"
      "Interface information\n"
      "RX queue\n")
{
	/* TODO */
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_monitor_install(void)
{
	install_element(VIEW_NODE, &monitor_system_cpu_cmd);
	install_element(VIEW_NODE, &monitor_interface_rxq_cmd);
	install_element(ENABLE_NODE, &monitor_system_cpu_cmd);
	install_element(ENABLE_NODE, &monitor_interface_rxq_cmd);
	return 0;
}

static struct cmd_ext cmd_ext_monitor = {
	.node = NULL,
	.install = cmd_ext_monitor_install,
};

static void __attribute__((constructor))
gtp_vty_monitor_init(void)
{
	cmd_ext_register(&cmd_ext_monitor);
}
