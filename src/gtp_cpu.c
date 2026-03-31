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

#include "logger.h"
#include "thread.h"
#include "cpu.h"

/* Local data */
static struct cpu_load *cpu_load;

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Polling thread
 */
static void
gtp_cpu_poll(struct thread *t)
{
	int i;

	cpu_load_update(cpu_load);

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		float load = cpu_load_get(cpu_load, i);
	        if (load < 0.0f)
			continue;   /* offline CPU */
#if 0
		printf("CPU #%i : %f\n", i, load*100);
#endif
	}

	thread_add_timer(master, gtp_cpu_poll, NULL, TIMER_HZ / 5);
}


/*
 *	Tunnel ID tracking init
 */
int
gtp_cpu_init(void)
{
	if (cpu_load_init_tsc(&cpu_load)) {
		log_message(LOG_INFO, "%s(): Error initializing CPU monitoring (%m)"
				    , __FUNCTION__);
		return -1;
	}

	thread_add_event(master, gtp_cpu_poll, NULL, 0);
	return 0;
}

int
gtp_cpu_destroy(void)
{
	cpu_load_destroy(cpu_load);	
	return 0;
}
