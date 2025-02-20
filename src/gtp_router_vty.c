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

/* system includes */
#include <pthread.h>
#include <sys/stat.h>
#include <net/if.h>
#include <errno.h>
#include <inttypes.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int gtp_config_write(vty_t *vty);
cmd_node_t gtp_router_node = {
        .node = GTP_ROUTER_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(gtp-router)# ",
	.config_write = gtp_config_write,
};


/*
 *	Command
 */
DEFUN(gtp_router,
      gtp_router_cmd,
      "gtp-router WORD",
      "Configure GTP routing context\n"
      "Context Name")
{
	gtp_router_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = gtp_router_get(argv[0]);
	if (!new)
		new = gtp_router_init(argv[0]);

	vty->node = GTP_ROUTER_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_gtp_router,
      no_gtp_router_cmd,
      "no gtp-router WORD",
      "Configure GTP routing context\n"
      "Context Name")
{
	gtp_router_t *ctx;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	ctx = gtp_router_get(argv[0]);
	if (!ctx) {
		vty_out(vty, "%% unknown gtp-router %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_router_ctx_destroy(ctx);
	FREE(ctx);

	return CMD_SUCCESS;
}

DEFUN(gtpc_router_tunnel_endpoint,
      gtpc_router_tunnel_endpoint_cmd,
      "gtpc-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535> [listener-count [INTEGER]]",
      "GTP Control channel tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2123)\n"
      "Number\n"
      "max UDP listener pthreads\n"
      "Number pthreads (default = "STR(GTP_DEFAULT_THREAD_CNT)")\n")
{
        gtp_router_t *ctx = vty->index;
        gtp_server_t *srv = &ctx->gtpc;
	struct sockaddr_storage *addr = &srv->addr;
	int port = 2123, ret = 0;

        if (argc < 1) {
                vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

        if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
                vty_out(vty, "%% GTPc already configured!%s", VTY_NEWLINE);
                return CMD_WARNING;
        }

        if (argc == 2)
                VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);

	ret = inet_stosockaddr(argv[0], port, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	/* argv[3] is listnener-count */
	srv->thread_cnt = (argc == 4) ? strtoul(argv[3], NULL, 10) : GTP_DEFAULT_THREAD_CNT;
	srv->thread_cnt = (srv->thread_cnt < 1) ? 1 : srv->thread_cnt;
	__set_bit(GTP_FL_CTL_BIT, &srv->flags);
	gtp_server_init(srv, ctx, gtp_router_ingress_init, gtp_router_ingress_process);
	gtp_server_start(srv);

	return CMD_SUCCESS;
}

DEFUN(gtpu_router_tunnel_endpoint,
      gtpu_router_tunnel_endpoint_cmd,
      "gtpu-tunnel-endpoint (A.B.C.D|X:X:X:X) port <1024-65535> [listener-count [INTEGER]]",
      "GTP Userplane channel tunnel endpoint\n"
      "Bind IPv4 Address\n"
      "Bind IPv6 Address\n"
      "listening UDP Port (default = 2152)\n"
      "Number\n"
      "max UDP listener pthreads\n"
      "Number pthreads (default = "STR(GTP_DEFAULT_THREAD_CNT)")\n")
{
	gtp_router_t *ctx = vty->index;
	gtp_server_t *srv = &ctx->gtpu;
	struct sockaddr_storage *addr = &srv->addr;
	int port = 2152, ret = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(GTP_FL_UPF_BIT, &srv->flags)) {
		vty_out(vty, "%% GTPu already configured!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc == 2)
		VTY_GET_INTEGER_RANGE("UDP Port", port, argv[1], 1024, 65535);

	ret = inet_stosockaddr(argv[0], port, addr);
	if (ret < 0) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	/* argv[3] is listnener-count */
	srv->thread_cnt = (argc == 4) ? strtoul(argv[3], NULL, 10) : GTP_DEFAULT_THREAD_CNT;
	srv->thread_cnt = (srv->thread_cnt < 1) ? 1 : srv->thread_cnt;
	__set_bit(GTP_FL_UPF_BIT, &srv->flags);
	gtp_server_init(srv, ctx, gtp_router_ingress_init, gtp_router_ingress_process);
	gtp_server_start(srv);

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
gtp_config_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->gtp_router_ctx;
	gtp_server_t *srv;
	gtp_router_t *ctx;

        list_for_each_entry(ctx, l, next) {
        	vty_out(vty, "gtp-router %s%s", ctx->name, VTY_NEWLINE);
		srv = &ctx->gtpc;
		if (__test_bit(GTP_FL_CTL_BIT, &srv->flags)) {
			vty_out(vty, " gtpc-tunnel-endpoint %s port %d"
				   , inet_sockaddrtos(&srv->addr)
				   , ntohs(inet_sockaddrport(&srv->addr)));
			if (srv->thread_cnt != GTP_DEFAULT_THREAD_CNT)
				vty_out(vty, " listener-count %d"
					   , srv->thread_cnt);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		srv = &ctx->gtpu;
		if (__test_bit(GTP_FL_UPF_BIT, &srv->flags)) {
			vty_out(vty, " gtpu-tunnel-endpoint %s port %d"
				   , inet_sockaddrtos(&srv->addr)
				   , ntohs(inet_sockaddrport(&srv->addr)));
			if (srv->thread_cnt != GTP_DEFAULT_THREAD_CNT)
				vty_out(vty, " listener-count %d"
					   , srv->thread_cnt);
			vty_out(vty, "%s" , VTY_NEWLINE);
		}
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/* XXX TODO, extend gtp_server_for_each_worker(gtp_server_t *srv, int (*hdl) (gtp_server_worker_t *)) */
static int
_gtp_server_for_each_worker(gtp_server_t *srv, int (*cb) (gtp_server_worker_t *, void *), void *arg)
{
	gtp_server_worker_t *w;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(w, &srv->workers, next)
		(*cb) (w, arg);
	pthread_mutex_unlock(&srv->workers_mutex);
	return 0;
}

struct vty_server_work_arg {
	vty_t *vty;
	const gtp_msg_type_map_t *msg_type2str;
};

static int
vty_server_worker(gtp_server_worker_t *w, void *arg)
{
	char flags2str[BUFSIZ];
	vty_t *vty = ((struct vty_server_work_arg *)arg)->vty;
	const gtp_msg_type_map_t *msg_type2str = ((struct vty_server_work_arg *)arg)->msg_type2str;
	char fdpath[PATH_MAX];

	vty_out(vty, "   %s worker %d task 0x%lx fd %d (%s)%s"
		     "    flags:%s%s"
		     "    seed:%d pbuff:%p (len:%d size:%d bytes)%s"
		     "    rx:%"PRIu64"bytes %"PRIu64"pkt | tx:%"PRIu64"bytes %"PRIu64"pkt%s"
		   , w->pname
		   , w->id
		   , w->task
		   , w->fd, w->fd >= 0 ? gtp_disk_fd2filename(w->fd, fdpath, sizeof(fdpath)) : "none"
		   , VTY_NEWLINE
		   , gtp_flags2str(flags2str, sizeof(flags2str), w->flags)
		   , VTY_NEWLINE
		   , w->seed , w->pbuff
		   , pkt_buffer_len(w->pbuff), pkt_buffer_size(w->pbuff)
		   , VTY_NEWLINE
		   , w->rx_bytes, w->rx_pkt
		   , w->tx_bytes, w->tx_pkt
		   , VTY_NEWLINE);

	vty_out(vty, "    RX:%s"
		   , VTY_NEWLINE);
	for (int i = 0; i < ARRAY_SIZE(w->msg_stats.rx); i++) {
		if (w->msg_stats.rx[i].count != 0)
			vty_out(vty, "     %s(%d): %d%s"
				   , msg_type2str
				       ? msg_type2str[i].name
				       : "null"
				   , i
				   , w->msg_stats.rx[i].count
				   , VTY_NEWLINE);
		if (w->msg_stats.rx[i].unsupported != 0)
			vty_out(vty, "     %s(%d): %d (not supported)%s"
				   , msg_type2str
				       ? msg_type2str[i].name ? msg_type2str[i].name : "bad type"
				       : "null"
				   , i
				   , w->msg_stats.rx[i].unsupported
				   , VTY_NEWLINE);
		if (w->cause_stats.rx[i].count != 0)
			vty_out(vty, "     %s(%d): %d%s"
				   , gtpc_msg_cause2str[i].name ? gtpc_msg_cause2str[i].name : "bad cause"
				   , i
				   , w->cause_stats.rx[i].count
				   , VTY_NEWLINE);
	}
	vty_out(vty, "    TX:%s"
		   , VTY_NEWLINE);
	for (int i = 0; i < ARRAY_SIZE(w->msg_stats.tx); i++) {
		if (w->msg_stats.tx[i].count != 0)
			vty_out(vty, "     %s(%d): %d%s"
				   , msg_type2str
				       ? msg_type2str[i].name
				       : "null"
				   , i
				   , w->msg_stats.tx[i].count
				   , VTY_NEWLINE);
		if (w->msg_stats.tx[i].unsupported != 0)
			vty_out(vty, "     %s(%d): %d (not supported)%s"
				   , msg_type2str
				       ? msg_type2str[i].name ? msg_type2str[i].name : "bad type"
				       : "null"
				   , i
				   , w->msg_stats.tx[i].unsupported
				   , VTY_NEWLINE);
		if (w->cause_stats.tx[i].count != 0)
			vty_out(vty, "     %s(%d): %d%s"
				   , gtpc_msg_cause2str[i].name ? gtpc_msg_cause2str[i].name : "bad cause"
				   , i
				   , w->cause_stats.tx[i].count
				   , VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

static int
vty_server(vty_t *vty, gtp_server_t *srv, const char *gtplane, const gtp_msg_type_map_t *msg_type2str)
{
	char flags2str[BUFSIZ];

	vty_out(vty, "  %s: %s port %d with %d threads%s"
		     "   flags:0x%lx (%s)%s"
		   , gtplane
		   , inet_sockaddrtos(&srv->addr)
		   , ntohs(inet_sockaddrport(&srv->addr))
		   , srv->thread_cnt
		   , VTY_NEWLINE
		   , srv->flags, gtp_flags2str(flags2str, sizeof(flags2str), srv->flags)
		   , VTY_NEWLINE);
	struct vty_server_work_arg arg = {
		.vty = vty,
		.msg_type2str = msg_type2str,
	};
	_gtp_server_for_each_worker(srv, vty_server_worker, &arg);

	return CMD_SUCCESS;
}

/* show handlers */
DEFUN(show_workers_gtp_router,
      show_workers_gtp_router_cmd,
      "show workers gtp-router (*|STRING) [plane (gtpu|gtpc|both)]",
      SHOW_STR
      "workers tasks\n"
      "gtp-router gtpc and gtpu workers\n"
      "all workers\n"
      "Router name\n"
      "GTPu\n"
      "GTPc\n"
      "both GTPu and GTPc\n")
{
	const list_head_t *l = &daemon_data->gtp_router_ctx;
	gtp_router_t *ctx;

	const char *name =  (argc > 0) ? argv[0] : "*";
	const char *plane = (argc > 2) ? argv[2] : "both";

        list_for_each_entry(ctx, l, next) {
		char flags2str[BUFSIZ];

		if ((name[0] != '*') && (strcmp(name, ctx->name) != 0))
			continue;

		vty_out(vty, "gtp-router %s refcnt:%d%s"
			     " flags:0x%lx (%s)%s"
			   , ctx->name
			   , ctx->refcnt
			   , VTY_NEWLINE
			   , ctx->flags, gtp_flags2str(flags2str, sizeof(flags2str), ctx->flags)
			   , VTY_NEWLINE);

		if ((strcmp(plane, "both") == 0) ||
		    (strcmp(plane, "gtpc") == 0)) {
			gtp_server_t *srv = &ctx->gtpc;
			if (__test_bit(GTP_FL_CTL_BIT, &srv->flags))
				vty_server(vty, srv, "gtpc", gtpc_msg_type2str);
			else
				vty_out(vty, "  gtpc: none%s"
					   , VTY_NEWLINE);
		}

		if ((strcmp(plane, "both") == 0) ||
		    (strcmp(plane, "gtpu") == 0)) {
			gtp_server_t *srv = &ctx->gtpu;
			if (__test_bit(GTP_FL_UPF_BIT, &srv->flags))
				vty_server(vty, srv, "gtpu", gtpu_msg_type2str);
			else
				vty_out(vty, "  gtpu: none%s"
					   , VTY_NEWLINE);
		}
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_router_vty_init(void)
{
	/* Install PDN commands. */
	install_node(&gtp_router_node);
	install_element(CONFIG_NODE, &gtp_router_cmd);
	install_element(CONFIG_NODE, &no_gtp_router_cmd);

	install_default(GTP_ROUTER_NODE);
	install_element(GTP_ROUTER_NODE, &gtpc_router_tunnel_endpoint_cmd);
	install_element(GTP_ROUTER_NODE, &gtpu_router_tunnel_endpoint_cmd);

	install_element(ENABLE_NODE, &show_workers_gtp_router_cmd);

	return 0;
}
