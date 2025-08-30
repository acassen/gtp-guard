/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2011, 2018, 2024, 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "tools.h"
#include "signals.h"
#include "cdr_fwd-priv.h"
#include "cdr_avp.h"


/* globals */
uint64_t cdrlog = 3;	/* trace1 + trace2 */
struct thread_master *master;
static int sigint;


static void
sigint_hdl(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	if (++sigint > 2) {
		fprintf(stderr, "ctrl-C pressed too much, dying hard\n");
		exit(1);
	}

	if (sigint == 1) {
		fprintf(stderr, "shutting down\n");
		thread_add_terminate_event(master);
	}

}

static struct cdr_fwd_context *ctx;
static struct thread *tick_ev;
static int k;


static void
_tick_cb(struct thread *t)
{
	uint8_t data[50];
	char b[1000];
	int n;

	if (k == 0) {
		cdr_fwd_ctx_dump(ctx, b, sizeof (b));
		printf("%s\n", b);
	}

	printf("tick-et %d\n", k);

	n = sprintf((char *)data, "%d", k + 1);
	cdr_fwd_send_ticket(ctx, data, n + 1);
	k++;

	tick_ev = thread_add_timer(master, _tick_cb, NULL, USEC_PER_SEC);
}


static void
test_ticket_async(void)
{
	struct cdr_fwd_config cdrcfg;
	union addr addr[4];
	//char b[1000];

	memset(&cdrcfg, 0x00, sizeof (cdrcfg));
	cdrcfg.log = cdrlog;
	cdrcfg.loop = master;
	cdrcfg.ack_window = 10;
	cdrcfg.rr_roll_period = 5;
	/* cdrcfg.lb_mode = CDR_FWD_MODE_ACTIVE_ACTIVE; */
	/* cdrcfg.lb_mode = CDR_FWD_MODE_FAIL_OVER; */
	cdrcfg.lb_mode = CDR_FWD_MODE_ROUND_ROBIN;
	strcpy(cdrcfg.spool_path, "test_spool");
	addr_parse_const("127.0.0.1:1664", &addr[0]);
	addr_parse_const("127.0.0.1:1665", &addr[1]);
	addr_parse_const("127.0.0.1:1666", &addr[2]);
	addr_zero(&addr[3]);
	ctx = cdr_fwd_ctx_create(&cdrcfg, addr);

	tick_ev = thread_add_timer(master, _tick_cb, NULL, USEC_PER_SEC);
}


struct srv_ctx
{
	struct thread *io;
	int64_t seq;
	int win_size;
	int nb_processed;
};

static void
_server_io_cb(struct thread *ev)
{
	struct srv_ctx *srv = ev->arg;
	static uint8_t recv_buf[8000];
	static int recv_buf_size;
	struct cdr_fwd_ticket_buffer *t;
	int ret, i, ack;
	int fd = ev->u.f.fd;

	ret = recv(fd, recv_buf + recv_buf_size,
		   4096 - recv_buf_size, MSG_NOSIGNAL);
	if (!ret) {
		err(cdrlog, "connection closed by peer");
		info(cdrlog, "processed tickets: %d", srv->nb_processed);
		goto err;
	}
	if (ret < 0) {
		err(cdrlog, "recv: %m");
		goto err;
	}
	ret += recv_buf_size;
	recv_buf_size = 0;

	for (i = 0; i < ret - 8; ) {
		printf("read at %d/%d\n", i, ret);
		t = (struct cdr_fwd_ticket_buffer *)(recv_buf + i);
		if (t->size > CDR_FWD_TICKETS_MAX_BUFF ||
		    (int)t->size + 8 > ret - i) {
			printf("invalid ticket size: %d/%d\n",
			       t->size, ret - i);
			goto err;
		}
		switch (t->mtype) {
		case -3:
			if (srv->win_size) {
				printf("disconnect client\n");
				info(cdrlog, "processed tickets: %d", srv->nb_processed);
				goto err;
			}
			printf("set window size=%s (size=%d)\n",
			       t->mtext, t->size);
			srv->win_size = atol(t->mtext);
			break;
		case -2:
			printf("set newseq=%s\n", t->mtext);
			srv->seq = atoll(t->mtext);
			break;
		case -1:
			printf("ask for ack\n");
			ack = -1;
			write(fd, &ack, 4);
			break;
		default:
			if (t->mtype > srv->win_size)
				printf("XXXXX recv cntsent > ack_win (%d/%d)",
				       t->mtype, srv->win_size);
			else
				++srv->nb_processed;
			printf("recv cnt=%d size=%d ticket=%s\n",
			       t->mtype, t->size, t->mtext);
			break;
		}
		i += 8 + t->size + 4;
	}

	recv_buf_size = ret - i;
	memcpy(recv_buf, recv_buf + i, recv_buf_size);
	srv->io = thread_add_read(master, _server_io_cb, srv,
				  fd, TIMER_NEVER, 0);
	return;

 err:
	thread_del(srv->io);
	close(fd);
	free(srv);
	return;
}

static void
_server_accept(struct thread *ev)
{
	struct srv_ctx *srv;
	union addr ra;
	socklen_t ral;
	int afd = ev->u.f.fd;
	int fd;

	ral = sizeof (ra);
	fd = accept(afd, &ra.sa, &ral);
	if (fd < 0) {
		err(cdrlog, "accept: %m");
		return;
	}

	printf("new connection accepted, fd %d from accept fd %d\n", fd, afd);
	srv = calloc(1, sizeof (*srv));
	srv->io = thread_add_read(master, _server_io_cb, srv, fd, TIMER_NEVER, 0);

	thread_add_read(master, _server_accept, NULL, afd, TIMER_NEVER, 0);
}

static void
fake_server(void)
{
	union addr addr;
	char buf[64];
	int fd, r, i;
	int on = 1;

	addr_parse_const("127.0.0.1", &addr);

	for (i = 0; i < 3; i++) {
		fd = socket(PF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			err(cdrlog, "socket: %m");
			return;
		}
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0) {
			err(cdrlog, "setsockopt: %m");
			close(fd);
			return;
		}
		addr_set_port(&addr, 1664 + i);
		r = bind(fd, &addr.sa, addr_len(&addr));
		if (r < 0) {
			err(cdrlog, "bind: %m");
			close(fd);
			return;
		}
		r = listen(fd, 10);
		if (r < 0) {
			err(cdrlog, "listen: %m");
			close(fd);
			return;
		}

		thread_add_read(master, _server_accept, NULL, fd, TIMER_NEVER, 0);

		debug(cdrlog, "listening on %s", addr_stringify(&addr, buf, sizeof (buf)));
	}
}

int
main(int argc, char **argv)
{
	const char *cmd = "<unset>";
	int ret = 0;

	srand(time(NULL));
	enable_console_log();
	master = thread_make_master(false);

	if (argc > 1)
		cmd = argv[1];

	system("mkdir test_spool 2> /dev/null || rm -f test_spool/*");

	if (!strcmp(cmd, "client"))
		test_ticket_async();
	else if (!strcmp(cmd, "server"))
		fake_server();
	else {
		printf("unknown command %s\n", cmd);
		goto exit;
	}


	if (isatty(STDIN_FILENO))
		signal_set(SIGINT, sigint_hdl, NULL);

	launch_thread_scheduler(master);

 exit:
	if (ctx != NULL)
		cdr_fwd_ctx_release(ctx);

	thread_destroy_master(master);

	return ret;
}
