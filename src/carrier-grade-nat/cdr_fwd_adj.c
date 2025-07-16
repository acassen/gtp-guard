/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2018, 2024, 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <assert.h>

#include "tools.h"
#include "cdr_fwd-priv.h"


static void _server_reconnect(struct cdr_fwd_server *sr);
static void _server_connect(struct _thread *ev);
static void _server_io_cb(struct _thread *ev);



/*
 * send a ticket, then ack when window is full
 */
void
cdr_fwd_adjacency_ticket(struct cdr_fwd_server *sr, struct cdr_fwd_ticket_buffer *t)
{
	/* send ticket */
	if (cdr_fwd_remote_send_data(sr, CDR_FWD_SND_TICKET, t) < 0)
		return;

	/* window full, ack this sequence */
	if (sr->cntsent >= sr->ctx->cfg.ack_window) {
		sr->cntrecv_low = sr->ctx->cfg.ack_window + 1;
		if (cdr_fwd_remote_send_data(sr, CDR_FWD_SND_ACK, NULL) < 0)
			return;

		/* wait for reply */
		sr->flags &= ~CDR_FWD_FL_READY;
		sr->state = 21;
	}
}


static void
_server_sm(struct cdr_fwd_server *sr)
{
	struct cdr_fwd_ticket_buffer t;

	trace2(sr->ctx->log, "%s: server_sm state=%d", sr->addr_str, sr->state);

	switch (sr->state) {
	case 0:
		sr->cntsent = 0;

		/* if last ack'ed data was in the past, restart at this position */
		if (sr->win_idx != -1 &&
		    (sr->win_idx != sr->cur_idx || sr->win_off != sr->cur_off))
			sr->flags |= CDR_FWD_FL_LATE;
		sr->cur_idx = sr->win_idx;
		sr->cur_off = sr->win_off;

		/* on connection, set transmission window size */
		if (cdr_fwd_remote_send_data(sr, CDR_FWD_SND_WND_SIZE, NULL) < 0)
			return;

		/* set cur sequence number */
		if (cdr_fwd_remote_send_data(sr, CDR_FWD_SND_NEWSEQ, NULL) < 0)
			return;

		sr->state = 20;
		/* fallthrough... */

	case 20:
		/* no spool to send */
		if (!(sr->flags & CDR_FWD_FL_LATE)) {
			sr->state = 30;
			sr->flags |= CDR_FWD_FL_READY;
			break;
		}

		/* send as much tickets from spool as we can */
		while ((sr->flags & CDR_FWD_FL_CONNECTED) && sr->state == 20) {
			if (!cdr_fwd_spool_read_ticket(sr, &t)) {
				info(sr->ctx->log, "%s: finished spool processing",
				     sr->addr_str);
				sr->flags &= ~CDR_FWD_FL_LATE;
				sr->flags |= CDR_FWD_FL_READY;
				sr->state = 30;
				break;
			}
			cdr_fwd_adjacency_ticket(sr, &t);
		}
		break;

	case 22:
		++sr->seq;

		/* the position we'll restart on disconnect */
		sr->win_idx = sr->cur_idx;
		sr->win_off = sr->cur_off;
		cdr_fwd_spool_save_wincur(sr);

		/* may rotate, if round-robin mode */
		if (sr->flags & CDR_FWD_FL_ROTATE) {
			if (cdr_fwd_remote_select_next(sr->ctx))
				return;
		}

		/* ready for next sequence! */
		if (cdr_fwd_remote_send_data(sr, CDR_FWD_SND_NEWSEQ, NULL) < 0)
			return;
		sr->state = 20;
		_server_sm(sr);
		return;

	case 23:
		/* negative ack. retransmit the window */
		sr->state = 10;
		_server_sm(sr);
		break;

	case 30:
		/* ready (wait for tickets) */
		break;
	}
}


static void
_server_got_ack(struct cdr_fwd_server *sr, bool need_retransmit)
{
	sr->cntsent = 0;

	if (need_retransmit) {
		info(sr->ctx->log, "%s: server ask for retransmit. "
		     "ignore this order, go to next seq", sr->addr_str);
	}

	switch (sr->state) {
	case 21:
		sr->state = 22;
		_server_sm(sr);
		break;

	default:
		warn(sr->ctx->log, "sm state bug, state=%d", sr->state);
		break;
	}
}

static void
_server_connect_cb(thread_t *ev)
{
	struct cdr_fwd_server *sr = THREAD_ARG(ev);
	struct _thread *io;
	unsigned val;
	int r, status;
	int fd = THREAD_FD(ev);
	timeval_t timer_min;

	if (ev->type == THREAD_WRITE_TIMEOUT ||
	    ev->type == THREAD_WRITE_ERROR) {
		warn(sr->ctx->log, "%s: timeout while connecting",
		     sr->addr_str);
		_server_reconnect(sr);
		return;
	}

	/* check if connect was successful */
	val = sizeof (status);
	status = 0;
	r = getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&status, &val);
	if (r) {
		err(sr->ctx->log, "getsockopt: %m");
		_server_reconnect(sr);
		return;
	}

	if (status == EINPROGRESS) {
		trace1(sr->ctx->log, "%s: connection still in-progress",
		       sr->addr_str);
		timer_min = timer_sub_now(ev->sands);
		io = thread_add_write(ev->master, _server_connect_cb,
				      sr, fd, -timer_long(timer_min), 0);
		assert(io != NULL);
		sr->io = io;
		return;
	}

	if (status) {
		errno = status;
		err(sr->ctx->log, "%s: connect: %m", sr->addr_str);
		_server_reconnect(sr);
		return;
	}

	/* ok, ready to send tickets. switch to READ event */
	trace1(sr->ctx->log, "%s: connected", sr->addr_str);
	io = thread_add_read(ev->master, _server_io_cb, sr,
			     fd, TIMER_NEVER, 0);
	assert(io != NULL);
	thread_del(sr->io);
	sr->io = io;
	sr->flags |= CDR_FWD_FL_CONNECTED;
	cdr_fwd_remote_connected(sr);
	_server_sm(sr);
}

static void
_server_io_cb(thread_t *ev)
{
	struct cdr_fwd_server *sr = THREAD_ARG(ev);
	uint8_t recv_buf[4100];
	int i, ret, seq;
	int fd = THREAD_FD(ev);

	if (ev->type == THREAD_READ_ERROR) {
		warn(sr->ctx->log, "%s: read error",
		     sr->addr_str);
		_server_reconnect(sr);
		return;
	}

	memcpy(recv_buf, sr->recv_buf, sr->recv_buf_size);
	ret = recv(fd, recv_buf + sr->recv_buf_size,
		   4096, MSG_NOSIGNAL);
	if (!ret) {
		err(sr->ctx->log, "%s: connection closed by peer",
		    sr->addr_str);
		_server_reconnect(sr);
		return;
	}
	if (ret < 0) {
		err(sr->ctx->log, "%s: recv: %m", sr->addr_str);
		_server_reconnect(sr);
		return;
	}
	ret += sr->recv_buf_size;
	sr->recv_buf_size = 0;

	for (i = 0; i < ret / (int)sizeof (seq); i++) {
		seq = *((int *)recv_buf + i);
		if (seq >= 0 && seq < sr->cntrecv_low)
			sr->cntrecv_low = seq;
		if (seq == -1)
			_server_got_ack(sr, sr->cntrecv_low <=
					sr->cntsent);
	}

	sr->recv_buf_size = ret % sizeof (seq);
	memcpy(sr->recv_buf, recv_buf + (ret / sizeof (seq)),
	       sr->recv_buf_size);

	if (sr->flags & CDR_FWD_FL_CONNECTED) {
		sr->io = thread_add_read(ev->master, _server_io_cb, sr,
					 fd, TIMER_NEVER, 0);
	}
}

/*
 * disconnect, and prepare reconnection
 */
static void
_server_reconnect(struct cdr_fwd_server *sr)
{
	trace1(sr->ctx->log, "%s: server_reconnect (was connected:%d)",
	       sr->addr_str, sr->flags & CDR_FWD_FL_CONNECTED);

	if (sr->io != NULL) {
		int fd = THREAD_FD(sr->io);
		thread_del(sr->io);
		sr->io = NULL;
		close(fd);
	}

	if (!(sr->flags & CDR_FWD_FL_CONNECTED)) {
		if (++sr->try_count > 30)
			sr->try_count = 30;
		sr->try_last = time(NULL);

	} else {
		sr->try_count = !!(time(NULL) < sr->try_last + 2);
		sr->try_last = time(NULL);
		sr->flags &= ~(CDR_FWD_FL_CONNECTED | CDR_FWD_FL_READY |
			       CDR_FWD_FL_ROTATE);

		sr->state = 0;
		sr->recv_buf_size = 0;

		disk_close_fd(&sr->cur_fd);

		debug(sr->ctx->log, "%s: closing connection", sr->addr_str);
	}

	/* set reconnect delay */
	if (sr->connect_ev == NULL) {
		sr->connect_ev =
			thread_add_timer(sr->ctx->cfg.loop, _server_connect,
					 sr, sr->try_count * 2 * USEC_PER_SEC);
	}
}


/*
 * async connect state machine
 */
static void
_server_connect(thread_t *ev)
{
	struct cdr_fwd_server *sr = THREAD_ARG(ev);
	int fd;
	int r;

	sr->connect_ev = NULL;

	/* connected, ignore this event */
	if (sr->flags & CDR_FWD_FL_CONNECTED)
		return;

	trace2(sr->ctx->log, "%s: connecting", sr->addr_str);
	sr->try_last = time(NULL);

	/* create socket */
	fd = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		err(sr->ctx->log, "socket: %m");
		_server_reconnect(sr);
		return;
	}

	/* increase write buffer */
	r = inet_setsockopt_sndbuf(fd, 8 * 1024 * 1024);
	r = (r) ? : inet_setsockopt_sndbufforce(fd, 8 * 1024 * 1024);

	/* set keepalive option */
	r = (r) ? : inet_setsockopt_tcp_keepcnt(fd, 3);
	r = (r) ? : inet_setsockopt_tcp_keepidle(fd, 60);
	r = (r) ? : inet_setsockopt_tcp_keepintvl(fd, 60);
	r = (r) ? : inet_setsockopt_keepalive(fd, 1);
	if (r) {
		err(sr->ctx->log, "setsockopt: %m");
		close(fd);
		_server_reconnect(sr);
		return;
	}

	/* local bind */
	if (sr->ctx->cfg.addr_ip_bound.sa.sa_family) {
		if (bind(fd, &sr->ctx->cfg.addr_ip_bound.sa,
			 addr_len(&sr->ctx->cfg.addr_ip_bound)) != 0) {
			err(sr->ctx->log, "bind: %m");
			close(fd);
			_server_reconnect(sr);
			return;
		}
	}

	/* connect */
	r = connect(fd, &sr->addr.sa, addr_len(&sr->addr));
	if (r && errno != EINPROGRESS) {
		err(sr->ctx->log, "%s: connect: %m", sr->addr_str);
		close(fd);
		_server_reconnect(sr);
		return;
	}

	if (!r) {
		/* ok, ready to send tickets */
		trace1(sr->ctx->log, "%s: connected (early)", sr->addr_str);
		sr->io = thread_add_read(ev->master, _server_io_cb, sr, fd,
					 TIMER_NEVER, 0);
		sr->flags |= CDR_FWD_FL_CONNECTED;
		cdr_fwd_remote_connected(sr);
		_server_sm(sr);
		return;
	}

	trace2(sr->ctx->log, "%s: connection in progress...",
	       sr->addr_str);
	sr->io = thread_add_write(ev->master, _server_connect_cb,
				  sr, fd, 8 * USEC_PER_SEC, 0);
}


void
cdr_fwd_adjacency_reset(struct cdr_fwd_server *sr)
{
	_server_reconnect(sr);
}

void
cdr_fwd_adjacency_init(struct cdr_fwd_server *sr)
{
	thread_add_event(sr->ctx->cfg.loop, _server_connect, sr, 0);
}

void
cdr_fwd_adjacency_release(struct cdr_fwd_server *sr)
{
	_server_reconnect(sr);
	thread_del(sr->connect_ev);
	sr->connect_ev = NULL;
}
