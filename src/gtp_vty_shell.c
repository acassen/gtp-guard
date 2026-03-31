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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>
#include <arpa/telnet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "thread.h"

enum telnet_state {
	TEL_NORMAL,
	TEL_IAC,
	TEL_OPT,
	TEL_SB,
	TEL_SB_IAC,
};

struct gtp_vtysh {
	int sock_fd;
	struct termios orig;
	struct thread_master *master;
	struct thread *t_stdin;
	struct thread *t_sock;
	enum telnet_state tel_state;
	unsigned char tel_cmd;
};
static struct gtp_vtysh gtp_vtysh_data;

static void gtp_vtysh_stdin_read(struct thread *t);
static void gtp_vtysh_sock_read(struct thread *t);


static ssize_t
gtp_vtysh_send_naws(int fd)
{
	/* struct winsize layout: ws_row, ws_col, ws_xpixel, ws_ypixel */
	unsigned short winsz[4] = {24, 80, 0, 0};
	unsigned char buf[12];
	int len = 0;

	ioctl(STDIN_FILENO, TIOCGWINSZ, winsz);

	buf[len++] = IAC;
	buf[len++] = WILL;
	buf[len++] = TELOPT_NAWS;
	buf[len++] = IAC;
	buf[len++] = SB;
	buf[len++] = TELOPT_NAWS;
	buf[len++] = (winsz[1] >> 8) & 0xff;	/* cols high */
	buf[len++] = winsz[1] & 0xff;		/* cols low */
	buf[len++] = (winsz[0] >> 8) & 0xff;	/* rows high */
	buf[len++] = winsz[0] & 0xff;		/* rows low */
	buf[len++] = IAC;
	buf[len++] = SE;
	return write(fd, buf, len);
}

static void
gtp_vtysh_sigwinch(__attribute__((unused)) int sig)
{
	gtp_vtysh_send_naws(gtp_vtysh_data.sock_fd);
}

static void
gtp_vtysh_signal_handler(__attribute__((unused)) int sig)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &gtp_vtysh_data.orig);
	_exit(1);
}

static void
gtp_vtysh_close(struct gtp_vtysh *ctx)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &ctx->orig);
	close(ctx->sock_fd);
	thread_add_terminate_event(ctx->master);
}


/*
 *	Strip IAC sequences from telnet server output.
 */
static int
gtp_vtysh_telnet_filter(struct gtp_vtysh *ctx, const unsigned char *in,
			int inlen, unsigned char *out, int outsize)
{
	int i, pos = 0;

	for (i = 0; i < inlen && pos < outsize; i++) {
		unsigned char c = in[i];

		switch (ctx->tel_state) {
		case TEL_NORMAL:
			if (c == IAC)
				ctx->tel_state = TEL_IAC;
			else
				out[pos++] = c;
			break;
		case TEL_IAC:
			switch (c) {
			case IAC:
				/* Escaped 0xFF */
				out[pos++] = IAC;
				ctx->tel_state = TEL_NORMAL;
				break;
			case SB:
				ctx->tel_state = TEL_SB;
				break;
			case WILL:
			case WONT:
			case DO:
			case DONT:
				ctx->tel_cmd = c;
				ctx->tel_state = TEL_OPT;
				break;
			default:
				/* Other 2-byte command */
				ctx->tel_state = TEL_NORMAL;
				break;
			}
			break;
		case TEL_OPT:
			if (ctx->tel_cmd == DO && c == TELOPT_NAWS)
				gtp_vtysh_send_naws(ctx->sock_fd);
			ctx->tel_state = TEL_NORMAL;
			break;
		case TEL_SB:
			if (c == IAC)
				ctx->tel_state = TEL_SB_IAC;
			break;
		case TEL_SB_IAC:
			if (c == SE)
				ctx->tel_state = TEL_NORMAL;
			else
				ctx->tel_state = TEL_SB;
			break;
		}
	}

	return pos;
}


/*
 *	stdin to socket relay
 */
static void
gtp_vtysh_stdin_read(struct thread *t)
{
	struct gtp_vtysh *ctx = THREAD_ARG(t);
	char buf[512];
	ssize_t n;

	n = read(STDIN_FILENO, buf, sizeof(buf));
	if (n <= 0)
		goto close;

	if (write(ctx->sock_fd, buf, n) != n)
		goto close;

	ctx->t_stdin = thread_add_read(ctx->master, gtp_vtysh_stdin_read, ctx,
				       STDIN_FILENO, TIMER_NEVER, 0);
	return;

close:
	ctx->t_stdin = NULL;
	gtp_vtysh_close(ctx);
	return;

}


/*
 *	socket to stdout relay
 */
static void
gtp_vtysh_sock_read(struct thread *t)
{
	struct gtp_vtysh *ctx = THREAD_ARG(t);
	unsigned char buf[512];
	unsigned char filtered[512];
	ssize_t n;
	int flen;

	n = read(ctx->sock_fd, buf, sizeof(buf));
	if (n <= 0)
		goto close;

	flen = gtp_vtysh_telnet_filter(ctx, buf, n, filtered, sizeof(filtered));
	if (flen > 0 && write(STDOUT_FILENO, filtered, flen) != flen)
		goto close;

	ctx->t_sock = thread_add_read(ctx->master, gtp_vtysh_sock_read, ctx,
				      ctx->sock_fd, TIMER_NEVER, 0);
	return;

close:
	ctx->t_sock = NULL;
	gtp_vtysh_close(ctx);
	return;
}


/*
 *	Connect to AF_UNIX vty socket and act as a telnet client
 */
int
gtp_vtysh(const char *path)
{
	struct gtp_vtysh *ctx = &gtp_vtysh_data;
	struct sockaddr_un addr;
	struct termios raw;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Error creating socket (%m)\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Error connectinf to %s (%m)\n", path);
		goto err;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->sock_fd = fd;

	if (tcgetattr(STDIN_FILENO, &ctx->orig) < 0) {
		fprintf(stderr, "tcgetattr error (%m)\n");
		goto err;
	}

	ctx->master = thread_make_master(true);
	if (!ctx->master) {
		fprintf(stderr, "Failed to create scheduler\n");
		goto err;
	}

	/* Restore terminal on fatal signals */
	signal(SIGINT, gtp_vtysh_signal_handler);
	signal(SIGTERM, gtp_vtysh_signal_handler);
	signal(SIGQUIT, gtp_vtysh_signal_handler);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGHUP, gtp_vtysh_signal_handler);
	signal(SIGWINCH, gtp_vtysh_sigwinch);

	raw = ctx->orig;
	cfmakeraw(&raw);
	tcsetattr(STDIN_FILENO, TCSANOW, &raw);

	ctx->t_stdin = thread_add_read(ctx->master, gtp_vtysh_stdin_read, ctx,
				       STDIN_FILENO, TIMER_NEVER, 0);
	ctx->t_sock = thread_add_read(ctx->master, gtp_vtysh_sock_read, ctx,
				      ctx->sock_fd, TIMER_NEVER, 0);

	launch_thread_scheduler(ctx->master);

	thread_destroy_master(ctx->master);
	return 0;

err:
	close(fd);
	return -1;
}
