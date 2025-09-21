/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2024, 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */


#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "tools.h"
#include "utils.h"
#include "disk.h"
#include "cdr_fwd-priv.h"


int
cdr_fwd_remote_send_data(struct cdr_fwd_server *sr, int cmd,
			 struct cdr_fwd_ticket_buffer *t)
{
	struct cdr_fwd_ticket_buffer tc;
	uint32_t crc_value = 0xbab1bab1;
	struct msghdr msg;
	struct iovec iov[2];
	int nbytes;

	if (!(sr->flags & CDR_FWD_FL_CONNECTED))
		return -1;

	switch (cmd) {
	case CDR_FWD_SND_WND_SIZE:
		trace1(sr->ctx->log, "%s: sending ack_window=%u",
		       sr->addr_str, sr->ctx->cfg.ack_window);
		tc.size = sprintf(tc.mtext, "%d", sr->ctx->cfg.ack_window) + 1;
		tc.mtype = -3;
		iov[0].iov_base = &tc;
		iov[0].iov_len = tc.size + sizeof (tc.size) + sizeof (tc.mtype);
		break;

	case CDR_FWD_SND_NEWSEQ:
		if (sr->ctx->cfg.instance_id)
			tc.size = sprintf(tc.mtext, "%d_%u",
					  sr->ctx->cfg.instance_id, sr->seq) + 1;
		else
			tc.size = sprintf(tc.mtext, "%u", sr->seq) + 1;
		trace1(sr->ctx->log, "%s: sending new_seq=%s",
		       sr->addr_str, tc.mtext);
		tc.mtype = -2;
		iov[0].iov_base = &tc;
		iov[0].iov_len = tc.size + sizeof (tc.size) + sizeof (tc.mtype);
		break;

	case CDR_FWD_SND_ACK:
		trace1(sr->ctx->log, "%s: send ack, seq=%u; cntsent=%d",
		       sr->addr_str, sr->seq, sr->cntsent);
		tc.size = 1;
		tc.mtype = -1;
		tc.mtext[0] = 0;
		iov[0].iov_base = &tc;
		iov[0].iov_len = tc.size + sizeof (tc.size) + sizeof (tc.mtype);
		break;

	case CDR_FWD_SND_TICKET:
		trace2(sr->ctx->log, "%s: send ticket, seq=%u; cnt=%d; size=%d",
		       sr->addr_str, sr->seq, sr->cntsent + 1, t->size);
		t->mtype = ++sr->cntsent;
		iov[0].iov_base = t;
		iov[0].iov_len = t->size + sizeof (t->size) + sizeof (t->mtype);
		++sr->st_tickets_out;
		sr->st_bytes_out += t->size;
		break;

	default:
		abort();
	}

	/* add fake crc */
	iov[1].iov_base = &crc_value;
	iov[1].iov_len = 4;

	/* send data */
	memset(&msg, 0x00, sizeof (msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	nbytes = sendmsg(sr->io->u.f.fd, &msg, MSG_NOSIGNAL);
	if (nbytes <= 0) {
		err(sr->ctx->log, "%s: send: %s",
		    sr->addr_str,
		    (nbytes == -1) ? strerror(errno) : "closed connection");
		cdr_fwd_remote_reset(sr);
		return -1;
	}

	return 0;
}

void
cdr_fwd_remote_reset(struct cdr_fwd_server *sr)
{
	if (!(sr->flags & CDR_FWD_FL_CONNECTED))
		return;

	if (sr == sr->ctx->active_sr)
		sr->ctx->active_reco_recent = time(NULL);

	cdr_fwd_adjacency_reset(sr);
}


void
cdr_fwd_remote_connected(struct cdr_fwd_server *sr)
{
	if (sr == sr->ctx->active_sr) {
		if (sr->ctx->active_reco_recent &&
		    sr->ctx->active_reco_recent + 60 > time(NULL)) {
			sr->ctx->active_reco_n++;
		} else {
			sr->ctx->active_reco_recent = time(NULL);
			sr->ctx->active_reco_n = 0;
		}
	}
}


static bool
cdr_fwd_remote_select(struct cdr_fwd_context *ctx, struct cdr_fwd_server *new)
{
	struct cdr_fwd_server *old = ctx->active_sr;

	/* no need to select a server in active-active mode */
	if (ctx->cfg.lb_mode == CDR_FWD_MODE_ACTIVE_ACTIVE)
		return false;

	/* no change */
	if (old == new) {
		if (new != NULL)
			new->flags &= ~CDR_FWD_FL_ROTATE;
		return false;
	}

	info(ctx->log, "set new active server: %s => %s",
	     old != NULL ? old->addr_str : "none",
	     new != NULL ? new->addr_str : "none");

	/* disconnect previous active server */
	if (old != NULL) {
		old->flags &= ~(CDR_FWD_FL_ACTIVE | CDR_FWD_FL_ROTATE);
		cdr_fwd_spool_save_wincur(old);
		cdr_fwd_adjacency_release(old);
	}

	/* connect new active server */
	if (new != NULL) {
		new->flags |= CDR_FWD_FL_ACTIVE;

		/* transfer current window data, or get from index file */
		if (old != NULL) {
			new->win_idx = old->win_idx;
			new->win_off = old->win_off;
			new->seq = old->seq;
			new->flags |= CDR_FWD_FL_LATE;
			cdr_fwd_spool_save_wincur(new);
		} else {
			cdr_fwd_spool_restore_wincur(new);
		}

		cdr_fwd_adjacency_init(new);
	}

	ctx->active_reco_n = 0;
	ctx->active_reco_recent = 0;
	ctx->active_since = time(NULL);
	ctx->active_sr = new;

	return true;
}

bool
cdr_fwd_remote_select_next(struct cdr_fwd_context *ctx)
{
	struct cdr_fwd_server *new = NULL;

	/* choose next entry from remote_list */
	if (!list_empty(&ctx->remote_list)) {
		if (ctx->active_sr == NULL) {
			new = list_first_entry(&ctx->remote_list,
					       struct cdr_fwd_server, list);
		} else {
			new = list_next_entry(ctx->active_sr, list);
			if (list_entry_is_head(new, &ctx->remote_list, list))
				new = list_next_entry(new, list);
		}
	}

	return cdr_fwd_remote_select(ctx, new);
}

bool
cdr_fwd_remote_select_addr(struct cdr_fwd_context *ctx, const union addr *a)
{
	struct cdr_fwd_server *sr;

	list_for_each_entry(sr, &ctx->remote_list, list) {
		if (!addr_cmp(a, &sr->addr)) {
			debug(ctx->log, "%s: selecting", sr->addr_str);
			return cdr_fwd_remote_select(ctx, sr);
		}
	}
	return false;
}

static void
cdr_fwd_remote_check(struct cdr_fwd_context *ctx)
{
	time_t now = time(NULL);

	if (ctx->active_sr == NULL)
		return;

	if (!(ctx->active_sr->flags & CDR_FWD_FL_CONNECTED) &&
	    ctx->active_since + 120 < now &&
	    (ctx->active_reco_recent + 60 < now ||
	     ctx->active_reco_n >= 6)) {
		if (ctx->active_reco_n >= 6) {
			info(ctx->log, "%s: %d re-connections since %ld seconds, "
			     "select next server",
			     ctx->active_sr->addr_str,
			     ctx->active_reco_n, now - ctx->active_reco_recent);
		} else if (ctx->active_reco_recent) {
			info(ctx->log, "%s: not connected since %ld seconds, "
			     "select next server",
			     ctx->active_sr->addr_str, now - ctx->active_reco_recent);
		} else {
			info(ctx->log, "%s: can not connect, select next server",
			     ctx->active_sr->addr_str);
		}
		cdr_fwd_remote_select_next(ctx);
	}

	if (ctx->cfg.lb_mode == CDR_FWD_MODE_ROUND_ROBIN &&
	    ctx->active_since + ctx->cfg.rr_roll_period < now &&
	    !(ctx->active_sr->flags & CDR_FWD_FL_ROTATE)) {
		info(ctx->log, "%s: round-robin, time to switch server",
		     ctx->active_sr->addr_str);
		ctx->active_sr->flags |= CDR_FWD_FL_ROTATE;
	}
}

static void
_tick_remote_check(struct thread *ev)
{
	struct cdr_fwd_context *ctx = ev->arg;

	cdr_fwd_remote_check(ctx);
	ctx->active_tick = thread_add_timer(ctx->cfg.loop, _tick_remote_check,
					  ctx, USEC_PER_SEC);
}


static char *
_time_to_str(time_t t, char *b, int len)
{
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(b, len, "%Y-%m-%d %H:%M:%S", &tm);
	return b;
}

int
cdr_fwd_ctx_dump(const struct cdr_fwd_context *ctx, char *b, size_t s)
{
	struct cdr_fwd_server *sr;
	char buf[64];
	time_t ts = 0;
	int i, k = 0;
	off_t total = 0;

	k += scnprintf(b + k, s - k, "config:\n");
	k += scnprintf(b + k, s - k, "  spool_path: %s\n",
		       ctx->cfg.spool_path);
	k += scnprintf(b + k, s - k, "  roll_period: %d seconds\n",
		       ctx->cfg.roll_period);
	k += scnprintf(b + k, s - k, "  load balancing mode: %d\n",
		       ctx->cfg.lb_mode);
	if (ctx->cfg.lb_mode == CDR_FWD_MODE_ROUND_ROBIN)
		k += scnprintf(b + k, s - k, "  round-robin switch period: %d seconds\n",
			       ctx->cfg.rr_roll_period);
	k += scnprintf(b + k, s - k, "  ack_window: %d\n",
		       ctx->cfg.ack_window);
	k += scnprintf(b + k, s - k, "  instance_id: %d\n",
		       ctx->cfg.instance_id);
	k += scnprintf(b + k, s - k, "spool:\n");
	if (ctx->flags & CDR_FWD_FL_CTX_SPOOL_ONLY)
		k += scnprintf(b + k, s - k, "  force spool, send tickets only on periodic()\n");
	k += scnprintf(b + k, s - k, "  stored    : low:%d high:%d alloc_size:%d\n",
		       ctx->spool_f_l, ctx->spool_f_u, ctx->spool_f_m);
	bool more = false;
	for (i = ctx->spool_f_l; i < ctx->spool_f_u; i++) {
		total += ctx->spool_f[i].size;
		if ((i > ctx->spool_f_l + 12) && (i < ctx->spool_f_u - 12)) {
			if (!more) {
				k += scnprintf(b + k, s - k, "    ...\n");
				more = true;
			}
			continue;
		}
		k += scnprintf(b + k, s - k, "    [%04d] %s (%ld, %ld bytes)\n",
			       i, _time_to_str(ctx->spool_f[i].ts, buf, sizeof (buf)),
			       ctx->spool_f[i].ts, ctx->spool_f[i].size);
		ts = ctx->spool_f[i].ts;
	}
	k += scnprintf(b + k, s - k, "  total size: %ld bytes\n", total);
	if (ctx->disk_next_check)
		k += scnprintf(b + k, s - k, "  disk usage: %.2f%%\n",
			       (1. - ctx->disk_avail) * 100.);
	k += scnprintf(b + k, s - k, "  writing   : fd=%d ts=%ld idx=%d off=%ld\n",
		       ctx->spool_wr_fd, ts, ctx->spool_wr_idx, ctx->spool_wr_off);
	k += scnprintf(b + k, s - k, "    stats   : ticket=%ld ",
		       ctx->st_tickets_in);
	k += scnprintf(b + k, s - k, "bytes=%ld\n", ctx->st_bytes_in);

	if (ctx->active_sr != NULL) {
		k += scnprintf(b + k, s - k, "current server:\n  addr       : %s\n",
			       ctx->active_sr->addr_str);
		k += scnprintf(b + k, s - k, "  since      : %s\n",
			       _time_to_str(ctx->active_since, buf, sizeof (buf)));
		k += scnprintf(b + k, s - k, "  recent reco: %s  count=%d\n",
			       _time_to_str(ctx->active_reco_recent, buf, sizeof (buf)),
					    ctx->active_reco_n);
	}

	k += scnprintf(b + k, s - k, "remotes:\n");
	list_for_each_entry(sr, &ctx->remote_list, list) {
		k += scnprintf(b + k, s - k, "  addr: %s\n    flags    :",
			       sr->addr_str);
		if (sr->flags & CDR_FWD_FL_ACTIVE)
			k += scnprintf(b + k, s - k, " active");
		if (sr->flags & CDR_FWD_FL_CONNECTED)
			k += scnprintf(b + k, s - k, " connected");
		if (sr->flags & CDR_FWD_FL_LATE)
			k += scnprintf(b + k, s - k, " late");
		if (sr->flags & CDR_FWD_FL_READY)
			k += scnprintf(b + k, s - k, " ready");
		if (sr->flags & CDR_FWD_FL_ROTATE)
			k += scnprintf(b + k, s - k, " rotate");
		k += scnprintf(b + k, s - k, "\n");
		if (!(sr->flags & CDR_FWD_FL_ACTIVE))
			continue;
		if (!(sr->flags & CDR_FWD_FL_CONNECTED)) {
			k += scnprintf(b + k, s - k, "    last try : %s "
				       "try_count=%d\n",
				       _time_to_str(sr->try_last, buf, sizeof (buf)),
				       sr->try_count);
		}
		k += scnprintf(b + k, s - k, "    seq      : %u sent_in_win: %d/%d\n",
			       sr->seq, sr->cntsent, ctx->cfg.ack_window);
		k += scnprintf(b + k, s - k, "    spool pos: idx=%d "
			       "ts=%ld off=%ld fd=%d\n",
			       sr->cur_idx, sr->cur_idx == -1 ? 0 :
			       ctx->spool_f[sr->cur_idx].ts,
			       sr->cur_off, sr->cur_fd);
		k += scnprintf(b + k, s - k, "    last ack : "
			       "idx=%d ts=%ld off=%ld\n",
			       sr->win_idx, sr->win_idx == -1 ? 0 :
			       ctx->spool_f[sr->win_idx].ts, sr->win_off);
		k += scnprintf(b + k, s - k, "    stats    : ticket=%ld ",
			       sr->st_tickets_out);
		k += scnprintf(b + k, s - k, "bytes=%ld\n", sr->st_bytes_out);
	}

	return k;
}

int
cdr_fwd_ctx_dump_stats(const struct cdr_fwd_context *ctx, char *b, size_t s)
{
	struct cdr_fwd_server *sr;
	int i, k = 0;
	off_t total = 0;

	k += scnprintf(b + k, s - k, "ticket_in=%ld;bytes_in=%ld\n",
		       ctx->st_tickets_in, ctx->st_bytes_in);
	for (i = ctx->spool_f_l; i < ctx->spool_f_u; i++)
		total += ctx->spool_f[i].size;
	k += scnprintf(b + k, s - k, "spool_file_count=%d;spool_total_size=%ld\n",
		       ctx->spool_f_u - ctx->spool_f_l, total);
	list_for_each_entry(sr, &ctx->remote_list, list) {
		k += scnprintf(b + k, s - k, "addr=%s;active=%d;connected=%d;"
			       "late=%d;", sr->addr_str,
			       !!(sr->flags & CDR_FWD_FL_ACTIVE),
			       !!(sr->flags & CDR_FWD_FL_CONNECTED),
			       !!(sr->flags & CDR_FWD_FL_LATE));
		k += scnprintf(b + k, s - k, "ticket_out=%ld;bytes_out=%ld\n",
			       sr->st_tickets_out, sr->st_bytes_out);
	}

	return k;
}


void
cdr_fwd_ctx_force_spool_set(struct cdr_fwd_context *ctx, bool enable)
{
	if (enable)
		ctx->flags |= CDR_FWD_FL_CTX_SPOOL_ONLY;
	else
		ctx->flags &= ~CDR_FWD_FL_CTX_SPOOL_ONLY;
}

bool
cdr_fwd_ctx_force_spool_get(struct cdr_fwd_context *ctx)
{
	return ctx->flags & CDR_FWD_FL_CTX_SPOOL_ONLY;
}


static void
_send_ticket(struct cdr_fwd_server *sr, struct cdr_fwd_ticket_buffer *t, int r)
{
	/* update current position if not late,
	 * minus ticket just written in spool */
	if (!(sr->flags & CDR_FWD_FL_LATE)) {
		sr->cur_idx = sr->ctx->spool_wr_idx;
		sr->cur_off = sr->ctx->spool_wr_off - r;
		if (sr->win_idx == -1) {
			sr->win_idx = sr->cur_idx;
			sr->win_off = sr->cur_off;
			trace1(sr->ctx->log, "%s: init win=cur at %d:%ld",
			       sr->addr_str, sr->win_idx, sr->win_off);
		}
	}

	if (!(sr->flags & CDR_FWD_FL_READY)) {
		/* not ready + 1 live ticket => set late */
		if (!(sr->flags & CDR_FWD_FL_LATE)) {
			trace1(sr->ctx->log, "%s: is now late", sr->addr_str);
			sr->flags |= CDR_FWD_FL_LATE;
		}

	} else {
		/* connected and not late, send ticket now */
		sr->cur_off += r;
		cdr_fwd_adjacency_ticket(sr, t);
	}
}


/*
 * spool and send one ticket.
 */
void
cdr_fwd_send_ticket(struct cdr_fwd_context *ctx, const uint8_t *data, int size)
{
	struct cdr_fwd_ticket_buffer t;
	struct cdr_fwd_server *sr;
	int r;

	t.size = size;
	memcpy(t.mtext, data, size);

	/* stats */
	++ctx->st_tickets_in;
	ctx->st_bytes_in += size;

	/* first, write to spool */
	r = cdr_fwd_spool_write_ticket(ctx, &t);
	if (r == 0)
		return;

	if (ctx->flags & CDR_FWD_FL_CTX_SPOOL_ONLY) {
		/* mark active server as 'late' */
		list_for_each_entry(sr, &ctx->remote_list, list) {
			if (sr->flags & CDR_FWD_FL_ACTIVE)
				sr->flags |= CDR_FWD_FL_LATE;
		}

	} else {
		/* send to server(s) */
		if (ctx->cfg.lb_mode == CDR_FWD_MODE_ACTIVE_ACTIVE) {
			list_for_each_entry(sr, &ctx->remote_list, list) {
				_send_ticket(sr, &t, r);
			}
		} else if (ctx->active_sr != NULL) {
			_send_ticket(ctx->active_sr, &t, r);
		}
	}
}


/* add remote adjacency.
 * port is mandatory, there's no default. */
static void
cdr_fwd_ctx_add_remote(struct cdr_fwd_context *ctx, const union addr *addr)
{
	struct cdr_fwd_server *sr;
	char buf[CDR_FWD_PATH_MAX + 80];

	if (!addr_is_unicast(addr) || !addr_get_port(addr)) {
		debug(ctx->log, "cannot add remote, bad addr: %s",
		      addr_stringify(addr, buf, sizeof (buf)));
		return;
	}

	sr = calloc(1, sizeof (*sr));
	sr->ctx = ctx;
	sr->cur_fd = -1;

	addr_copy(&sr->addr, addr);
	snprintf(sr->addr_str, sizeof (sr->addr_str), "%s",
		 addr_stringify(&sr->addr, buf, sizeof (buf)));

	snprintf(buf, sizeof (buf), "%s/idx_%s",
		 ctx->cfg.spool_path, sr->addr_str);
	sr->cur_filepath = strdup(buf);

	list_add_tail(&sr->list, &ctx->remote_list);
	debug(ctx->log, "%s: peer added", sr->addr_str);
}

static void
_del_remote(struct cdr_fwd_context *ctx, struct cdr_fwd_server *sr)
{
	cdr_fwd_adjacency_release(sr);

	if (sr->flags & CDR_FWD_FL_ACTIVE)
		cdr_fwd_spool_save_wincur(sr);

	disk_close_fd(&sr->cur_fd);
	free(sr->cur_filepath);
	list_del(&sr->list);
	debug(ctx->log, "%s: peer removed", sr->addr_str);
	free(sr);
}

static struct cdr_fwd_context *
_cdr_fwd_ctx_create(const struct cdr_fwd_config *cfc)
{
	struct cdr_fwd_context *ctx;

	ctx = calloc(1, sizeof (*ctx));
	ctx->cfg = *cfc;
	ctx->log = cfc->log;
	INIT_LIST_HEAD(&ctx->remote_list);

	if (ctx->cfg.lb_mode == 0)
		ctx->cfg.lb_mode = CDR_FWD_MODE_FAIL_OVER;
	if (ctx->cfg.roll_period <= 0)
		ctx->cfg.roll_period = 600;
	if (ctx->cfg.ack_window <= 0)
		ctx->cfg.ack_window = 200;
	if (!ctx->cfg.spool_path[0])
		strcpy(ctx->cfg.spool_path, "/tmp");
	if (ctx->cfg.rr_roll_period <= 0)
		ctx->cfg.rr_roll_period = 3600;

	return ctx;
}

static void
_cdr_fwd_ctx_init(struct cdr_fwd_context *ctx)
{
	struct cdr_fwd_server *sr;

	cdr_fwd_spool_init(ctx);

	switch (ctx->cfg.lb_mode) {
	case CDR_FWD_MODE_ACTIVE_ACTIVE:
		/* set all servers active */
		list_for_each_entry(sr, &ctx->remote_list, list) {
			sr->flags |= CDR_FWD_FL_ACTIVE;
			cdr_fwd_spool_restore_wincur(sr);
			cdr_fwd_adjacency_init(sr);
		}
		break;

	case CDR_FWD_MODE_FAIL_OVER:
	case CDR_FWD_MODE_ROUND_ROBIN:
		/* select last active peer (which should have idx file) */
		cdr_fwd_spool_list_idx_files(ctx);

		/* select any peer */
		if (ctx->active_sr == NULL)
			cdr_fwd_remote_select_next(ctx);

		ctx->active_tick = thread_add_timer(ctx->cfg.loop,
						    _tick_remote_check,
						    ctx, USEC_PER_SEC);

		break;
	default:
		warn(ctx->log, "invalid lb_mode=%d", ctx->cfg.lb_mode);
	}
}



/*
 * create context
 */
struct cdr_fwd_context *
cdr_fwd_ctx_create(const struct cdr_fwd_config *cfc,
		   const union addr *remote_array)
{
	struct cdr_fwd_context *ctx;
	int i;

	if (cfc->loop == NULL)
		return NULL;

	ctx = _cdr_fwd_ctx_create(cfc);
	if (remote_array != NULL) {
		for (i = 0; addr_len(&remote_array[i]); i++)
			cdr_fwd_ctx_add_remote(ctx, &remote_array[i]);
	}
	_cdr_fwd_ctx_init(ctx);

	return ctx;
}


void
cdr_fwd_ctx_release(struct cdr_fwd_context *ctx)
{
	struct cdr_fwd_server *sr, *sr_tmp;

	list_for_each_entry_safe(sr, sr_tmp, &ctx->remote_list, list) {
		_del_remote(ctx, sr);
	}
	cdr_fwd_spool_release(ctx);
	thread_del(ctx->active_tick);
	free(ctx);
}
