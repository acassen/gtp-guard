/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2010, 2011, 2024 Olivier Gournet, <gournet.olivier@gmail.com>
 */


#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>

#include "tools.h"
#include "cdr_fwd-priv.h"


/*
 * scan spool directory. strategy:
 *  - scan directory once on startup (and config reload)
 *  - build array of timestamp from filenames to ctx->spool_f (with file size)
 *  - when ticket are written in spool file by current process, add
 *    new spools files to ctx->spool_f
 *  - remotes have their own spool file+offset when fetching, stored
 *    in idx_<ip> file
 *  - when all remotes are done with a specific ts, aslo unlink file.
 *  - if disk usage > 95%, remove oldest spool files.
 */

static void
cdr_fwd_spool_add_file(struct cdr_fwd_context *ctx, time_t ts)
{
	if (ctx->spool_f_u >= ctx->spool_f_m) {
		ctx->spool_f_m = max(ctx->spool_f_m, 25) * 2;
		ctx->spool_f = realloc(ctx->spool_f, ctx->spool_f_m *
				       sizeof (*ctx->spool_f));
	}
	ctx->spool_f[ctx->spool_f_u].size = 0;
	ctx->spool_f[ctx->spool_f_u].ts = ts;
	ctx->spool_wr_idx = ctx->spool_f_u++;
}


/* remove spool files that are not referenced by any remote */
static void
cdr_fwd_spool_purge(struct cdr_fwd_context *ctx)
{
	struct cdr_fwd_server *srt;
	char buf[CDR_FWD_PATH_MAX + 64];
	int i;

	/* last (most recent) spool file is _never_ deleted */
	for (i = ctx->spool_f_l; i < ctx->spool_f_u - 1; i++) {
		list_for_each_entry(srt, &ctx->remote_list, list) {
			if ((srt->flags & CDR_FWD_FL_ACTIVE) &&
			    srt->win_idx != -1 && srt->win_idx <= i)
				goto stop;
		}
		sprintf(buf, "%s/spool_%ld", ctx->cfg.spool_path,
			ctx->spool_f[i].ts);
		trace1(ctx->log, "spool: remove %s", buf);
		unlink(buf);
	}

stop:
	ctx->spool_f_l = i;

	/* move everything back to the beginning of ts array */
	if (ctx->spool_f_l > ctx->spool_f_m / 2) {
		trace1(ctx->log, "move ts idx [%d, %d] -> [0, %d] alloc_size:%d",
		       ctx->spool_f_l, ctx->spool_f_u,
		       ctx->spool_f_u - ctx->spool_f_l, ctx->spool_f_m);
		for (i = 0; i < ctx->spool_f_u - ctx->spool_f_l; i++)
			ctx->spool_f[i] = ctx->spool_f[i + ctx->spool_f_l];
		list_for_each_entry(srt, &ctx->remote_list, list) {
			if (srt->flags & CDR_FWD_FL_ACTIVE) {
				if (srt->cur_idx >= 0) {
					srt->cur_idx -= ctx->spool_f_l;
					assert(srt->cur_idx >= 0);
				}
				if (srt->win_idx >= 0) {
					srt->win_idx -= ctx->spool_f_l;
					assert(srt->win_idx >= 0);
				}
			}
		}
		ctx->spool_f_u -= ctx->spool_f_l;
		if (ctx->spool_wr_idx != -1)
			ctx->spool_wr_idx -= ctx->spool_f_l;
		ctx->spool_f_l = 0;
	}
}


static int
scandir_filter(const struct dirent *d)
{
	if (d->d_type != DT_REG)
		return 0;
	if (!strncmp(d->d_name, "spool_", 6))
		return 1;
	return 0;
}

static int
scandir_compar(const struct dirent **a, const struct dirent **b)
{
	time_t al = atoll(a[0]->d_name + 6);
	time_t bl = atoll(b[0]->d_name + 6);

	if (al < bl)
		return -1;
	if (al > bl)
		return 1;
	return 0;
}


static void
cdr_fwd_spool_list_directory(struct cdr_fwd_context *ctx)
{
	char path[CDR_FWD_PATH_MAX + 256];
	struct dirent **dent;
	struct stat st;
	time_t ts, now = time(NULL);
	int i, n, r;
	off_t total = 0;

	/* scan spool dir */
	n = scandir(ctx->cfg.spool_path, &dent,
		    scandir_filter, scandir_compar);
	if (n < 0) {
		err(ctx->log, "%s: %m", ctx->cfg.spool_path);
		return;
	}

	/* add valid spool files */
	for (i = 0; i < n; i++) {
		r = sscanf(dent[i]->d_name, "spool_%ld", &ts);
		if (r != 1) {
			info(ctx->log, "cannot parse spool filename %s",
			     dent[i]->d_name);
		} else if (ts > now) {
			warn(ctx->log, "ignore spool file %ld, is in the future",
			     ts);
		} else {
			snprintf(path, sizeof (path), "%s/%s",
				 ctx->cfg.spool_path, dent[i]->d_name);
			if (stat(path, &st) < 0) {
				err(ctx->log, "%s: stat: %m", path);
			} else if (st.st_size < 8) {
				warn(ctx->log, "%s: skip too small file (%ld bytes)",
				     path, st.st_size);
			} else {
				cdr_fwd_spool_add_file(ctx, ts);
				ctx->spool_f[ctx->spool_f_u - 1].size = st.st_size;
				total += st.st_size;
			}
		}
		free(dent[i]);
	}
	free(dent);

	debug(ctx->log, "%s: %d spool files scanned, total size: %ld bytes",
	      ctx->cfg.spool_path, ctx->spool_f_u, total);
}

static void
cdr_fwd_disk_check_usage(struct cdr_fwd_context *ctx)
{
	char path[CDR_FWD_PATH_MAX + 64];
	struct cdr_fwd_server *srt;
	struct statvfs fsst;
	off_t removed = 0, avail;
	int i, r;

	/* get file system remaining size */
	r = fstatvfs(ctx->spool_wr_fd, &fsst);
	if (r < 0) {
		err(ctx->log, "fstatvfs: %m");
		return;
	}
	if (!fsst.f_blocks) {
		err(ctx->log, "wrong fstatvfs return");
		return;
	}

	ctx->disk_avail = (double)fsst.f_bavail / fsst.f_blocks;
	debug(ctx->log, "spool: %.2f%% disk used (av. blocks: %ld/%ld, bs: %ld)",
	       (1. - ctx->disk_avail) * 100., fsst.f_bavail, fsst.f_blocks,
	       fsst.f_bsize);
	if (ctx->disk_avail > 0.05)
		return;

	info(ctx->log, "spool: disk is full, try to make some space");

	/* remove oldest spool files, until we're at 90% */
	for (i = ctx->spool_f_l; i < ctx->spool_f_u - 4 &&
		     ctx->disk_avail < 0.10; i++) {
		snprintf(path, sizeof (path), "%s/spool_%lu",
			 ctx->cfg.spool_path, ctx->spool_f[i].ts);
		trace1(ctx->log, "spool: remove %s", path);
		unlink(path);

		removed += ctx->spool_f[i].size;
		avail = fsst.f_bavail + (removed / fsst.f_bsize);
		ctx->disk_avail = (double)avail / fsst.f_blocks;
	}

	info(ctx->log, "spool: %d files were removed", i - ctx->spool_f_l);
	ctx->spool_f_l = i;

	list_for_each_entry(srt, &ctx->remote_list, list) {
		if ((srt->flags & CDR_FWD_FL_ACTIVE) &&
		    (srt->win_idx != -1 && srt->win_idx < ctx->spool_f_l)) {
			info(ctx->log, "%s: very late, set win_idx=%d, change seq",
			     srt->addr_str, ctx->spool_f_l);
			cdr_fwd_remote_reset(srt);
			unlink(srt->cur_filepath);
			srt->cur_idx = srt->win_idx = ctx->spool_f_l;
			srt->cur_off = srt->win_off = 0;
			srt->seq = random();
		}
	}
}


static int
scandir_wincur_filter(const struct dirent *d)
{
	if (d->d_type != DT_REG)
		return 0;
	if (!strncmp(d->d_name, "idx_", 4))
		return 1;
	return 0;
}


void
cdr_fwd_spool_list_idx_files(struct cdr_fwd_context *ctx)
{
	struct dirent **dent;
	char buf[64];
	union addr a;
	int n, i, r;

	trace1(ctx->log, "%s: scanning idx_* files", ctx->cfg.spool_path);

	/* scan spool dir */
	n = scandir(ctx->cfg.spool_path, &dent,
		    scandir_wincur_filter, alphasort);
	if (n < 0) {
		err(ctx->log, "%s: %m", ctx->cfg.spool_path);
		return;
	}

	if (n == 0)
		debug(ctx->log, "%s: no idx_* file", ctx->cfg.spool_path);

	for (i = 0; i < n; i++) {
		trace1(ctx->log, "%s: found %s", ctx->cfg.spool_path,
		       dent[i]->d_name);
		r = sscanf(dent[i]->d_name, "idx_%63s", buf);
		if (r != 1) {
			info(ctx->log, "cannot parse idx filename %s",
			     dent[i]->d_name);
		} else {
			if (addr_parse(buf, &a)) {
				info(ctx->log, "cannot parse ip from file %s",
				     dent[i]->d_name);
			} else {
				cdr_fwd_remote_select_addr(ctx, &a);
			}
		}
		free(dent[i]);
	}
	free(dent);
}



/*
 * read file containing last acked file/offset with its seq number.
 * if this file is missing/invalid, sync with spool writer (with random seq number).
 */
void
cdr_fwd_spool_restore_wincur(struct cdr_fwd_server *sr)
{
	struct cdr_fwd_context *ctx = sr->ctx;
	time_t ts;
	int fd, r, i, seq = 0;
	char buf[256];

	/* read checkpoint file */
	fd = open(sr->cur_filepath, O_RDONLY, 0644);
	if (fd < 0) {
		if (errno == ENOENT) {
			trace1(ctx->log, "%s: %s: %m", sr->addr_str,
			       sr->cur_filepath);
		} else {
			err(ctx->log, "%s: %s: open: %m", sr->addr_str,
			    sr->cur_filepath);
			unlink(sr->cur_filepath);
		}
		goto end;
	}
	r = read(fd, buf, sizeof (buf));
	if (r < 0) {
		err(ctx->log, "%s: %s: read: %m", sr->addr_str,
		    sr->cur_filepath);
		close(fd);
		unlink(sr->cur_filepath);
		goto end;
	}
	close(fd);

	buf[r] = 0;
	r = sscanf(buf, "spool %ld:%ld seq %u", &ts, &sr->cur_off, &seq);

	/* if we cannot parse current spool file, skip everything */
	if (r <= 0) {
		unlink(sr->cur_filepath);
		goto end;
	}

	/* offset can be skipped in file */
	if (r <= 1)
		sr->cur_off = 0;
	if (r == 3)
		sr->seq = seq;

	trace1(ctx->log, "%s: cur file scanned: ts=%ld off=%ld seq=%u",
	       sr->addr_str, ts, sr->cur_off, seq);

	/* adjust to spools on disk */
	for (i = ctx->spool_f_l; i < ctx->spool_f_u; i++) {
		if (ctx->spool_f[i].ts < ts)
			continue;

		sr->cur_idx = i;

		/* spool file is newer that what we have written in cur.
		 * trash the window and restart at off=0 */
		if (ctx->spool_f[i].ts != ts) {
			info(ctx->log, "%s: adjust spool file %ld:%ld => %ld:0",
			     sr->addr_str, ts, sr->cur_off, ctx->spool_f[i].ts);
			sr->cur_off = 0;
			sr->seq = random();
			ts = ctx->spool_f[i].ts;
		}

		if (sr->cur_off > ctx->spool_f[i].size) {
			info(ctx->log, "%s: saved offset (%ld) is behind "
			     "spool size (%ld). skip this spool file",
			     sr->addr_str, sr->cur_off, ctx->spool_f[i].size);
			continue;
		}

		sr->win_idx = sr->cur_idx;
		sr->win_off = sr->cur_off;

		if (i == ctx->spool_f_u - 1 &&
		    sr->cur_off == ctx->spool_wr_off) {
			sr->flags &= ~CDR_FWD_FL_LATE;
		} else {
			sr->flags |= CDR_FWD_FL_LATE;
			debug(ctx->log, "%s: is late, start at spool_%ld:%ld",
			      sr->addr_str, ts, sr->cur_off);
		}

		return;
	}

 end:
	/* initialize at current server spool writer */
	sr->seq = random();
	sr->cur_idx = ctx->spool_wr_idx;
	sr->cur_off = ctx->spool_wr_off;
	sr->win_idx = sr->cur_idx;
	sr->win_off = sr->cur_off;
	sr->flags &= ~CDR_FWD_FL_LATE;

	debug(ctx->log, "%s: missing or bad spool files or index, "
	      "start at current position", sr->addr_str);
	trace1(ctx->log, "%s: current pos is cur=%d:%ld win=%d:%ld",
	       sr->addr_str, sr->cur_idx, sr->cur_off, sr->win_idx, sr->win_off);
}


/*
 * overwrite current spool info (file, offset and current seq).
 * called after every successful window ack.
 */
void
cdr_fwd_spool_save_wincur(struct cdr_fwd_server *sr)
{
	struct cdr_fwd_context *ctx = sr->ctx;
	char buf[100];
	int fd, l;
	time_t ts;

	/* do not save if:
	 *  - problem with spool writer
	 *  - this peer is not selected */
	if (sr->win_idx == -1 || !(sr->flags & CDR_FWD_FL_ACTIVE)) {
		trace1(ctx->log, "%s: remove spool file index", sr->addr_str);
		unlink(sr->cur_filepath);
		return;
	}

	fd = cdr_fwd_disk_create(sr->cur_filepath, false);
	if (fd < 0) {
		err(ctx->log, "%s: create: %m", sr->cur_filepath);
		return;
	}

	ts = ctx->spool_f[sr->win_idx].ts;
	l = scnprintf(buf, sizeof (buf), "spool %ld:%ld seq %u\n",
		      ts, sr->win_off, sr->seq);
	if (cdr_fwd_disk_write(fd, buf, l) < 0) {
		err(ctx->log, "%s: %m", sr->cur_filepath);
		close(fd);
		unlink(sr->cur_filepath);
		return;
	}
	close(fd);

	debug(ctx->log, "%s: wrote spool file index: %ld:%ld, seq %u",
	      sr->addr_str, ts, sr->win_off, sr->seq);
}



/*
 * fetch a ticket from spool files.
 *
 * return:
 *    0: no ticket
 *    1: got a ticket
 */
int
cdr_fwd_spool_read_ticket(struct cdr_fwd_server *sr,
			       struct cdr_fwd_ticket_buffer *out_t)
{
	struct cdr_fwd_context *ctx = sr->ctx;
	char path[CDR_FWD_PATH_MAX + 64];
	int ret, fd, l;
	off_t off;
	time_t ts;

 next:
	assert(sr->cur_idx != -1);
	ts = ctx->spool_f[sr->cur_idx].ts;
	l = scnprintf(path, sizeof (path), "%s/spool_%ld", ctx->cfg.spool_path, ts);

	/* open spool file */
	if (sr->cur_fd < 0) {
		fd = open(path, O_RDONLY, 0644);
		if (fd < 0) {
			err(ctx->log, "%s: open: %m", path);
			goto skip_file;
		}

		if (sr->cur_off > 0) {
			off = lseek(fd, sr->cur_off, SEEK_SET);
			if (off != sr->cur_off) {
				err(ctx->log, "%s: lseek(%ld) %" PRId64 ": %m",
				    path, off, sr->cur_off);
				close(fd);
				goto skip_file;
			}
		}

		sr->cur_fd = fd;

		trace2(ctx->log, "%s: get ticket from %s:%" PRId64,
		       sr->addr_str, path, sr->cur_off);
	}

	/* fetch a ticket */
	snprintf(path + l, sizeof (path) - l, ":%ld", sr->cur_off);
	ret = cdr_fwd_disk_read_ticket(ctx, sr->cur_fd, out_t, path);
	if (ret > 0) {
		/* got it ! */
		sr->cur_off += ret;
		return 1;
	}
	cdr_fwd_disk_close_file(&sr->cur_fd);

 skip_file:
	/* go to next spool file */
	if (sr->cur_idx + 1 < ctx->spool_f_u) {
		++sr->cur_idx;
		sr->cur_off = 0;
		goto next;
	}

	return 0;
}


/*
 * write ticket 't' in spool file.
 * return written ticket size, or 0.
 */
int
cdr_fwd_spool_write_ticket(struct cdr_fwd_context *ctx,
				const struct cdr_fwd_ticket_buffer *t)
{
	char path[CDR_FWD_PATH_MAX + 64];
	time_t ts, now = time(NULL);
	bool append = false;
	int r;

	if (ctx->spool_wr_last_try && ctx->spool_wr_last_try == now) {
		trace2(ctx->log, "fast fail");
		return 0;
	}

	/* time to roll the file ? create a new file if none exists */
	if (ctx->spool_wr_idx != -1) {
		ts = ctx->spool_f[ctx->spool_wr_idx].ts;
		if (now - ts >= ctx->cfg.roll_period) {
			cdr_fwd_disk_close_file(&ctx->spool_wr_fd);
			ts = now;
			info(ctx->log, "spool: time to roll, to %ld", ts);
		} else {
			append = true;
		}
	} else {
		ts = now;
		info(ctx->log, "spool: create a new spool file, at %ld", ts);
	}
	snprintf(path, sizeof (path), "%s/spool_%lu", ctx->cfg.spool_path, ts);

	/* create file if none opened */
	if (ctx->spool_wr_fd < 0) {
		ctx->spool_wr_off =
			append ? ctx->spool_f[ctx->spool_wr_idx].size : 0;

		/* open file */
		ctx->spool_wr_fd = cdr_fwd_disk_create(path, append);
		if (ctx->spool_wr_fd < 0) {
			err(ctx->log, "%s: create: %m", path);
			goto err;
		}

		/* remove spool file(s) not referenced by any peer */
		cdr_fwd_spool_purge(ctx);

		/* add to our list of available file */
		if (!append)
			cdr_fwd_spool_add_file(ctx, ts);
	}

	/* check if filesystem is not full (every 10s) */
	if (ctx->disk_next_check < now) {
		cdr_fwd_disk_check_usage(ctx);
		ctx->disk_next_check = now + 10;
	}

	/* write ticket to file */
	r = cdr_fwd_disk_write_ticket(ctx, ctx->spool_wr_fd, t, path);
	if (r < 0)
		goto err;

	ctx->spool_f[ctx->spool_wr_idx].size += r;
	ctx->spool_wr_off += r;
	ctx->spool_wr_last_try = 0;

	trace2(ctx->log, "spool: write ticket of %d bytes, now at "
	       "%ld:%ld", r, ts, ctx->spool_wr_off);

	return r;

 err:
	/* check if filesystem have space (error may be a full disk) */
	if (ctx->spool_wr_fd >= 0 && ctx->disk_next_check < now) {
		cdr_fwd_disk_check_usage(ctx);
		ctx->disk_next_check = now + 10;
	}

	/* cannot write to disk */
	ctx->spool_wr_idx = -1;
	ctx->spool_wr_off = 0;
	cdr_fwd_disk_close_file(&ctx->spool_wr_fd);
	ctx->spool_wr_last_try = now;

	return 0;
}


void
cdr_fwd_spool_init(struct cdr_fwd_context *ctx)
{
	/* reset spool data */
	ctx->spool_f_l = 0;
	ctx->spool_f_u = 0;
	ctx->spool_wr_fd = -1;
	ctx->spool_wr_idx = -1;
	ctx->spool_wr_off = 0;
	ctx->spool_wr_last_try = 0;

	/* build list of already present file */
	cdr_fwd_spool_list_directory(ctx);

	ctx->spool_wr_idx = ctx->spool_f_u - 1;
	if (ctx->spool_wr_idx != -1)
		ctx->spool_wr_off = ctx->spool_f[ctx->spool_wr_idx].size;
}


void
cdr_fwd_spool_release(struct cdr_fwd_context *ctx)
{
	cdr_fwd_disk_close_file(&ctx->spool_wr_fd);
	free(ctx->spool_f);
	ctx->spool_f = NULL;
	ctx->spool_f_m = 0;
}
