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


#pragma once

#include "addr.h"
#include "list_head.h"
#include "thread.h"
#include "inet_utils.h"

#include "cdr_fwd.h"


#define	CDR_FWD_FL_CTX_SPOOL_ONLY		0x0001

#define	CDR_FWD_FL_ACTIVE			0x0001
#define	CDR_FWD_FL_CONNECTED			0x0002
#define	CDR_FWD_FL_LATE				0x0004
#define	CDR_FWD_FL_READY			0x0008
#define	CDR_FWD_FL_ROTATE			0x0010

#define	CDR_FWD_SND_WND_SIZE			0x01
#define	CDR_FWD_SND_NEWSEQ			0x02
#define	CDR_FWD_SND_ACK				0x03
#define	CDR_FWD_SND_TICKET			0x04

#define CDR_FWD_MTYPE_STOR_MAGIC		0xacf001ee


/* CDR protocol header */
struct cdr_fwd_ticket_buffer
{
	uint32_t			size;	/* strlen(mtext) */
	int32_t				mtype;
	char				mtext[CDR_FWD_TICKETS_MAX_BUFF + 1];
	/* crc is following end of text */
} __attribute__((packed));


struct cdr_fwd_spool_file
{
	time_t				ts;
	off_t				size;
};

/* Pool of servers */
struct cdr_fwd_context
{
	struct cdr_fwd_config		cfg;
	uint16_t			flags;

	uint64_t			log;

	/* not used if lb_mode is active-active */
	struct cdr_fwd_server		*active_sr;
	time_t				active_since;
	time_t				active_reco_recent;
	int				active_reco_n;
	struct _thread			*active_tick;

	/* spooled files timestamp list */
	struct cdr_fwd_spool_file	*spool_f;
	int				spool_f_m;
	int				spool_f_u;
	int				spool_f_l;

	/* spool file writing */
	int				spool_wr_fd;
	int				spool_wr_idx;
	int64_t				spool_wr_off;
	time_t				spool_wr_last_try;

	/* stats */
	uint64_t			st_tickets_in;
	uint64_t			st_bytes_in;
	double				disk_avail;
	time_t				disk_next_check;

	/* list of server */
	struct list_head		remote_list;
};


/*
 * a remote peer (remote server)
 */
struct cdr_fwd_server
{
	struct cdr_fwd_context		*ctx;
	struct list_head		list;
	uint16_t			flags;

	/* Connection related */
	union addr			addr;
	char				addr_str[64];
	time_t				try_last;
	int				try_count;

	struct _thread			*connect_ev;	/* timer */
	struct _thread			*io;		/* fd */
	int				state;
	uint8_t				recv_buf[4];
	uint32_t			recv_buf_size;
	int				cntrecv_low;

	/* sequence number, shared with cdrhubd.
	 * initialized with random value */
	uint32_t			seq;

	/* number of ticket sent on this window (ie.
	 * a particular seq) */
	int				cntsent;

	/* spool index file, filename and fd */
	char				*cur_filepath;
	int				cur_fd;

	/* position in spool file where we should
	 * fetch the next ticket. incremented each time:
	 *   - we directly forward ticket (not late)
	 *   - we read a ticket from spool
	 * initialized from current pos file, or from spool
	 * writer position */
	int				cur_idx;	/* in spool_f[] */
	off_t				cur_off;

	/* position in spool file, either:
	 *   - at init: on cur_idx, or on the first sent/spooled ticket
	 *   - after a window ack: at this position
	 * this position is saved in spool file index */
	int				win_idx;	/* in spool_f[] */
	off_t				win_off;

	/* stats */
	uint64_t			st_tickets_out;
	uint64_t			st_bytes_out;
};


/* cdr_fwd.c */
int cdr_fwd_remote_send_data(struct cdr_fwd_server *sr, int cmd,
			     struct cdr_fwd_ticket_buffer *t);
void cdr_fwd_remote_reset(struct cdr_fwd_server *sr);
void cdr_fwd_remote_connected(struct cdr_fwd_server *sr);
bool cdr_fwd_remote_select_next(struct cdr_fwd_context *ctx);


/* cdr_fwd_adj.c */
void cdr_fwd_adjacency_ticket(struct cdr_fwd_server *sr,
			      struct cdr_fwd_ticket_buffer *t);
void cdr_fwd_adjacency_reset(struct cdr_fwd_server *sr);
void cdr_fwd_adjacency_init(struct cdr_fwd_server *sr);
void cdr_fwd_adjacency_release(struct cdr_fwd_server *sr);


/* cdr_fwd_disk.c */
int cdr_fwd_disk_create(char *path, bool append);
int cdr_fwd_disk_write(int fd, const void *buffer, int size);
int cdr_fwd_disk_read(int fd, void *buffer, int size);
void cdr_fwd_disk_close_file(int *fd);
int cdr_fwd_disk_write_ticket(struct cdr_fwd_context *ctx, int fd,
			      const struct cdr_fwd_ticket_buffer *t,
			      const char *pathname);
int cdr_fwd_disk_read_ticket(struct cdr_fwd_context *ctx, int fd,
			     struct cdr_fwd_ticket_buffer *ticket,
			     const char *pathname);

/* cdr_fwd_spool.c */
void cdr_fwd_spool_list_idx_files(struct cdr_fwd_context *ctx);
void cdr_fwd_spool_save_wincur(struct cdr_fwd_server *sr);
void cdr_fwd_spool_restore_wincur(struct cdr_fwd_server *sr);
int cdr_fwd_spool_read_ticket(struct cdr_fwd_server *sr,
			      struct cdr_fwd_ticket_buffer *out_t);
int cdr_fwd_spool_write_ticket(struct cdr_fwd_context *ctx,
			       const struct cdr_fwd_ticket_buffer *t);
void cdr_fwd_spool_init(struct cdr_fwd_context *ctx);
void cdr_fwd_spool_release(struct cdr_fwd_context *ctx);

