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
 * Copyright (C) 2025, 2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <pthread.h>
#include <libbpf.h>
#include <xdp/xsk.h>

#include "thread.h"
#include "list_head.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "vty.h"
#include "gtp_netlink.h"
#include "gtp_interface.h"
#include "gtp_bpf_prog.h"
#include "gtp_bpf_ifrules.h"
#include "gtp_bpf_xsk.h"
#include "bpf/lib/if_rule-def.h"


/*
 * userland packet handling using AF_XDP.
 *
 * packets data/metadata are read from xsk, stay on umem,
 * and are freed on timeout or when user TX them on xsk.
 *
 * packets can be RX/TX on the same iface, or RX from one iface (nic) and
 * TX to another (veth). the latter allows triggering xdp program on TX
 * (RX on the other veth side).
 *    RX: one xsk socket will be created for each rx queue.
 *    TX: one xsk socket will be created for each tx queue.
 *
 * caution: pthreads ahead !
 */


/* notification system between pthread worker and main context */
typedef void (*gtp_xsk_notif_t)(void *, void *, size_t);

struct gtp_xsk_notif
{
	struct list_head	list;
	gtp_xsk_notif_t		cb;
	void			*cb_ud;
	uint32_t		size;
	uint8_t			data[];
};


/* wrap xsk_socket with data we need */
struct gtp_xsk_socket
{
	int			queue_id;
	struct gtp_xsk_iface	*xi;
	struct gtp_xsk_ctx	*xc;
	struct xsk_socket	*xsk;

	/* rx */
	bool			has_rx;
	uint32_t		xsk_map_idx;
	struct xsk_ring_cons	rx;
	struct xsk_ring_prod	fq;
	struct thread		*read_th;
	uint64_t		st_rx;

	/* tx */
	bool			has_tx;
	struct xsk_ring_prod	tx;
	struct xsk_ring_cons	cq;
	uint32_t		outstanding_tx;
	uint64_t		st_tx;
	uint64_t		st_tx_drop;
};

struct gtp_xsk_iface
{
	struct gtp_xsk_ctx	*xc;
	struct gtp_interface	*iface;
	struct gtp_xsk_socket	**rx_sock;
	struct gtp_xsk_socket	**tx_sock;
	uint32_t		rx_sock_n;
	uint32_t		tx_sock_n;
	uint32_t		bpf_base_index;
	struct list_head	list;
};

/* context for xsk user */
struct gtp_xsk_ctx
{
	struct gtp_xsk_cfg	c;
	struct gtp_bpf_xsk	*x;
	int			instance_id;

	pthread_t		task;	/* XXX: may allow more threads */
	bool			task_running;
	struct thread_master	*master;

	/* main -> thead notification channel */
	int			th_r_fd;
	int			m_w_fd;
	struct thread		*notif_th_th;
	struct list_head	notif_th_list;
	pthread_mutex_t		notif_th_lock;

	/* thread -> main notification channel */
	int			th_w_fd;
	int			m_r_fd;
	struct thread		*notif_m_th;
	struct list_head	notif_m_list;
	pthread_mutex_t		notif_m_lock;

	/* bound interfaces */
	struct list_head	iface_list;

	/* egress xdp hook */
	struct gtp_interface	*veth_iface_rx;
	struct gtp_xsk_socket	*veth_xs;
};


/* bpf data, one per bpf program */
struct gtp_bpf_xsk
{
	struct gtp_bpf_prog	*p;
	struct bpf_map		*xsks_map;
	struct bpf_map		*xsks_base_map;

	/* attached contexts */
	struct gtp_xsk_ctx	*xc[6];
	int			xc_n;
	uint32_t		bpf_next_base_index;

	/* umem */
	struct xsk_umem		*umem;
	struct xsk_ring_prod	unused_fq;
	struct xsk_ring_cons	unused_cq;
	void			*buffer;
	uint32_t		desc_n;		/* # descriptors */
	uint64_t		*desc_free;	/* addresses of free desc */
	uint32_t		desc_free_n;	/* # free descriptors */
#if 0
	/* pkt buffering */
	struct pq_desc		*desc_pending;
	uint32_t		desc_pending_b;
	uint32_t		desc_pending_e;
#endif
};

/* locals */
static int next_instance_id;

/* Extern data */
extern struct thread_master *master;



/*************************************************************************/
/*
 *	ethtool helpers
 */


#define MAX_DEV_QUEUE_PATH_LEN 64

static void
xsk_get_queues_from_sysfs(const char* ifname, uint32_t *rx, uint32_t *tx)
{
	char buf[MAX_DEV_QUEUE_PATH_LEN];
	struct dirent *entry;
	DIR *dir;

	snprintf(buf, MAX_DEV_QUEUE_PATH_LEN,
		 "/sys/class/net/%s/queues/", ifname);

	dir = opendir(buf);
	if (dir == NULL)
		return;

	while ((entry = readdir(dir))) {
		if (!strncmp(entry->d_name, "rx", 2))
			++*rx;

		if (!strncmp(entry->d_name, "tx", 2))
			++*tx;
	}

	closedir(dir);
}

/*
 * get configured number of rx/tx queues for requested iface,
 * from kernel ethtool
 */
static int
xsk_get_cur_queues(const char *ifname, uint32_t *rx, uint32_t *tx)
{
	struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct ifreq ifr = {};
	int fd, err;

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	*rx = 0;
	*tx = 0;

	ifr.ifr_data = (void *)&channels;
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		close(fd);
		return -errno;
	}

	if (err) {
		/* If the device says it has no channels, try to get rx tx
		 * from sysfs */
		xsk_get_queues_from_sysfs(ifr.ifr_name, rx, tx);
	} else {
		/* Take the max of rx, tx, combined. Drivers return
		 * the number of channels in different ways.
		 */
		*rx = channels.rx_count;
		if (!*rx)
			*rx = channels.combined_count;
		*tx = channels.tx_count;
		if (!*tx)
			*tx = channels.combined_count;
	}

	close(fd);

	return *rx > 0 && *tx > 0 ? 0 : -1;
}

static int
xsk_set_iface_forwarding(const char *ifname, bool ipv4, bool ipv6)
{
	char path[256];
	const char on[3] = "1\n";
	int fd;

	if (ipv4) {
		snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/forwarding",
			 ifname);
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			log_message(LOG_ERR, "%s: %m", path);
			return -1;
		}
		write(fd, on, sizeof (on));
		close(fd);
	}

	if (ipv6) {
		snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/forwarding",
			 ifname);
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			log_message(LOG_ERR, "%s: %m", path);
			return -1;
		}
		write(fd, on, sizeof (on));
		close(fd);
	}

	return 0;
}


/*************************************************************************/
/*
 *	sockets read/write (run in thread)
 */


#if 0
static void
timeout_cb(struct ev_loop * /* loop */, struct ev_timer *t, int /* revents */)
{
	struct gg_ctx *ctx = container_of(t, struct gg_ctx, timer);
	struct gg_xsk_umem *u = ctx->umem;
	struct gg_desc *pkt;
	uint32_t i;

	for (i = u->desc_pending_b; i < u->desc_pending_e; i++) {
		pkt = _get_pending_desc(ctx, i);
		if (pkt->alloc_time + ctx->c.timeout_ms / 1000 > time(NULL))
			break;
		printf("free pkt %p pending: [%d-%d]\n", pkt->data,
		       u->desc_pending_b, u->desc_pending_e);
		if (ctx->c.timeout_pkt_cb != NULL)
			ctx->c.timeout_pkt_cb(ctx, ctx->c.uctx, pkt);
	}
	u->desc_pending_b = i;

	if (u->desc_pending_b > u->desc_n) {
		memmove(u->desc_pending, _get_pending_desc(ctx, u->desc_pending_b),
			(u->desc_pending_e - u->desc_pending_b) *
			(sizeof (struct gg_desc) + ctx->c.pkt_cb_user_size));
		u->desc_pending_e -= u->desc_pending_b;
		u->desc_pending_b = 0;
	}
}

static inline struct gg_desc *
_get_pending_desc(struct gtp_bpf_xsk *ctx, uint32_t idx)
{
	return (struct gtp_xsk_desc *)((uint8_t *)ctx->umem->desc_pending +
				       idx * (sizeof (struct gtp_xsk_desc) +
					      ctx->c.pkt_cb_user_size));
}
#endif


static inline void
_tx_complete(struct gtp_xsk_socket *xs)
{
	struct gtp_bpf_xsk *x = xs->xc->x;
	uint32_t i, n, idx_cq = 0;
 	int ret;

	if (!xs->outstanding_tx)
		return;

	/* if (xs->outstanding_tx < 32) */
	/* 	return; */

	/* kick tx */
	if (xsk_ring_prod__needs_wakeup(&xs->tx)) {
		ret = sendto(xsk_socket__fd(xs->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (ret < 0 && (errno != EAGAIN && errno != EBUSY && errno != ENETDOWN))
			printf("kick_tx sento: %m\n");
	} else {
		printf("tx no need wakeup\n");
	}

	/* reclaim descriptors for finished TX operations, add them to our
	 * free list */
	n = min(64, xs->outstanding_tx);
	n = xsk_ring_cons__peek(&xs->cq, n, &idx_cq);
	if (n > 0) {
		for (i = 0; i < n; i++)
			x->desc_free[x->desc_free_n++] =
				*xsk_ring_cons__comp_addr(&xs->cq, idx_cq + i);
		xsk_ring_cons__release(&xs->cq, n);
		xs->outstanding_tx -= n;
	}
}

static void
_sock_tx(struct gtp_xsk_socket *xs, struct gtp_xsk_desc *pkt)
{
	uint32_t idx;

	if (!xsk_ring_prod__reserve(&xs->tx, 1, &idx)) {
		_tx_complete(xs);
		if (!xsk_ring_prod__reserve(&xs->tx, 1, &idx)) {
			++xs->st_tx_drop;
			return;
		}
	}

	++xs->st_tx;

	struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xs->tx, idx);
	tx_desc->addr = pkt->data - xs->xc->x->buffer;
	tx_desc->len = pkt->len;
	tx_desc->options = 0;

	xsk_ring_prod__submit(&xs->tx, 1);
	++xs->outstanding_tx;

	_tx_complete(xs);
}

static void
_sock_tx_select(struct gtp_xsk_socket *xs, struct gtp_xsk_desc *pkt)
{
	if (xs->has_tx) {
		_sock_tx(xs, pkt);
		return;
	}

	if (xs->queue_id < xs->xi->tx_sock_n) {
		xs = xs->xi->tx_sock[xs->queue_id];
		_sock_tx(xs, pkt);
		return;
	}

	if (xs->xi->tx_sock_n) {
		xs = xs->xi->tx_sock[xs->queue_id % xs->xi->tx_sock_n];
		_sock_tx(xs, pkt);
		return;
	}

	gtp_xsk_tx(xs->xi->xc, xs->queue_id, pkt);
}

void
gtp_xsk_tx(struct gtp_xsk_ctx *xc, int queue_id, struct gtp_xsk_desc *pkt)
{
	struct gtp_xsk_iface *xi;

	list_for_each_entry(xi, &xc->iface_list, list) {
		if (queue_id < xi->tx_sock_n) {
			_sock_tx(xi->tx_sock[queue_id], pkt);
			return;
		}
		if (xi->tx_sock_n) {
			_sock_tx(xi->tx_sock[queue_id % xi->tx_sock_n], pkt);
			return;
		}
	}
}


/*
 * read callback
 */
static void
_socket_cb(struct thread *t)
{
	const uint32_t read_pkt_max = 64;
	struct gtp_xsk_socket *xs = THREAD_ARG(t);
	struct gtp_xsk_ctx *xc = xs->xc;
	struct gtp_bpf_xsk *x = xs->xc->x;
	struct gtp_xsk_desc pkt;
	uint32_t rcvd, i;
	uint32_t idx_rx, idx_fq = 0, cum_read = 0;
	int ret;

 do_it_again:
	/* how many descriptors to read ? */
	rcvd = xsk_ring_cons__peek(&xs->rx, read_pkt_max, &idx_rx);
	if (!rcvd)
		goto end;

	/* printf("socket_cb: %d from %s\n", rcvd, xs->xi->iface->ifname); */

	cum_read += rcvd;
	xs->st_rx += rcvd;

	/* read packets */
	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xs->rx, idx_rx++);
		if (desc->options & XDP_PKT_CONTD) {
			printf("I AM fragmented :/\n");
		}

		pkt.data = xsk_umem__get_data(x->buffer, desc->addr);
		pkt.len = desc->len;
		ret = xc->c.pkt_read(xc->c.priv, &pkt);
		switch (ret) {
		case GTP_XSK_DROP:
			x->desc_free[x->desc_free_n++] = desc->addr;
			break;

		case GTP_XSK_TX:
			/* printf("%s tx\n", __func__); */
			if (xc->veth_xs != NULL)
				_sock_tx(xc->veth_xs, &pkt);
			else
				_sock_tx_select(xs, &pkt);
			break;

		case GTP_XSK_QUEUE:
#if 0
			// add this packet to pending list
			pkt = _get_pending_desc(x, x->desc_pending_e);
			pkt->data = xsk_umem__get_data(x->buffer, desc->addr);
			pkt->len = desc->len;
			pkt->alloc_time = time(NULL);
			++x->desc_pending_e;
#endif
			break;

		default:
			abort();
		}
	}

	// acke'd, we read them
	xsk_ring_cons__release(&xs->rx, rcvd);

	/* now we give back to kernel the same number of descriptors, */
	/* so it won't run out. */
	if (x->desc_free_n < rcvd) {
		printf("ooops, running out of RX descriptors :/\n");
		goto end;
	}
	if (xsk_ring_prod__reserve(&xs->fq, rcvd, &idx_fq) == 0) {
		printf("cannot write into fill queue\n");
		goto end;
	}
	for (i = 0; i < rcvd; i++)
		*xsk_ring_prod__fill_addr(&xs->fq, idx_fq++) =
			x->desc_free[--x->desc_free_n];
	xsk_ring_prod__submit(&xs->fq, rcvd);

	if (rcvd == read_pkt_max)
		goto do_it_again;

 end:
	/* if (cum_read) */
	/* 	printf("read %d frames\n", cum_read); */
	xs->read_th = thread_add_read(xc->master, _socket_cb, xs,
				      xsk_socket__fd(xs->xsk), TIMER_NEVER, 0);
	/* xs->read_th = thread_add_event(xc->master, _socket_cb, xs, 0); */
}



static void
_notif_th_shutdown(void *ctx, void *ud, size_t size)
{
	struct gtp_xsk_ctx *xc = ctx;

	thread_add_terminate_event(xc->master);
}

static void
_notif_th_add_xs(void *ctx, void *ud, size_t size)
{
	struct gtp_xsk_ctx *xc = ctx;
	struct gtp_xsk_socket *xs = *(struct gtp_xsk_socket **)ud;
	int fd;

	fd = xsk_socket__fd(xs->xsk);
	xs->read_th = thread_add_read(xc->master, _socket_cb,
				      xs, fd, TIMER_NEVER, 0);
	/* xs->read_th = thread_add_event(xc->master, _socket_cb, xs, 0); */
}

static void
_notif_th_del_xs(void *ctx, void *ud, size_t size)
{
	struct gtp_xsk_socket *xs = *(struct gtp_xsk_socket **)ud;

	thread_del(xs->read_th);
	xsk_socket__delete(xs->xsk);
	free(xs);
}

/* process all notifs from main context, in thread */
static void
_notif_th_read_cb(struct thread *t)
{
	struct gtp_xsk_ctx *xc = THREAD_ARG(t);
	struct gtp_xsk_notif *n, *n_tmp;
	struct list_head tmp_list = LIST_HEAD_INIT(tmp_list);
	int fd = THREAD_FD(t);
	char buf[PIPE_BUF];
	int ret;

	ret = read(fd, buf, sizeof (buf));
	if (ret < 0) {
		log_message(LOG_ERR, "notif_th_read pipe: %m");
		return;
	}

	pthread_mutex_lock(&xc->notif_th_lock);
	list_splice_init(&xc->notif_th_list, &tmp_list);
	pthread_mutex_unlock(&xc->notif_th_lock);

	list_for_each_entry_safe(n, n_tmp, &tmp_list, list) {
		n->cb(n->cb_ud, n->data, n->size);
		free(n);
	}

	xc->notif_th_th = thread_add_read(xc->master, _notif_th_read_cb, xc,
					  xc->th_r_fd, TIMER_NEVER, 0);
}


/* should be called from main context.
 * it will call 'cb' in thread context. */
static void
gtp_xsk_send_thread_notif(struct gtp_xsk_ctx *xc, gtp_xsk_notif_t cb, void *cb_ud,
			  const void *data, size_t size)
{
	struct gtp_xsk_notif *n;
	bool wake_up;

	n = malloc(sizeof(*n) + size);
	if (n == NULL)
		return;
	n->cb = cb;
	n->cb_ud = cb_ud;
	n->size = size;
	if (size && data)
		memcpy(n->data, data, size);

	pthread_mutex_lock(&xc->notif_th_lock);
	wake_up = list_empty(&xc->notif_th_list);
	list_add_tail(&n->list, &xc->notif_th_list);
	pthread_mutex_unlock(&xc->notif_th_lock);

	if (wake_up) {
		uint8_t c = 77;
		int ret = write(xc->m_w_fd, &c, 1);
		if (ret < 0)
			log_message(LOG_ERR, "notif_th_write pipe: %m");
	}
}


static void *
gtp_xsk_main_loop(void *arg)
{
	struct gtp_xsk_ctx *xc = arg;
	char identity[64];

	/* Our identity */
	snprintf(identity, sizeof (identity), "xsk_%s-%d",
		 xc->c.name, xc->instance_id);
	prctl(PR_SET_NAME, identity, 0, 0, 0, 0);

	xc->master = thread_make_master(true);
	if (xc->master == NULL)
		return NULL;

	xc->notif_th_th = thread_add_read(xc->master, _notif_th_read_cb, xc,
					  xc->th_r_fd, TIMER_NEVER, 0);

	if (xc->c.thread_init != NULL)
		xc->c.thread_init(xc->c.priv);

	launch_thread_scheduler(xc->master);

	if (xc->c.thread_release != NULL)
		xc->c.thread_release(xc->c.priv);

	thread_destroy_master(xc->master);

	return NULL;
}




/*************************************************************************/
/*
 *	context / sockets management (run in main context)
 */


static int
_xsk_sock_dump(struct gtp_xsk_socket *xs, char *buf, int size, bool rx)
{
	struct xdp_statistics stats = {};
	socklen_t optlen;
	int k = 0;

	k += scnprintf(buf + k, size - k, "   - [%d] ",
		       xs->queue_id);

	optlen = sizeof (stats);
	if (getsockopt(xsk_socket__fd(xs->xsk), SOL_XDP, XDP_STATISTICS, &stats, &optlen)) {
		k += scnprintf(buf + k, size - k, "{err getsockopt: %m}\n");
		return k;
	}

	if (rx) {
		k += scnprintf(buf + k, size - k, "xsk_idx: %-7d rx:%ld drop:%lld "
			       "rx_full:%lld no_desc:%lld",
			       xs->xsk_map_idx, xs->st_rx,
			       stats.rx_dropped + stats.rx_invalid_descs,
			       stats.rx_ring_full, stats.rx_fill_ring_empty_descs);
	} else {
		k += scnprintf(buf + k, size - k, "pending_tx: %-4d tx:%ld drop:%lld "
			       "no_desc:%lld",
			       xs->outstanding_tx, xs->st_tx,
			       xs->st_tx_drop + stats.tx_invalid_descs,
			       stats.tx_ring_empty_descs);
	}
	k += scnprintf(buf + k, size - k, "\n");

	return k;
}

static int
_xsk_ctx_dump(struct gtp_xsk_ctx *xc, char *buf, int size)
{
	struct gtp_xsk_iface *xi;
	struct list_head *lh;
	int cm = 0, cth = 0;
	int k = 0;
	int i;

	k += scnprintf(buf + k, size - k,
		       " name                 : %s\n"
		       " instance_id          : %d\n"
		       " running pthread      : %d\n",
		       xc->c.name, xc->instance_id, xc->task_running);

	/* get number of pending notifications */
	pthread_mutex_lock(&xc->notif_m_lock);
	list_for_each(lh, &xc->notif_m_list)
		cm++;
	pthread_mutex_unlock(&xc->notif_m_lock);
	pthread_mutex_lock(&xc->notif_th_lock);
	list_for_each(lh, &xc->notif_th_list)
		cth++;
	pthread_mutex_unlock(&xc->notif_th_lock);
	k += scnprintf(buf + k, size - k,
		       " pending notification\n"
		       "   - main -> thread   : %d\n"
		       "   - thread -> main   : %d\n",
		       cth, cm);

	list_for_each_entry(xi, &xc->iface_list, list) {
		k += scnprintf(buf + k, size - k, " interface '%s'\n",
			       xi->iface->ifname);
		if (xi->rx_sock_n)
			k += scnprintf(buf + k, size - k, "  rx sockets (%d)\n",
				       xi->rx_sock_n);
		for (i = 0; i < xi->rx_sock_n; i++)
			k += _xsk_sock_dump(xi->rx_sock[i], buf + k, size - k, true);
		if (xi->tx_sock_n > 0)
			k += scnprintf(buf + k, size - k, "  tx sockets (%d)\n",
				       xi->tx_sock_n);
		for (i = 0; i < xi->tx_sock_n; i++)
			k += _xsk_sock_dump(xi->tx_sock[i], buf + k, size - k, false);
	}

	return k;
}

static int
_xsk_sock_set_busypoll(int xsk_fd, int opt_batch_size)
{
	int sock_opt;

	sock_opt = 1;
	if (setsockopt(xsk_fd, SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		return -1;

	sock_opt = 20;
	if (setsockopt(xsk_fd, SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		return -1;

	sock_opt = opt_batch_size;
	if (setsockopt(xsk_fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		return -1;

	return 0;
}


/*
 * setup AF_XDP sockets (xsk), one per rx queue.
 * socket is bind() on a specific queue_id and will only receive from it,
 * so there has to be one socket per rx queue.
 *
 * it will use polling (with lib/thread). no busy poll.
 * if real performance is needed, we may start one thread per socket.
 *
 * it also configure 4 rings:
 *   - tx ring
 *   - rx ring
 *   - fill ring: gives back buffers to kernel, so it can use them for RX
 *   - completion ring: kernel gives buffers to us, so we can use them again for TX.
 * these 4 rings will be mmap'ed by libxdp
 *
 * we WILL create a set of sockets for one netdev/queue_id (like SO_REUSEPORT),
 * in this case fill/completion ring WILL be shared.
 */
static struct gtp_xsk_socket *
_socket_setup(struct gtp_xsk_iface *xi, const char *ifname, int queue_id,
	      bool w_rx, bool w_tx)
{
	struct gtp_xsk_ctx *xc = xi->xc;
	struct gtp_bpf_xsk *x = xc->x;
	struct gtp_xsk_socket *xs;
	uint32_t idx, i;
	int ret, fd;

	printf(" initialize xsk on iface:%s/%d, mode:%s%s\n",
	       ifname, queue_id, w_rx ? " RX" : "", w_tx ? " TX" : "");

	xs = calloc(1, sizeof (*xs));
	if (xs == NULL)
		return NULL;
	xs->queue_id = queue_id;
	xs->xsk_map_idx = xi->bpf_base_index + queue_id;
	xs->has_rx = w_rx;
	xs->has_tx = w_tx;
	xs->xi = xi;
	xs->xc = xc;
	LIBBPF_OPTS(xsk_socket_opts, xsd_cfg,
		    .fill = &xs->fq,
		    .comp = &xs->cq,
		    .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		    .xdp_flags = XDP_FLAGS_DRV_MODE,
		    .bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY,
	);
	if (w_rx) {
		xsd_cfg.rx = &xs->rx;
		xsd_cfg.rx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	}
	if (w_tx) {
		xsd_cfg.tx = &xs->tx;
		xsd_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	}

	/* wait for 1ms max. may happen if delete then setup is too fast */
	for (i = 0; i < 100; i++) {
		xs->xsk = xsk_socket__create_opts(ifname, queue_id, x->umem, &xsd_cfg);
		if (xs->xsk != NULL || errno != EBUSY)
			break;
		usleep(10);
	}
	if (xs->xsk == NULL) {
		printf("cannot create xsk socket: %m\n");
		return NULL;
	}

	if (!w_rx)
		return xs;

	/* insert this fd into bpf's map BPF_MAP_TYPE_XSKMAP */
	fd = xsk_socket__fd(xs->xsk);
	bpf_map__update_elem(x->xsks_map, &xs->xsk_map_idx, sizeof (uint32_t),
			     &fd, sizeof (fd), 0);

	if (_xsk_sock_set_busypoll(fd, 64))
		log_message(LOG_ERR, "xsk: %s: setbusypoll: %m", ifname);

	/* add socket into thread's iomux */
	gtp_xsk_send_thread_notif(xc, _notif_th_add_xs, xc, &xs, sizeof (xs));

	/* give kernel some descriptors for RX, by writting into fill ring */
	ret = xsk_ring_prod__reserve(&xs->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
	assert(ret == XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
		*xsk_ring_prod__fill_addr(&xs->fq, idx++) = x->desc_free[--x->desc_free_n];
	xsk_ring_prod__submit(&xs->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);

	return xs;
}

static void
_socket_cleanup(struct gtp_xsk_socket *xs, bool rx)
{
	struct gtp_xsk_ctx *xc = xs->xc;

	/* TX only socket, destroy now */
	if (!xs->has_rx) {
		assert(!rx);
		xsk_socket__delete(xs->xsk);
		free(xs);
		return;
	}

	/* socket has RX: will destroy in thread */
	if (rx && xs->has_rx) {
		bpf_map__delete_elem(xc->x->xsks_map, &xs->xsk_map_idx,
				     sizeof (uint32_t), 0);
		gtp_xsk_send_thread_notif(xc, _notif_th_del_xs, xc, &xs, sizeof (xs));
	}
}


static int
_xsk_iface_add(struct gtp_xsk_ctx *xc, struct gtp_interface *iface, bool is_veth)
{
	struct gtp_bpf_xsk *x = xc->x;
	struct gtp_xsk_iface *xi;
	struct gtp_xsk_socket *xs;
	int i, ret, sock_n = 0;

	xi = calloc(1, sizeof (*xi));
	if (xi == NULL)
		return -1;
	xi->xc = xc;
	xi->iface = iface;
	xi->bpf_base_index = x->bpf_next_base_index;

	ret = xsk_get_cur_queues(iface->ifname, &xi->rx_sock_n, &xi->tx_sock_n);
	if (ret < 0) {
		log_message(LOG_ERR, "xsk: %s: cannot get queues count",
			    iface->ifname);
		goto err;
	}

	if (is_veth) {
		xi->rx_sock_n = 0;
	} else {
		xi->rx_sock = calloc(xi->rx_sock_n, sizeof (*xi->rx_sock));
		if (xi->rx_sock == NULL)
			goto err;
	}

	if (xc->c.egress_xdp_hook && !is_veth) {
		xi->tx_sock_n = 0;
	} else {
		xi->tx_sock = calloc(xi->tx_sock_n, sizeof (*xi->tx_sock));
		if (xi->tx_sock == NULL)
			goto err;
	}
	printf("iface %s rx_queue: %d tx_queue: %d is_veth:%d\n", iface->ifname,
	       xi->rx_sock_n, xi->tx_sock_n, is_veth);

	/* initialize sockets */
	sock_n = max(xi->rx_sock_n, xi->tx_sock_n);
	for (i = 0; i < sock_n; i++) {
		xs = _socket_setup(xi, iface->ifname, i,
				   i < xi->rx_sock_n, i < xi->tx_sock_n);
		if (xs == NULL)
			goto err;
		if (i < xi->rx_sock_n)
			xi->rx_sock[i] = xs;
		if (i < xi->tx_sock_n)
			xi->tx_sock[i] = xs;
	}

	/* shortcut when using egress xdp hook */
	if (is_veth)
		xc->veth_xs = xi->tx_sock[0];

	if (xi->rx_sock_n) {
		ret = bpf_map__update_elem(x->xsks_base_map,
					   &iface->ifindex, sizeof (uint32_t),
					   &xi->bpf_base_index, sizeof (uint32_t),
					   0);
		if (ret < 0) {
			log_message(LOG_ERR, "xsk: map_insert{xsks_base} failed: %m");
			goto err;
		}
	}

	x->bpf_next_base_index += xi->rx_sock_n;
	if (is_veth)
		list_add(&xi->list, &xc->iface_list);
	else
		list_add_tail(&xi->list, &xc->iface_list);

	return 0;

 err:
	for (i = 0; i < sock_n; i++) {
		if ((xi->rx_sock && (xs = xi->rx_sock[i]) != NULL) ||
		    (xi->tx_sock && (xs = xi->tx_sock[i]) != NULL)) {
			if (xs->has_rx)
				bpf_map__delete_elem(xc->x->xsks_map, &xs->xsk_map_idx,
						     sizeof (uint32_t), 0);
			xsk_socket__delete(xs->xsk);
			free(xs);
		}
	}
	free(xi->rx_sock);
	free(xi->tx_sock);
	free(xi);
	return -1;
}

static int
_xsk_iface_del(struct gtp_xsk_ctx *xc, struct gtp_interface *iface)
{
	struct gtp_xsk_iface *xi;
	int i, ret;

	list_for_each_entry(xi, &xc->iface_list, list) {
		if (iface == NULL || xi->iface == iface)
			goto found;
	}
	return -1;

 found:
	printf("iface_del{%s}\n", iface ? iface->ifname : "<all>");
	if (xi->rx_sock_n) {
		ret = bpf_map__delete_elem(xc->x->xsks_base_map,
					   &xi->iface->ifindex, sizeof (uint32_t),
					   0);
		if (ret < 0)
			printf("map_delete{xsks_base} failed: %m\n");
	}

	for (i = 0; i < xi->tx_sock_n; i++)
		_socket_cleanup(xi->tx_sock[i], false);
	for (i = 0; i < xi->rx_sock_n; i++)
		_socket_cleanup(xi->rx_sock[i], true);
	free(xi->rx_sock);
	free(xi->tx_sock);

	// xxx del ifrule output with our index
	list_del(&xi->list);
	free(xi);
	return 0;
}


static void
_xsk_veth_iface_event_cb(struct gtp_interface *iface, enum gtp_interface_event type,
			 void *udata, void *arg)
{
	struct gtp_xsk_ctx *xc = udata;

	if (type == GTP_INTERFACE_EV_DESTROYING) {
		gtp_netlink_link_delete(iface->ifindex);
		xc->veth_iface_rx = NULL;
	}
}


static int
_xsk_create_veth_socket(struct gtp_xsk_ctx *xc)
{
	struct gtp_interface *iface;
	struct gtp_bpf_prog *p = xc->x->p;
	char veth_in[16], veth_out[16];
	int ret;

	snprintf(veth_in, sizeof (veth_in), "%.9s-xi%d", xc->c.name, xc->instance_id);
	snprintf(veth_out, sizeof (veth_out), "%.9s-xo%d", xc->c.name, xc->instance_id);

	/* create virtual 'rx' interface */
	iface = gtp_interface_get(veth_in, true);
	if (iface == NULL) {
		ret = gtp_netlink_link_create_veth(veth_in, veth_out);
		if (ret < 0)
			return -1;
		iface = gtp_interface_get(veth_in, true);
		if (iface == NULL)
			return -1;
	} else {
		log_message(LOG_INFO, "xsk{%s-%d}: veth iface already exists, use it "
			    "(maybe it was not cleaned from previous run)",
			    xc->c.name, xc->instance_id);
	}
	xc->veth_iface_rx = iface;

	/* veth will need to forward packets back to physical interface */
	if (xsk_set_iface_forwarding(veth_in, 1, 1))
		goto err;

	/* retrieve interface on the 'rx' side of the veth, and attach
	 * bpf-program. use custom bpf-program function name. */
	iface->bpf_prog = p;
	snprintf(iface->xdp_progname, sizeof (iface->xdp_progname),
		 "%s_xsk", xc->c.name);
	list_add(&iface->bpf_prog_list, &p->iface_bind_list);
	__clear_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	if (gtp_interface_start(iface) < 0)
		goto err;
	gtp_interface_register_event(xc->veth_iface_rx, _xsk_veth_iface_event_cb, xc);

	/* start tx side (packet entry in veth from userspace) */
	iface = gtp_interface_get(veth_out, true);
	if (iface == NULL)
		goto err;
	__set_bit(GTP_INTERFACE_FL_BPF_NO_DEFAULT_ROUTE_BIT, &iface->flags);
	__clear_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	if (gtp_interface_start(iface) < 0 ||
	    _xsk_iface_add(xc, iface, true) < 0) {
		gtp_interface_destroy(iface);
		goto err;
	}

	return 0;

 err:
	if (xc->veth_iface_rx != NULL) {
		gtp_netlink_link_delete(xc->veth_iface_rx->ifindex);
		gtp_interface_destroy(xc->veth_iface_rx);
		xc->veth_iface_rx = NULL;
	}
	return -1;
}

static void
_xsk_ifrules_event(void *user_data, enum gtp_bpf_ifrules_event type, void *arg)
{
	struct gtp_xsk_ctx *xc = user_data;
	struct gtp_xsk_iface *xi;
	struct gtp_if_rule *r = arg;
	bool found = false;
	int i;

	/* not interested by rules that are not binded to an interface */
	if (r->from == NULL || r->from == xc->veth_iface_rx)
		return;

	/* map to xsk_iface */
	list_for_each_entry(xi, &xc->iface_list, list) {
		if (r->from == xi->iface || r->from->link_iface == xi->iface) {
			found = true;
			break;
		}
	}
	if (!found)
		return;

	switch (type) {
	case GTP_BPF_IFRULES_IN_ADDING:
		/* before installing input_rule: set xsk base index if source
		 * interface has some af_xdp socket created */
		if (!xc->c.egress_xdp_hook && xi->rx_sock_n)
			r->xsk_base_idx = xi->bpf_base_index;
		break;

	case GTP_BPF_IFRULES_IN_ADD:
	case GTP_BPF_IFRULES_IN_DEL:
	case GTP_BPF_IFRULES_IN_UPDATE:
		if (xc->veth_iface_rx == NULL)
			break;
		for (found = false, i = 0;
		     i < ARRAY_SIZE(xc->c.prc_action_filter) &&
			     xc->c.prc_action_filter[i]; i++) {
			if (xc->c.prc_action_filter[i] == r->action) {
				found = true;
				break;
			}
		}
		if (!found)
			break;

		/* copy rule and add it under xsk_veth_rx iface */
		struct gtp_if_rule cr = *r;
		cr.from = xc->veth_iface_rx;
		cr.xsk_base_idx = 0;
		cr.table_id = r->table_id ?: r->from ? r->from->table_id : 0;
		struct if_rule_key_base *bk = cr.key;
		bk->ifindex = xc->veth_iface_rx->ifindex;
		gtp_bpf_ifrules_set(&cr, type != GTP_BPF_IFRULES_IN_DEL);
		break;
	}
}

/* process all notifs from thread, in main context */
static void
_notif_m_read_cb(struct thread *t)
{
	struct gtp_xsk_ctx *xc = THREAD_ARG(t);
	struct gtp_xsk_notif *n, *n_tmp;
	struct list_head tmp_list = LIST_HEAD_INIT(tmp_list);
	int fd = THREAD_FD(t);
	char buf[PIPE_BUF];
	int ret;

	ret = read(fd, buf, sizeof (buf));
	if (ret < 0) {
		log_message(LOG_ERR, "notif_m_read pipe: %m");
		return;
	}

	pthread_mutex_lock(&xc->notif_m_lock);
	list_splice_init(&xc->notif_m_list, &tmp_list);
	pthread_mutex_unlock(&xc->notif_m_lock);

	list_for_each_entry_safe(n, n_tmp, &tmp_list, list) {
		n->cb(n->cb_ud, n->data, n->size);
		free(n);
	}

	xc->notif_m_th = thread_add_read(master, _notif_m_read_cb, xc,
					 xc->m_r_fd, TIMER_NEVER, 0);
}


/* should be called from thread context.
 * it will call 'cb' in main context. */
void
gtp_xsk_send_notif(struct gtp_xsk_ctx *xc, gtp_xsk_notif_t cb, void *cb_ud,
		   const void *data, size_t size)
{
	struct gtp_xsk_notif *n;
	bool wake_up;

	n = malloc(sizeof(*n) + size);
	if (n == NULL)
		return;
	n->cb = cb;
	n->cb_ud = cb_ud;
	n->size = size;
	memcpy(n->data, data, size);

	pthread_mutex_lock(&xc->notif_m_lock);
	wake_up = list_empty(&xc->notif_m_list);
	list_add_tail(&n->list, &xc->notif_m_list);
	pthread_mutex_unlock(&xc->notif_m_lock);

	if (wake_up) {
		uint8_t c = 69;
		int ret = write(xc->th_w_fd, &c, 1);
		if (ret < 0)
			log_message(LOG_ERR, "notif_m_write pipe: %m");
	}
}

struct thread_master *
gtp_xsk_thread_master(struct gtp_xsk_ctx *xc)
{
	return xc->master;
}


struct gtp_xsk_ctx *
gtp_xsk_create(struct gtp_bpf_prog *p, struct gtp_xsk_cfg *cfg)
{
	struct gtp_interface *iface;
	struct gtp_bpf_xsk *x;
	struct gtp_xsk_ctx *xc;
	int fds[2];
	int ret;

	x = gtp_bpf_prog_tpl_data_get(p, "xsks");
	if (x == NULL)
		return NULL;

	xc = calloc(1, sizeof (*xc));
	if (xc == NULL)
		return NULL;
	xc->c = *cfg;
	xc->x = x;
	xc->instance_id = next_instance_id++;
	xc->th_r_fd = -1;
	xc->m_w_fd = -1;
	xc->th_w_fd = -1;
	xc->m_r_fd = -1;
	INIT_LIST_HEAD(&xc->iface_list);

	/* communication channels */
	ret = pipe2(fds, O_CLOEXEC | O_NONBLOCK);
	if (ret < 0) {
		printf("pipe2: %m\n");
		goto err;
	}
	xc->th_r_fd = fds[0];
	xc->m_w_fd = fds[1];
	INIT_LIST_HEAD(&xc->notif_th_list);
	pthread_mutex_init(&xc->notif_th_lock, NULL);

	ret = pipe2(fds, O_CLOEXEC | O_NONBLOCK);
	if (ret < 0) {
		printf("pipe2: %m\n");
		goto err;
	}
	xc->m_r_fd = fds[0];
	xc->th_w_fd = fds[1];
	INIT_LIST_HEAD(&xc->notif_m_list);
	pthread_mutex_init(&xc->notif_m_lock, NULL);
	xc->notif_m_th = thread_add_read(master, _notif_m_read_cb, xc,
					 xc->m_r_fd, TIMER_NEVER, 0);

	/* create AF_XDP for already bound sockets */
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		if (!__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags)) {
			if (_xsk_iface_add(xc, iface, false))
				goto err;
		}
	}

	/* create veth pair if packet re-circulation is enabled */
	if (cfg->egress_xdp_hook && _xsk_create_veth_socket(xc))
		goto err;

	if (xc->c.bpf_ifrules != NULL)
		gtp_bpf_ifrules_register_event(xc->c.bpf_ifrules,
					       _xsk_ifrules_event, xc);

	/* register ourself in bpf_xsk */
	x->xc[x->xc_n++] = xc;

	return xc;

 err:
	gtp_xsk_release(xc);
	return NULL;
}

int
gtp_xsk_run(struct gtp_xsk_ctx *xc)
{
	int ret;
	cpu_set_t set;

	if (xc->task_running)
		return 0;

	ret = pthread_create(&xc->task, NULL, gtp_xsk_main_loop, xc);
	if (ret < 0) {
		log_message(LOG_INFO, "pthread_create: %m");
		return -1;
	}
	xc->task_running = true;

	CPU_ZERO(&set);
	CPU_SET(2, &set);
	pthread_setaffinity_np(xc->task, sizeof(set), &set);

	return 0;
}


static void
_xsk_stop(struct gtp_xsk_ctx *xc)
{
	struct gtp_xsk_notif *n, *n_tmp;
	int ret, i;

	for (i = 0; i < xc->x->xc_n; i++)
		if (xc->x->xc[i] == xc) {
			xc->x->xc[i] = xc->x->xc[--xc->x->xc_n];
			break;
		}

	if (xc->c.bpf_ifrules != NULL)
		gtp_bpf_ifrules_unregister_event(xc->c.bpf_ifrules,
						 _xsk_ifrules_event, xc);

	if (xc->veth_iface_rx != NULL) {
		gtp_interface_unregister_event(xc->veth_iface_rx,
					       _xsk_veth_iface_event_cb, xc);
		ret = gtp_netlink_link_delete(xc->veth_iface_rx->ifindex);
		if (ret < 0)
			printf("xsk_stop: link_delete: %m\n");
		xc->veth_iface_rx = NULL;
	}

	while (!list_empty(&xc->iface_list))
		_xsk_iface_del(xc, NULL);

	if (xc->task_running) {
		xc->task_running = false;
		gtp_xsk_send_thread_notif(xc, _notif_th_shutdown, xc, NULL, 0);
		pthread_join(xc->task, NULL);
	}
	thread_del(xc->notif_m_th);
	pthread_mutex_destroy(&xc->notif_m_lock);
	list_for_each_entry_safe(n, n_tmp, &xc->notif_m_list, list)
		free(n);
	if (xc->th_r_fd >= 0)
		close(xc->th_r_fd);
	if (xc->m_w_fd >= 0)
		close(xc->m_w_fd);
	if (xc->th_r_fd >= 0)
		close(xc->th_r_fd);
	if (xc->m_w_fd >= 0)
		close(xc->m_w_fd);
	xc->th_r_fd = -1;
	xc->m_w_fd = -1;
	xc->th_w_fd = -1;
	xc->m_r_fd = -1;
}

void
gtp_xsk_release(struct gtp_xsk_ctx *xc)
{
	_xsk_stop(xc);
	free(xc);
}



/*************************************************************************/
/*
 *	eBPF template for xsk  (run in main context)
 */


/*
 * umem is the memory shared between us and the kernel, where packets are stored.
 *
 * each packet (== descriptor) must fit in a 4KB page.
 * real packet data could be about 3.5KB because XDP use space at beginning and end.
 * ip packet could be fragmented into multiple descriptors.
 *
 * only ONE umem is created per bpf program, and will be shared with ALL AF_XDP sockets.
 *
 * packet memory should hold at least (fill ring size + completion ring size) buffers,
 * and may hold more, if we intend to hold (queue) RX packets for a few time before TX them.
 */
static int
_umem_setup(struct gtp_bpf_xsk *x)
{
	size_t buffer_size;
	uint32_t i;

	/* enough descriptors to fit all fill+completion rings, plus
	 * 'buffered' packets */
	if (x->p->xsk_desc_n < 32)
		x->p->xsk_desc_n = 32;
	if (x->p->xsk_desc_n > 100000)
		x->p->xsk_desc_n = 100000;
	x->desc_n = x->p->xsk_desc_n * 1024;

	/* create the 'big buffer' that will hold ALL packets data. */
	/*   32k packets of 4k size each => 128 MB */
	buffer_size = x->desc_n * XSK_UMEM__DEFAULT_FRAME_SIZE;
	x->buffer = mmap(NULL, buffer_size,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (x->buffer == MAP_FAILED) {
		log_message(LOG_ERR, "xsk: mmap of %ldMB failed: %m",
			    buffer_size / (1024 * 1024));
		goto out;
	}

	LIBBPF_OPTS(xsk_umem_opts, umem_cfg,
		    .size = buffer_size,
		    .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		    .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		    .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
		    /* leave space before packet data on rx, if we wanna add encap. */
		    .frame_headroom = 128,
		    .flags = 0,
		    .tx_metadata_len = 0,
	);

	/* create umem. umem fill/completion queues will not be used, as we
	 * will allocate one for each sockets (but it is mandatory here). */
	x->umem = xsk_umem__create_opts(x->buffer, &x->unused_fq, &x->unused_cq,
					&umem_cfg);
	if (x->umem == NULL) {
		log_message(LOG_ERR, "cannot create xsk umem: %m");
		goto out;
	}

	/* add all descriptor addresses into free array */
	x->desc_free = calloc(x->desc_n, sizeof (*x->desc_free));
	for (i = 0; i < x->desc_n; i++)
		x->desc_free[x->desc_free_n++] = i * XSK_UMEM__DEFAULT_FRAME_SIZE;

#if 0
	// XXX: when we will want to hold descriptors
	u->desc_pending = calloc(u->desc_n * 2,
				 sizeof (struct gtp_xsk_desc) +
				 x->c.pkt_cb_user_size);
#endif
	return 0;

 out:
	if (x->umem != NULL)
		(void)xsk_umem__delete(x->umem);
	if (x->buffer != MAP_FAILED)
		munmap(x->buffer, buffer_size);
	x->buffer = NULL;
	return -1;
}

static void
_umem_cleanup(struct gtp_bpf_xsk *x)
{
	if (x->umem != NULL)
		(void)xsk_umem__delete(x->umem);
	if (x->buffer != NULL)
		munmap(x->buffer, x->desc_n * XSK_UMEM__DEFAULT_FRAME_SIZE);
	free(x->desc_free);
}


static void *
gtp_bpf_xsk_alloc(struct gtp_bpf_prog *p)
{
	struct gtp_bpf_xsk *x;

	x = calloc(1, sizeof (*x));
	if (x == NULL)
		return NULL;
	x->p = p;
	x->bpf_next_base_index = 1;	/* keep 0 as unused index */
	return x;
}

static void
gtp_bpf_xsk_release(struct gtp_bpf_prog *p, void *udata)
{
	free(udata);
}

static int
gtp_bpf_xsk_loaded(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct gtp_bpf_xsk *x = udata;

	x->xsks_map = gtp_bpf_prog_load_map(p->obj_load, "xsks");
	x->xsks_base_map = gtp_bpf_prog_load_map(p->obj_load, "xsks_base");
	if (x->xsks_map == NULL || x->xsks_base_map == NULL)
		return -1;

	if (!reload && _umem_setup(x))
		return -1;

	return 0;
}

static void
gtp_bpf_xsk_closed(struct gtp_bpf_prog *p, void *udata)
{
	struct gtp_bpf_xsk *x = udata;

	while (x->xc_n > 0)
		_xsk_stop(x->xc[0]);
	_umem_cleanup(x);
}


static int
gtp_bpf_xsk_bind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct gtp_bpf_xsk *x = udata;
	int i;

	for (i = 0; i < x->xc_n; i++)
		if (_xsk_iface_add(x->xc[i], iface, false))
			return -1;

	return 0;
}

static void
gtp_bpf_xsk_unbind_itf(struct gtp_bpf_prog *p, void *udata, struct gtp_interface *iface)
{
	struct gtp_bpf_xsk *x = udata;
	int i;

	for (i = 0; i < x->xc_n; i++)
		_xsk_iface_del(x->xc[i], iface);
}

static void
gtp_bpf_xsk_vty(struct gtp_bpf_prog *p, void *udata, struct vty *vty,
		int argc, const char **argv)
{
	struct gtp_bpf_xsk *x = udata;
	char buf[60000];
	int i;

	vty_out(vty, "===\n");
	vty_out(vty, "xsk on bpf-program '%s', %d attached context:\n",
		p->name, x->xc_n);
	for (i = 0; i < x->xc_n; i++) {
		_xsk_ctx_dump(x->xc[i], buf, sizeof (buf));
		vty_out(vty, "%s", buf);
	}
}


static struct gtp_bpf_prog_tpl gtp_bpf_xsk_module = {
	.name = "xsks",
	.description = "AF_XDP handler",
	.alloc = gtp_bpf_xsk_alloc,
	.release = gtp_bpf_xsk_release,
	.loaded = gtp_bpf_xsk_loaded,
	.closed = gtp_bpf_xsk_closed,
	.iface_bind = gtp_bpf_xsk_bind_itf,
	.iface_unbind = gtp_bpf_xsk_unbind_itf,
	.vty_out = gtp_bpf_xsk_vty,
};

static void __attribute__((constructor))
gtp_bpf_xsk_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_xsk_module);
}
