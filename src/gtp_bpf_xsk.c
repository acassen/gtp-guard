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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
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
#include "gtp_bpf_xsk.h"

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


struct gtp_bpf_xsk;
struct gtp_xsk_socket;


enum {
	GTP_XSK_NOTIF_SHUTDOWN = 1,
	GTP_XSK_NOTIF_ADD_XS,
	GTP_XSK_NOTIF_DEL_XS,
};

struct gtp_xsk_notif_xs
{
	uint32_t		type;	/* GTP_XSK_NOTIF_ADD/DEL_XS */
	struct gtp_xsk_socket	*xs;
};

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
	int			refcnt;
	int			queue_id;
	uint32_t		xsk_map_idx;
	struct gtp_xsk_iface	*xi;
	struct gtp_xsk_ctx	*xc;
	struct xsk_socket	*xsk;

	/* rx */
	bool			have_rx;
	struct xsk_ring_cons	rx;
	struct xsk_ring_prod	fq;
	struct thread		*read_th;

	/* tx */
	bool			have_tx;
	struct xsk_ring_prod	tx;
	struct xsk_ring_cons	cq;
	uint32_t		outstanding_tx;
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
	struct thread		*notif_th;

	/* thread -> main notification channel */
	int			th_w_fd;
	int			m_r_fd;
	struct thread		*notif_m_th;
	struct list_head	notif_m_list;
	pthread_mutex_t		notif_m_lock;

	/* bound interfaces */
	struct list_head	iface_list;

	/* egress xdp hook */
	int			veth_ifindex_rx;
	struct gtp_interface	*veth_iface_tx;
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
	uint32_t		desc_n;		// number of descriptors in buffer
	size_t			buffer_size;	// desc_n * frame_size
	void			*buffer;
#if 0
	/* pkt buffering */
	struct pq_desc		*desc_pending;
	uint32_t		desc_pending_b;
	uint32_t		desc_pending_e;
#endif
	uint64_t		*desc_free;
	uint32_t		desc_free_n;
};

/* locals */
static int next_instance_id;

/* Extern data */
extern struct thread_master *master;


/*************************************************************************/
/*
 *	Helpers
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
#endif



#if 0
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

	/* kick tx */
	ret = sendto(xsk_socket__fd(xs->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret < 0 && (errno != EAGAIN && errno != EBUSY && errno != ENETDOWN))
		printf("kick_tx sento: %m\n");

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
			printf("TX ring buffer is full\n");
			return;
		}
	}

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
	if (xs->have_tx) {
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
	struct gtp_xsk_socket *xs = THREAD_ARG(t);
	struct gtp_xsk_ctx *xc = xs->xc;
	struct gtp_bpf_xsk *x = xs->xc->x;
	struct gtp_xsk_desc pkt;
	uint32_t rcvd, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	/* how many descriptors to read ? */
	rcvd = xsk_ring_cons__peek(&xs->rx, 64, &idx_rx);
	if (!rcvd)
		goto end;
	printf("socket_cb: %d\n", rcvd);

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
			break;
		case GTP_XSK_TX:
			printf("%s tx\n", __func__);
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
		}

		if (ret != GTP_XSK_QUEUE)
			x->desc_free[x->desc_free_n++] = desc->addr;
	}

	// acke'd, we read them
	xsk_ring_cons__release(&xs->rx, rcvd);

	// now we give back to kernel the same number of descriptors,
	// so it won't run out.
	if (x->desc_free_n < rcvd) {
		printf("ooops, running out of RX descriptors :/\n");
		goto end;
	}
	if (xsk_ring_prod__reserve(&xs->fq, rcvd, &idx_fq) == 0) {
		printf("cannot write into fill queue, what the kernel is doing ?\n");
		goto end;
	}
	for (i = 0; i < rcvd; i++)
		*xsk_ring_prod__fill_addr(&xs->fq, idx_fq++) =
			x->desc_free[--x->desc_free_n];
	xsk_ring_prod__submit(&xs->fq, rcvd);

 end:
	xs->read_th = thread_add_read(xc->master, _socket_cb, xs,
				      xsk_socket__fd(xs->xsk), TIMER_NEVER, 0);
}



static void
_notif_read_cb(struct thread *th)
{
	struct gtp_xsk_ctx *xc = THREAD_ARG(th);
	struct gtp_xsk_notif_xs *n_xs;
	struct gtp_xsk_socket *xs;
	int fd = THREAD_FD(th);
	char buf[PIPE_BUF];
	uint32_t *type;
	int ret;

	ret = read(fd, buf, sizeof (buf));
	if (ret < 0) {
		printf("read pipe: %m\n");
		return;
	}

	/* process notifications */
	type = (uint32_t *)(buf);
	switch (*type) {
	case GTP_XSK_NOTIF_SHUTDOWN:
		printf("receive shutdown notif\n");
		thread_add_terminate_event(xc->master);
		xc->notif_th = NULL;
		return;

	case GTP_XSK_NOTIF_ADD_XS:
		n_xs = (struct gtp_xsk_notif_xs *)buf;
		fd = xsk_socket__fd(n_xs->xs->xsk);
		n_xs->xs->read_th = thread_add_read(xc->master, _socket_cb,
						    n_xs->xs, fd, TIMER_NEVER, 0);
		break;

	case GTP_XSK_NOTIF_DEL_XS:
		n_xs = (struct gtp_xsk_notif_xs *)buf;
		xs = n_xs->xs;
		thread_del(xs->read_th);
		xsk_socket__delete(xs->xsk);
		free(xs);
		break;

	default:
		break;
	}

	xc->notif_th = thread_add_read(xc->master, _notif_read_cb, xc,
				       xc->th_r_fd, TIMER_NEVER, 0);
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

	xc->notif_th = thread_add_read(xc->master, _notif_read_cb, xc,
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
	xs->refcnt = !!w_rx + !!w_tx;
	xs->queue_id = queue_id;
	xs->xsk_map_idx = xi->bpf_base_index + queue_id;
	xs->have_rx = w_rx;
	xs->have_tx = w_tx;
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

	/* wait for 1ms max. */
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
	printf("fq cons: %p prod: %p\n", xs->fq.consumer, xs->fq.producer);

	if (!w_rx) {
		printf("done creating TX xsk\n");
		return xs;
	}

	/* insert this fd into bpf's map BPF_MAP_TYPE_XSKMAP */
	fd = xsk_socket__fd(xs->xsk);
	bpf_map__update_elem(x->xsks_map, &xs->xsk_map_idx, sizeof (uint32_t),
			     &fd, sizeof (fd), 0);

	/* add socket into thread's iomux */
	struct gtp_xsk_notif_xs n = {
		.type = GTP_XSK_NOTIF_ADD_XS,
		.xs = xs,
	};
	ret = write(xc->m_w_fd, &n, sizeof (n));
	if (ret < 0)
		printf("write pipe: %m\n");

	/* give kernel some descriptors for RX, by writting into fill ring */
	ret = xsk_ring_prod__reserve(&xs->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	assert(ret == XSK_RING_PROD__DEFAULT_NUM_DESCS);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&xs->fq, idx++) = x->desc_free[--x->desc_free_n];
	xsk_ring_prod__submit(&xs->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xs;
}

static void
_socket_cleanup(struct gtp_xsk_socket *xs)
{
	struct gtp_xsk_ctx *xc = xs->xc;
	int ret;

	if (--xs->refcnt)
		return;

	bpf_map__delete_elem(xc->x->xsks_map, &xs->xsk_map_idx,
			     sizeof (uint32_t), 0);

	struct gtp_xsk_notif_xs n = {
		.type = GTP_XSK_NOTIF_DEL_XS,
		.xs = xs,
	};
	ret = write(xc->m_w_fd, &n, sizeof (n));
	if (ret < 0)
		printf("write pipe: %m\n");
}


static int
_xsk_iface_add(struct gtp_xsk_ctx *xc, struct gtp_interface *iface)
{
	struct gtp_bpf_xsk *x = xc->x;
	struct gtp_xsk_iface *xi;
	struct gtp_xsk_socket *xs;
	int i, ret, sock_n;

	xi = calloc(1, sizeof (*xi));
	if (xi == NULL)
		return -1;
	xi->xc = xc;
	xi->iface = iface;
	xi->bpf_base_index = x->bpf_next_base_index;

	ret = xsk_get_cur_queues(iface->ifname, &xi->rx_sock_n, &xi->tx_sock_n);
	if (ret < 0)
		goto err;

	printf("iface_add{%s}: %p %p\n", iface->ifname, iface, xc->veth_iface_tx);
	if (iface != xc->veth_iface_tx) {
		xi->rx_sock = calloc(xi->rx_sock_n, sizeof (*xi->rx_sock));
		if (xi->rx_sock == NULL)
			goto err;
	} else {
		xi->rx_sock_n = 0;
	}

	if (xc->c.egress_xdp_hook && iface != xc->veth_iface_tx) {
		xi->tx_sock_n = 0;
	} else {
		xi->tx_sock = calloc(xi->tx_sock_n, sizeof (*xi->tx_sock));
		if (xi->tx_sock == NULL)
			goto err;
	}
	printf("iface %s rx_queue: %d tx_queue: %d\n", iface->ifname,
	       xi->rx_sock_n, xi->tx_sock_n);

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
	if (iface == xc->veth_iface_tx)
		xc->veth_xs = xi->tx_sock[0];

	if (xi->rx_sock_n) {
		ret = bpf_map__update_elem(x->xsks_base_map,
					   &iface->ifindex, sizeof (uint32_t),
					   &xi->bpf_base_index, sizeof (uint32_t),
					   0);
		if (ret < 0) {
			printf("map_insert{xsks_base} failed: %m\n");
		}

		// xxx also set this index in ifrule input, as an optimization
	}

	x->bpf_next_base_index += xi->rx_sock_n;
	list_add(&xi->list, &xc->iface_list);
	return 0;

 err:
	// XXX delete created sockets
	free(xi->rx_sock);
	free(xi->tx_sock);
	free(xi);
	printf("CANNOT add interface\n");
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

	for (i = 0; i < xi->rx_sock_n; i++)
		_socket_cleanup(xi->rx_sock[i]);
	for (i = 0; i < xi->tx_sock_n; i++)
		_socket_cleanup(xi->tx_sock[i]);
	free(xi->rx_sock);
	free(xi->tx_sock);

	// xxx del ifrule output with our index
	list_del(&xi->list);
	free(xi);
	return 0;
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

	/* retrieve interface on the 'rx' side of the veth, and attach
	 * bpf-program. use custom bpf-program function name. */
	iface->bpf_prog = p;
	snprintf(iface->xdp_progname, sizeof (iface->xdp_progname),
		 "%s_xsk", xc->c.name);
	list_add(&iface->bpf_prog_list, &p->iface_bind_list);
	__clear_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	xc->veth_ifindex_rx = iface->ifindex;
	if (gtp_interface_start(iface) < 0) {
		gtp_netlink_link_delete(iface->ifindex);
		return -1;
	}

	/* start output side, to be added to ifrule */
	// XXX: only need to retrieve ifindex ?
	iface = gtp_interface_get(veth_out, true);
	if (iface == NULL)
		return -1;
	xc->veth_iface_tx = iface;
	__set_bit(GTP_INTERFACE_FL_BPF_NO_DEFAULT_ROUTE_BIT, &iface->flags);
	__clear_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	gtp_interface_start(iface);

	return _xsk_iface_add(xc, xc->veth_iface_tx);
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
	list_add(&n->list, &xc->notif_m_list);
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

	/* create veth pair if packet re-circulation is enabled */
	if (cfg->egress_xdp_hook && _xsk_create_veth_socket(xc))
		goto err;

	/* communication channels */
	ret = pipe2(fds, O_CLOEXEC | O_DIRECT | O_NONBLOCK);
	if (ret < 0) {
		printf("pipe2: %m\n");
		goto err;
	}
	xc->th_r_fd = fds[0];
	xc->m_w_fd = fds[1];

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

	/* start worker thread */
	ret = pthread_create(&xc->task, NULL, gtp_xsk_main_loop, xc);
	if (ret < 0) {
		log_message(LOG_INFO, "pthread_create: %m");
		goto err;
	}
	xc->task_running = true;

	/* create AF_XDP for already bound sockets */
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		if (__test_bit(GTP_INTERFACE_FL_RUNNING_BIT, &iface->flags) &&
		    iface->ifindex != xc->veth_ifindex_rx) {
			printf("xsk create: adding iface %s\n", iface->ifname);
			if (_xsk_iface_add(xc, iface))
				goto err;
		}
	}

	/* register ourself in bpf_xsk */
	x->xc[x->xc_n++] = xc;

	return xc;

 err:
	gtp_xsk_release(xc);
	return NULL;
}

static void
_xsk_stop(struct gtp_xsk_ctx *xc)
{
	struct gtp_xsk_notif *n, *n_tmp;
	uint32_t type = GTP_XSK_NOTIF_SHUTDOWN;
	int ret, i;

	for (i = 0; i < xc->x->xc_n; i++)
		if (xc->x->xc[i] == xc) {
			xc->x->xc[i] = xc->x->xc[--xc->x->xc_n];
			break;
		}

	printf("stopping xsk context, veth_ifindex: %d\n", xc->veth_ifindex_rx);
	if (xc->veth_ifindex_rx) {
		ret = gtp_netlink_link_delete(xc->veth_ifindex_rx);
		if (ret < 0)
			printf("xsk_stop: link_delete: %m\n");
		xc->veth_ifindex_rx = 0;
	}

	while (!list_empty(&xc->iface_list))
		_xsk_iface_del(xc, NULL);

	if (xc->task_running) {
		ret = write(xc->m_w_fd, &type, sizeof (type));
		if (ret < 0)
			printf("write{shutdown}: %m\n");

		xc->task_running = false;
		pthread_join(xc->task, NULL);
	}
	pthread_mutex_destroy(&xc->notif_m_lock);
	list_for_each_entry_safe(n, n_tmp, &xc->notif_m_list, list)
		free(n);
	thread_del(xc->notif_m_th);
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
	uint32_t i;

	/* enough descriptors to fit all fill+completion rings, plus
	 * 'buffered' packets. default_num_desc is 2048 */
	x->desc_n = 32 * XSK_RING_PROD__DEFAULT_NUM_DESCS;

	/* create the 'big buffer' that will hold packets data. */
	/*   20k packets of 4k size each => 80 MB  (for one rx queue) */
	x->buffer_size = x->desc_n * XSK_UMEM__DEFAULT_FRAME_SIZE;
	x->buffer = mmap(NULL, x->buffer_size,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (x->buffer == MAP_FAILED) {
		printf("ERROR: mmap failed: %m\n");
		goto out;
	}

	LIBBPF_OPTS(xsk_umem_opts, umem_cfg,
		    .size = x->buffer_size,
		    .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
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
		printf("cannot create xsk umem\n");
		goto out;
	}

	// add all descriptors into free array
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
		munmap(x->buffer, x->buffer_size);
	x->buffer = NULL;
	return -1;
}

static void
_umem_cleanup(struct gtp_bpf_xsk *x)
{
	if (x->umem != NULL)
		(void)xsk_umem__delete(x->umem);
	if (x->buffer != NULL)
		munmap(x->buffer, x->buffer_size);
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
		if (_xsk_iface_add(x->xc[i], iface))
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

	vty_out(vty, "xsk contexts: %d\n", x->xc_n);
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
