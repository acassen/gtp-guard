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
 *              Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */

#include <errno.h>
#include <libbpf.h>

#include "tools.h"
#include "cgn.h"
#include "cdr_fwd.h"
#include "cdr_avp.h"
#include "bpf/lib/cgn-def.h"


/* Extern data */
extern struct thread_master *master;


/*
 * perf buffer
 * bpf program sends event through it
 * one cgn_blog_pb allocated per cpu
 */
#define PERF_BUFFER_PAGES		8

struct cgn_blog_pb
{
	struct perf_buffer *pb;
	struct thread *t;
	uint64_t cpu;
};



/*
 * cdr type
 */
#define CDR_TYPE_ALLOC_IP		0x01
#define CDR_TYPE_RELEASE_IP		0x02

enum cdr_avp_type {
	CDR_REFERENCE_TIME_AVP	= 0x0014, /* u64 */

	CDR_PGW			= 0x1200, /* string */
	CDR_PRIV_IP46		= 0x1201, /* v4: u32, v6: u8 + 8bytes */
	CDR_PUB_IP46		= 0x1202, /* v4: u32, v6: u8 + 8bytes */
	CDR_PUB_PORT_START	= 0x1203, /* u16 */
	CDR_PUB_PORT_END	= 0x1204, /* u16 */
	CDR_DURATION		= 0x1205, /* u32, seconds */
	CDR_PUB_IP6		= 0x1210, /* v4: u32, v6: u8 + 8bytes */
};


static void
cgn_blog_send(struct cgn_ctx *c, const struct cgn_v4_block_log *e)
{
	uint8_t data[400 + sizeof (struct cdr_header)];
	struct cdr_header *hdr = (struct cdr_header *)(data);
	uint8_t *dst = (uint8_t *)(hdr + 1);
	uint8_t *end = data + sizeof (data);
	time_t now = time(NULL);
	uint16_t port;

	if (c->blog_cdr_fwd == NULL || c->blog_cdr_fwd->ctx == NULL)
		return;

	memset(hdr, 0x00, sizeof (*hdr));
	hdr->version = CDR_VERSION;
	hdr->ne_type = CDR_NE_CGNLOG;
	hdr->cdr_type = e->flag & CGN_BLOG_FL_ALLOC ?
		CDR_TYPE_ALLOC_IP : CDR_TYPE_RELEASE_IP;

	now = htobe64(now);
	cdr_avp_append(&dst, end - dst, CDR_REFERENCE_TIME_AVP,
		       sizeof (now), &now);
	++hdr->nb_avp;

	if (e->prefix[0]) {
		cdr_avp_append_str(&dst, end - dst, CDR_PGW, e->prefix);
		++hdr->nb_avp;
	}

	cdr_avp_append(&dst, end - dst, CDR_PRIV_IP46, 4, &e->priv_addr);
	++hdr->nb_avp;

	cdr_avp_append(&dst, end - dst, CDR_PUB_IP46, 4, &e->cgn_addr);
	++hdr->nb_avp;

	if (e->port_size) {
		port = htons(e->port_start + e->port_size - 1);
		cdr_avp_append(&dst, end - dst, CDR_PUB_PORT_END, 2, &port);
		port = htons(e->port_start);
		cdr_avp_append(&dst, end - dst, CDR_PUB_PORT_START, 2, &port);
		hdr->nb_avp += 2;
	}

	uint32_t duration = htonl(e->duration);
	cdr_avp_append(&dst, end - dst, CDR_DURATION, 4, &duration);
	++hdr->nb_avp;

	hdr->size = htobe16(dst - (uint8_t *)(hdr + 1));

	cdr_fwd_send_ticket(c->blog_cdr_fwd->ctx, data,
			    sizeof (*hdr) + be16toh(hdr->size));
}



static void
handle_event(void *uctx, int cpu, void *data, __u32 data_size)
{
	struct cgn_ctx *c = uctx;

	fprintf(stderr, "got perf event cpu: %d data: %p, size: %d\n",
		cpu, data, data_size);

	if (data_size != sizeof (struct cgn_v4_block_log)) {
		log_message(LOG_WARNING, "block_log event of wrong size: "
			    "userapp:%ld != bpf:%d",
			    sizeof (struct cgn_v4_block_log), data_size);
		return;
	}

	cgn_blog_send(c, data);
}

static void
handle_missed_events(void *, int cpu, __u64 lost_cnt)
{
	log_message(LOG_INFO, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

/* callback called by thread, when there is something to read on perf buffer's fd.
 * libbpf will handle data and then will call handle_event. */
static void
cgn_pb_io_read(struct thread *t)
{
	struct cgn_blog_pb *pb = THREAD_ARG(t);
	int err;

	err = perf_buffer__consume_buffer(pb->pb, pb->cpu);
	if (err)
		log_message(LOG_INFO, "perf consume buffer: %m");

	pb->t = thread_add_read(master, cgn_pb_io_read, pb, t->u.f.fd,
				TIMER_NEVER, 0);
}

int
cgn_blog_init(struct cgn_ctx *c)
{
	struct cgn_blog_pb *pb;
	int map_fd, fd;
	uint64_t cpu;

	if (c->blog_pb != NULL) {
		printf("skip %s, already done\n", __func__);
		return 0;
	}

	map_fd = bpf_map__fd(c->blog_event);
	c->blog_pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES,
				      handle_event, handle_missed_events, c, NULL);
	if (c->blog_pb == NULL) {
		log_message(LOG_ERR, "Failed to open perf buffer: %m");
		return -errno;
	}

	c->blog_apb = calloc(perf_buffer__buffer_cnt(c->blog_pb),
			     sizeof (*c->blog_apb));
	for (cpu = 0; cpu < perf_buffer__buffer_cnt(c->blog_pb); cpu++) {
		fd = perf_buffer__buffer_fd(c->blog_pb, cpu);
		if (fd < 0)
			return fd;

		pb = calloc(1, sizeof (*pb));
		pb->pb = c->blog_pb;
		pb->cpu = cpu;
		pb->t = thread_add_read(master, cgn_pb_io_read, pb, fd,
					TIMER_NEVER, 0);
		c->blog_apb[cpu] = pb;
	}

	return 0;
}

void
cgn_blog_release(struct cgn_ctx *c)
{
	struct cgn_blog_pb *pb;
	uint64_t cpu;

	for (cpu = 0; cpu < perf_buffer__buffer_cnt(c->blog_pb); cpu++) {
		pb = c->blog_apb[cpu];
		thread_del(pb->t);
		free(pb);
	}
	free(c->blog_apb);
	perf_buffer__free(c->blog_pb);
}
