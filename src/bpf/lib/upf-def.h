/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"
#include "capture-def.h"

//#define UPF_DEBUG

#ifdef UPF_DEBUG
# define UPF_DBG(Fmt, ...) bpf_printk(Fmt, ## __VA_ARGS__)
#else
# define UPF_DBG(...)
#endif

#define BPF_UPF_USER_MAP_SIZE		1000000
#define BPF_UPF_USER_COUNTER_MAP_SIZE	1200000


#define UE_IPV4		(1 << 0)
#define UE_IPV6		(1 << 1)

struct upf_ingress_key {
	__u16		flags;
	__u16		_pad;
	union v4v6addr  ue_addr;
}  __attribute__((packed));

struct upf_egress_key {
	__be32		gtpu_local_teid;
	__be32		gtpu_local_addr;
	__be16		gtpu_local_port;
} __attribute__((packed));


#define UPF_FWD_FL_ACT_FWD			(1 << 0)
#define UPF_FWD_FL_ACT_BUFF			(1 << 1)
#define UPF_FWD_FL_ACT_DROP			(1 << 2)
#define UPF_FWD_FL_ACT_DUPL			(1 << 3)
#define UPF_FWD_FL_ACT_CREATE_OUTER_HEADER	(1 << 4)
#define UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER	(1 << 5)
#define UPF_FWD_FL_INGRESS			(1 << 6)
#define UPF_FWD_FL_EGRESS			(1 << 7)
#define UPF_FWD_FL_ACT_KEEP_OUTER_HEADER	\
	(UPF_FWD_FL_ACT_CREATE_OUTER_HEADER |	\
	 UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER)

/* rules set by userapp. bpf doesn't write into. */
struct upf_fwd_rule {
	__be32		gtpu_remote_teid;
	__be32		gtpu_remote_addr;
	__be32		gtpu_local_addr;
	__be16		gtpu_remote_port;
	__be16		gtpu_local_port;

	__u32		ul_mbr;
	__u32		dl_mbr;

	__u8		tos_tclass;
	__u8		tos_mask;
	__u16		flags;
	__u32		urr_idx;	/* index to upf_urr{,_data} */

	struct capture_bpf_entry capture;

}  __attribute__((packed));


#define UPF_FL_MEAS_VOL				0x01
#define UPF_FL_MEAS_DUR				0x02

#define UPF_TRIG_FL_VOLTH			0x0001
#define UPF_TRIG_FL_TIMTH			0x0002
#define UPF_TRIG_FL_VOLQU			0x0004
#define UPF_TRIG_FL_TIMQU			0x0008
#define UPF_TRIG_FL_PERIO			0x0010
#define UPF_TRIG_FL_QUHTI			0x0020
#define UPF_TRIG_FL_START			0x0040
#define UPF_TRIG_FL_STOPT			0x0080

/* reporting rules. bpf doesn't write into. */
struct upf_urr {
	struct bpf_timer timer;

	__u32		urr_idx;		/* index to upf_urr{,_data} */
	__u8		cur_ver;		/* inc. on modifySession */
	__u8		flags;			/* UPF_FL_* */
	__u8		_pad[2];

	__u32		inactivity_det_time;	/* seconds */
	__u32		time_threshold;
	__u32		time_quota;
	__u32		time_periodic;
	__u32		time_inactivity;	/* quota holding time */
	__u32		_pad2;

	__u64		vol_thres_to;
	__u64		vol_thres_ul;
	__u64		vol_thres_dl;
	__u64		vol_quota_to;
	__u64		vol_quota_ul;
	__u64		vol_quota_dl;
};

/* current stats. written by bpf, reported to userapp */
struct upf_urr_data {
	__u64		seid;
	__u32		urr_id;			/* pfcp urr_id ie */
	__u16		report_flags;		/* UPF_TRIG_FL_* */
	__u8		cur_ver;
	__u8		quota_reached;
	__u8		_pad[6];

	/* report and reset on each report */
	__u64		fwd_pkt_ul;
	__u64		fwd_bytes_ul;
	__u64		drop_pkt_ul;
	__u64		fwd_pkt_dl;
	__u64		fwd_bytes_dl;
	__u64		drop_pkt_dl;
	__u64		fwd_pkt_first;	/* in ns. */
	__u64		fwd_pkt_last;	/* in ns. */
	__u64		inactive_time;	/* in ns. */

	/* set when generating a trigger */
	__u64		vol_quota_ul_used;
	__u64		vol_quota_dl_used;
	__u64		time_quota_used; /* in ns. */

	/* timers */
	__u64		time_periodic_next;
	__u64		time_inactivity_next;
};


struct urr_ctl_init_ctx {
	__u32		index;
	__u32		urr_id;
	__u64		seid;
	struct upf_urr	uu;
} __attribute__((packed));

struct urr_ctl_report_ctx {
	__u32		index;
	__u32		action;
	struct upf_urr_data uud;
} __attribute__((packed));
