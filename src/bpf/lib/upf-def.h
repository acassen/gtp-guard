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
#define UPF_FL_QUOTA_REACHED			0x04

#define UPF_TRIG_FL_VOLTH			0x0001
#define UPF_TRIG_FL_TIMTH			0x0002
#define UPF_TRIG_FL_VOLQU			0x0004
#define UPF_TRIG_FL_TIMQU			0x0008
#define UPF_TRIG_FL_PERIO			0x0010
#define UPF_TRIG_FL_QUHTI			0x0020
#define UPF_TRIG_FL_START			0x0040
#define UPF_TRIG_FL_STOPT			0x0080

/* current urr stats. owned by bpf (256 bytes) */
struct upf_urr {
	struct bpf_timer timer;			/* 2u64 bytes */

	__u8		flags;			/* UPF_FL_* */
	__u8		cur_ver;
	__u16		_pad1;
	__u32		_pad2;

	/* volume counters, thresholds and quota (18u64) */
	struct upf_uur_vol_path {
		__u64	drop_pkt;
		__u64	pkt;
		__u64	bytes;			/* forwarded bytes */
		__u64	th;			/* config thres. in bytes */
		__u64	th_next;		/* trigger limit */
		__u64	qu;
		__u64	qu_next;
	}		ul, dl;
	__u64		total_th;
	__u64		total_th_next;
	__u64		total_qu;
	__u64		total_qu_next;

	__u32		urr_id;			/* pfcp urr_id ie */

	/* duration (u32 in sec. u64 in nsec) (10u64) */
	__u32		time_th;
	__u32		time_qu;
	__u32		time_periodic;
	__u32		time_inactivity;	/* quota holding time */
	__u32		inactivity_det_time;

	__u64		fwd_pkt_first;		/* first pkt seen */
	__u64		fwd_pkt_last;		/* last pkt seen */
	__u64		time_th_next;
	__u64		time_qu_next;
	__u64		inactive_time;		/* cumulative */
	__u64		time_periodic_next;
	__u64		time_inactivity_next;

	__u64		seid;
};


#define UPF_FL_CTL_INIT				0x01
#define UPF_FL_CTL_UPDATE			0x02
#define UPF_FL_CTL_DELETE			0x04
#define UPF_FL_CTL_REPORT			0x08
#define UPF_FL_CTL_MORE_CMD			0x10


struct upf_urr_cmd_req {
	__u64		seid;
	__u32		urr_id;			/* pfcp ie.urr_id */
	__u32		urr_idx;		/* idx in bpf map array */
	__u16		request_id;		/* trigger by syscall */
	__u8		flags;			/* UPF_FL_* */
	__u8		ctl_fl;			/* UPF_FL_CTL_* */
	__u8		cur_ver;

	__u32		time_th;
	__u32		time_qu;
	__u32		time_periodic;
	__u32		time_inactivity;
	__u32		inactivity_det_time;

	__u64		total_th;
	__u64		total_qu;
	__u64		dl_th;
	__u64		dl_qu;
	__u64		ul_th;
	__u64		ul_qu;
};

struct upf_urr_report {
	__u64		seid;
	__u32		urr_id;			/* pfcp urr_id ie */
	__u16		request_id;		/* if trigged by syscall */
	__u16		report_flags;		/* UPF_TRIG_FL_* */
};

struct upf_urr_report_data {
	struct upf_urr_report r;

	__u64		dl_bytes;
	__u64		dl_pkt;
	__u64		dl_drop_pkt;
	__u64		ul_bytes;
	__u64		ul_pkt;
	__u64		ul_drop_pkt;
	__u32		fwd_pkt_first;		/* first pkt seen */
	__u32		fwd_pkt_last;		/* last pkt seen */
};
