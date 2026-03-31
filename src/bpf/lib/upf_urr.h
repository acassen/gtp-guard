/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once



struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} upf_events SEC(".maps");

static __always_inline void
_urr_compute_duration(struct upf_urr *uu, __u32 rnow)
{
	__u32 last_pkt = max(uu->ul_last_pkt, uu->dl_last_pkt);
	if (uu->duration_ts_last && last_pkt > uu->duration_ts_last) {
		__u32 dur = last_pkt - uu->duration_ts_last;
		if (dur > uu->inactive_time)
			uu->duration += dur - uu->inactive_time;
		uu->inactive_time = 0;
		uu->duration_ts_last = rnow;
	}
}


static __always_inline void
_urr_send_report(struct upf_urr *uu, __u16 trigger_fl, __u16 request_id)
{
	struct upf_urr_report_data ur;

	/* sends interesting values through ringbuf */
	ur.r.seid = uu->seid;
	ur.r.urr_idx = uu->urr_idx;
	ur.r.report_flags = trigger_fl;
	ur.r.request_id = request_id;
	ur.dl_bytes = uu->dl_bytes;
	ur.dl_pkt = uu->dl_pkt;
	ur.dl_drop_pkt = uu->dl_drop_pkt;
	ur.ul_bytes = uu->ul_bytes;
	ur.ul_pkt = uu->ul_pkt;
	ur.ul_drop_pkt = uu->ul_drop_pkt;
	ur.report_first_pkt = ((__u64)uu->report_first_pkt << 24) / NSEC_PER_SEC;
	ur.report_last_pkt = ((__u64)uu->report_last_pkt << 24) / NSEC_PER_SEC;
	ur.duration = uu->duration ?
		((__u64)(uu->duration + 1) << 24) / NSEC_PER_SEC : 0;

#ifdef UPF_DEBUG
	bpf_printk("%s: send report from BPF, trigger flags: 0x%x, dl:%ld ul:%ld dur:%d",
		   __func__, trigger_fl, uu->dl_bytes, uu->ul_bytes, ur.duration);
#endif

	bpf_ringbuf_output(&upf_events, &ur, sizeof(ur), 0);

	uu->report_first_pkt = 0;
	uu->report_last_pkt = 0;
}

/* return 'timeout' in ns, when next timer should trigger */
static __always_inline __u64
_urr_compute_next_tick(struct upf_urr *uu, __u32 rnow)
{
	__u64 ret = ~0;

	if (uu->time_th && uu->duration_ts_last) {
		__u32 elapsed = uu->duration - uu->duration_th_last;
		if (elapsed < uu->time_th)
			ret = rnow + uu->time_th - elapsed + 50;
		else
			ret = rnow;
	}

	if (uu->time_qu && uu->duration_ts_last) {
		__u32 elapsed = uu->duration - uu->duration_qu_last;
		if (elapsed < uu->time_qu)
			ret = min(ret, rnow + uu->time_qu - elapsed + 50);
		else
			ret = rnow;
	}

	if (uu->time_periodic_next) {
		ret = min(ret, uu->time_periodic_next);
	} else if (uu->time_periodic) {
		uu->time_periodic_next = rnow + uu->time_periodic + 1;
		ret = min(ret, uu->time_periodic_next);
	}

	if (uu->time_inactivity_next) {
		ret = min(ret, uu->time_inactivity_next);
	} else if (uu->time_inactivity) {
		__u32 last_pkt = max(uu->ul_last_pkt, uu->dl_last_pkt);
		last_pkt = last_pkt ?: rnow;
		uu->time_inactivity_next = last_pkt + uu->time_inactivity + 1;
		ret = min(ret, uu->time_inactivity_next);
	}

	return ret != ~0 ? (__u64)(ret - rnow) << 24 : 0;
}

static __always_inline int
_urr_timer_tick(void *map, int *key, struct upf_urr *uu)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	__u16 trig = 0;

	if ((uu->flags & UPF_FL_MEAS_TIME)) {
		_urr_compute_duration(uu, rnow);

		if (uu->time_th) {
			__u32 elapsed = uu->duration - uu->duration_th_last;
			if (elapsed >= uu->time_th) {
				trig |= UPF_TRIG_FL_TIMTH;
				uu->duration_th_last = uu->duration;
			}
		}

		if (uu->time_qu) {
			__u32 elapsed = uu->duration - uu->duration_qu_last;
			if (elapsed >= uu->time_qu) {
				uu->flags |= UPF_FL_QUOTA_REACHED;
				trig |= UPF_TRIG_FL_TIMQU;
				uu->duration_qu_last = uu->duration;
			}
		}
	}

	if (uu->time_inactivity_next && rnow >= uu->time_inactivity_next) {
		__u32 last_pkt = max(uu->ul_last_pkt, uu->dl_last_pkt);
		if (!last_pkt || uu->time_inactivity <= rnow - last_pkt) {
			trig |= UPF_TRIG_FL_QUHTI;
			uu->time_inactivity_next = rnow + uu->time_inactivity + 1;
		} else {
			last_pkt = last_pkt ?: rnow;
			uu->time_inactivity_next = last_pkt + uu->time_inactivity + 1;
		}
	}

	if (uu->time_periodic_next && rnow >= uu->time_periodic_next) {
		trig |= UPF_TRIG_FL_PERIO;
		uu->time_periodic_next = 0;
	}

	/* send report if any */
	if (trig)
		_urr_send_report(uu, trig, 0);

	if (!(uu->flags & UPF_FL_QUOTA_REACHED)) {
		/* re-arm timer */
		__u64 next = _urr_compute_next_tick(uu, rnow);
		bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);
	}

	return 0;
}

static __always_inline void
_urr_measure_time(struct upf_urr *uu, __u32 *last_pkt, __u32 rnow)
{
	if (unlikely(!uu->report_first_pkt))
		uu->report_first_pkt = rnow;
	uu->report_last_pkt = rnow;

	if (!(uu->flags & UPF_FL_MEAS_TIME)) {
		*last_pkt = rnow;
		return;
	}

	/* count inactivity time (no packet since a looong time) */
	if (uu->inactivity_det_time && *last_pkt) {
		__u32 elapsed = rnow - *last_pkt;
		if (elapsed > uu->inactivity_det_time)
			uu->inactive_time += elapsed - uu->inactivity_det_time;
	}

	if (!uu->duration_ts_last) {
		uu->duration_ts_last = rnow;
		__u64 next = _urr_compute_next_tick(uu, rnow);
		if (next)
			bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);
	}
	*last_pkt = rnow;
}

static __always_inline void
upf_urr_check_dl(struct upf_urr *uu)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	__u16 trigg = 0;

#ifdef UPF_DEBUG
	if (uu->dl_th || uu->total_th)
		bpf_printk("%s: th{tot:%ld p:%ld} fwd:{tot:%ld dl:%ld}", __func__,
			   uu->total_th, uu->dl_th, uu->ul_bytes + uu->dl_bytes, uu->dl_bytes);
	if (uu->dl_qu || uu->total_qu)
		bpf_printk("%s: qu{tot:%ld p:%ld} fwd:{tot:%ld dl:%ld}", __func__,
			   uu->total_qu, uu->dl_qu, uu->ul_bytes + uu->dl_bytes, uu->dl_bytes);
#endif

	if ((uu->dl_th_next && uu->dl_bytes >= uu->dl_th_next) ||
	    (uu->total_th_next && uu->ul_bytes + uu->dl_bytes >= uu->total_th_next)) {
		trigg |= UPF_TRIG_FL_VOLTH;
		if (uu->total_th)
			uu->total_th_next = uu->total_th + uu->dl_bytes + uu->ul_bytes;
		if (uu->dl_th)
			uu->dl_th_next = uu->dl_th + uu->dl_bytes;
	}

	if ((uu->dl_qu_next && uu->dl_bytes >= uu->dl_qu_next) ||
	    (uu->total_qu_next && uu->ul_bytes + uu->dl_bytes >= uu->total_qu_next)) {
		trigg = UPF_TRIG_FL_VOLQU;
		uu->flags |= UPF_FL_QUOTA_REACHED;
	}

	_urr_measure_time(uu, &uu->dl_last_pkt, rnow);

	if (trigg) {
		if (uu->flags & UPF_FL_MEAS_TIME)
			_urr_compute_duration(uu, rnow);
		_urr_send_report(uu, trigg, 0);
	}
}

static __always_inline void
upf_urr_check_ul(struct upf_urr *uu)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	__u16 trigg = 0;

#ifdef UPF_DEBUG
	if (uu->ul_th || uu->total_th)
		bpf_printk("%s: th{tot:%ld p:%ld} fwd:{tot:%ld ul:%ld}", __func__,
			   uu->total_th, uu->ul_th, uu->ul_bytes + uu->dl_bytes, uu->ul_bytes);
	if (uu->ul_qu || uu->total_qu)
		bpf_printk("%s: qu{tot:%ld p:%ld} fwd:{tot:%ld ul:%ld}", __func__,
			   uu->total_qu, uu->ul_qu, uu->ul_bytes + uu->dl_bytes, uu->ul_bytes);
#endif

	if ((uu->ul_th_next && uu->ul_bytes >= uu->ul_th_next) ||
	    (uu->total_th_next && uu->dl_bytes + uu->ul_bytes >= uu->total_th_next)) {
		trigg |= UPF_TRIG_FL_VOLTH;
		if (uu->total_th)
			uu->total_th_next = uu->total_th + uu->dl_bytes + uu->ul_bytes;
		if (uu->ul_th)
			uu->ul_th_next = uu->ul_th + uu->ul_bytes;
	}

	if ((uu->ul_qu_next && uu->ul_bytes >= uu->ul_qu_next) ||
	    (uu->total_qu_next && uu->dl_bytes + uu->ul_bytes >= uu->total_qu_next)) {
		trigg = UPF_TRIG_FL_VOLQU;
		uu->flags |= UPF_FL_QUOTA_REACHED;
		if (uu->total_qu)
			uu->total_qu_next = uu->total_qu + uu->dl_bytes + uu->ul_bytes;
		if (uu->ul_qu)
			uu->ul_qu_next = uu->ul_qu + uu->ul_bytes;
	}

	_urr_measure_time(uu, &uu->ul_last_pkt, rnow);

	if (trigg) {
		if (uu->flags & UPF_FL_MEAS_TIME)
			_urr_compute_duration(uu, rnow);
		_urr_send_report(uu, trigg, 0);
	}
}


SEC("syscall")
int urr_ctl(struct upf_urr_cmd_req *c)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	struct upf_urr *uu;

	__u32 idx = c->urr_idx;
	uu = bpf_map_lookup_elem(&upf_urr, &idx);
	if (uu == NULL)
		return -1;

	if (uu->flags & UPF_FL_MEAS_TIME)
		_urr_compute_duration(uu, rnow);

	if (c->ctl_fl & (UPF_FL_CTL_INIT | UPF_FL_CTL_UPDATE)) {
		uu->flags = c->flags;
		uu->total_th = c->total_th;
		uu->total_qu = c->total_qu;
		uu->ul_th = c->ul_th;
		uu->ul_qu = c->ul_qu;
		uu->dl_th = c->dl_th;
		uu->dl_qu = c->dl_qu;
		uu->time_th = (((__u64)c->time_th * NSEC_PER_SEC) >> 24);
		uu->time_qu = (((__u64)c->time_qu * NSEC_PER_SEC) >> 24);
		uu->time_periodic = (((__u64)c->time_periodic * NSEC_PER_SEC) >> 24);
		uu->time_inactivity = (((__u64)c->time_inactivity * NSEC_PER_SEC) >> 24);
		uu->inactivity_det_time =
			(((__u64)c->inactivity_det_time * NSEC_PER_SEC) >> 24);
		uu->duration_ts_last =
			(uu->flags & UPF_FL_TIME_IMMEDIATE_METER) ? rnow : 0;
		uu->ul_last_pkt = 0;
		uu->dl_last_pkt = 0;
	}

	if (c->ctl_fl & UPF_FL_CTL_INIT) {
		uu->seid = c->seid;
		uu->urr_idx = c->urr_idx;

		/* Create URR: Reset all counters */
		uu->total_th_next = uu->total_th;
		uu->total_qu_next = uu->total_qu;
		uu->ul_drop_pkt = 0;
		uu->ul_pkt = 0;
		uu->ul_bytes = 0;
		uu->ul_th_next = uu->ul_th;
		uu->ul_qu_next = uu->ul_qu;
		uu->dl_drop_pkt = 0;
		uu->dl_pkt = 0;
		uu->dl_bytes = 0;
		uu->dl_th_next = uu->dl_th;
		uu->dl_qu_next = uu->dl_qu;
		uu->report_first_pkt = 0;
		uu->report_last_pkt = 0;
		uu->inactive_time = 0;
		uu->duration = 0;
		uu->duration_th_last = 0;
		uu->duration_qu_last = 0;
		uu->time_periodic_next = 0;
		uu->time_inactivity_next = 0;

		/* send ack */
		struct upf_urr_report ur = {
			.seid = c->seid,
			.urr_idx = c->urr_idx,
			.request_id = c->request_id,
		};
		bpf_ringbuf_output(&upf_events, &ur, sizeof(ur), 0);

		/* arm timer(s) */
		if (bpf_timer_init(&uu->timer, &upf_urr, CLOCK_MONOTONIC) != 0)
			return -1;
		bpf_timer_set_callback(&uu->timer, _urr_timer_tick);
		__u64 next = _urr_compute_next_tick(uu, rnow);
		if (next)
			bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);

	} else if (c->ctl_fl & UPF_FL_CTL_UPDATE) {
		/* Update URR: restart all triggers */
		uu->total_th_next = uu->total_th ?
			uu->total_th + uu->ul_bytes + uu->dl_bytes : 0;
		uu->total_qu_next = uu->total_qu ?
			uu->total_qu + uu->ul_bytes + uu->dl_bytes : 0;
		uu->ul_th_next = uu->ul_th ? uu->ul_th + uu->ul_bytes : 0;
		uu->ul_qu_next = uu->ul_qu ? uu->ul_qu + uu->ul_bytes : 0;
		uu->dl_th_next = uu->dl_th ? uu->dl_th + uu->dl_bytes : 0;
		uu->dl_qu_next = uu->dl_qu ? uu->dl_qu + uu->dl_bytes : 0;
		uu->duration_th_last = uu->duration;
		uu->duration_qu_last = uu->duration;
		uu->time_periodic_next = 0;
		uu->time_inactivity_next = 0;

		/* re-arm timer(s) */
		__u64 next = _urr_compute_next_tick(uu, rnow);
		if (next)
			bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);

		/* send report */
		_urr_send_report(uu, 0, c->request_id);

	} else if (c->ctl_fl & UPF_FL_CTL_DELETE) {
		/* Delete URR or Session: Report and stop timer */
		_urr_send_report(uu, 0, c->request_id);

		bpf_timer_cancel(&uu->timer);

	} else if (c->ctl_fl & UPF_FL_CTL_REPORT) {
		/* Only report */
		_urr_send_report(uu, 0, c->request_id);
	}

	return 0;
}
