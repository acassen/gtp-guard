/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once



struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} upf_events SEC(".maps");


static __always_inline void
_urr_send_report(struct upf_urr *uu, __u16 trigger_fl, __u16 request_id)
{
	struct upf_urr_report_data ur;

	bpf_printk("%s: send report from BPF, trigger flags: 0x%x, dl:%ld ul:%ld",
		   __func__, trigger_fl, uu->dl.bytes, uu->ul.bytes);

	/* sends interesting values through ringbuf */
	ur.r.seid = uu->seid;
	ur.r.urr_idx = uu->urr_idx;
	ur.r.report_flags = trigger_fl;
	ur.r.request_id = request_id;
	ur.dl_bytes = uu->dl.bytes;
	ur.dl_pkt = uu->dl.pkt;
	ur.dl_drop_pkt = uu->dl.drop_pkt;
	ur.ul_bytes = uu->ul.bytes;
	ur.ul_pkt = uu->ul.pkt;
	ur.ul_drop_pkt = uu->ul.drop_pkt;
	ur.fwd_pkt_first = uu->fwd_pkt_first / NSEC_PER_SEC;
	ur.fwd_pkt_last = uu->fwd_pkt_last / NSEC_PER_SEC;
	bpf_ringbuf_output(&upf_events, &ur, sizeof(ur), 0);

	/* reset threshold volume triggers (but not quota volume trig) */
	if (uu->total_th)
		uu->total_th_next = uu->total_th + uu->ul.bytes + uu->dl.bytes;
	if (uu->ul.th)
		uu->ul.th_next = uu->ul.th + uu->ul.bytes;
	if (uu->dl.th)
		uu->dl.th_next = uu->dl.th + uu->dl.bytes;

	/* reset time threshold */
	uu->fwd_pkt_first = 0;
	uu->fwd_pkt_last = 0;
	uu->time_th_next = 0;

#if 0
	/* restart timth only if start_time_now */
	if (uu->time_th_next)
		uu->time_th_next = uu->fwd_pkt_first + uu->time_th * NSEC_PER_SEC;
#endif
}

/* return 'timeout' in ns, when next timer should trigger */
static __always_inline __u64
_urr_compute_next_tick(struct upf_urr *uu, __u64 now)
{
	__u64 ret = ~0;

	if (uu->time_th_next)
		ret = uu->time_th_next;
	else if (uu->time_th && uu->fwd_pkt_first) {
		uu->time_th_next = now + uu->time_th * NSEC_PER_SEC;
		ret = uu->time_th_next;
	}

	if (uu->time_qu_next)
		ret = min(ret, uu->time_qu_next);
	else if (uu->time_qu && uu->fwd_pkt_first) {
		uu->time_qu_next = now + uu->time_qu * NSEC_PER_SEC;
		ret = uu->time_qu_next;
	}

	/* periodic timer */
	if (uu->time_periodic_next)
		ret = min(ret, uu->time_periodic_next);

	/* inactivity timer (quota holding time) */
	if (uu->time_inactivity) {
		if (!uu->time_inactivity_next)
			uu->time_inactivity_next = now +
				uu->time_inactivity * NSEC_PER_SEC;
		ret = min(ret, uu->time_inactivity_next);
	}

	return ret == ~0 ? 0 : ret - now;
}

static __always_inline int
_urr_timer_tick(void *map, int *key, struct upf_urr *uu)
{
	__u64 now = bpf_ktime_get_ns();
	__u16 trig = 0;

	/* check timers */
	if (uu->time_th_next && now > uu->time_th_next)
		trig |= UPF_TRIG_FL_TIMTH;

	if (uu->time_qu_next && now > uu->time_qu_next) {
		trig |= UPF_TRIG_FL_TIMQU;
		uu->flags |= UPF_FL_QUOTA_REACHED;
	}

	if (uu->time_inactivity_next && now > uu->time_inactivity_next) {
		trig |= UPF_TRIG_FL_QUHTI;
		uu->time_inactivity_next = ~0;
	}

	if (uu->time_periodic_next && now > uu->time_periodic_next) {
		trig |= UPF_TRIG_FL_PERIO;
		uu->time_periodic_next += uu->time_periodic * NSEC_PER_SEC;
	}

	/* send report if any */
	if (trig)
		_urr_send_report(uu, trig, 0);

	if (!(uu->flags & UPF_FL_QUOTA_REACHED)) {
		/* re-arm timer */
		__u64 next = _urr_compute_next_tick(uu, now);
		bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);
	}

	return 0;
}

static __always_inline void
_urr_check_volume(struct upf_urr *uu, struct upf_uur_vol_path *uup)
{
	__u16 trigg = 0;

	if (uup->th || uu->total_th)
		bpf_printk("%s: th{tot:%ld p:%ld} fwd:{tot:%ld p:%ld}", __func__,
			   uu->total_th, uup->th, uu->ul.bytes + uu->dl.bytes, uup->bytes);
	if (uup->qu || uu->total_qu)
		bpf_printk("%s: qu{tot:%ld p:%ld} fwd:{tot:%ld p:%ld}", __func__,
			   uu->total_qu, uup->qu, uu->ul.bytes + uu->dl.bytes, uup->bytes);

	if ((uup->th_next && uup->bytes >= uup->th_next) ||
	    (uu->total_th_next && uu->ul.bytes + uu->dl.bytes >= uu->total_th_next)) {
		trigg |= UPF_TRIG_FL_VOLTH;
	}

	if ((uup->qu_next && uup->bytes >= uup->qu_next) ||
	    (uu->total_qu_next && uu->ul.bytes + uu->dl.bytes >= uu->total_qu_next)) {
		trigg = UPF_TRIG_FL_VOLQU;
		uu->flags |= UPF_FL_QUOTA_REACHED;
	}

	if (trigg)
		_urr_send_report(uu, trigg, 0);
}

static __always_inline void
_urr_timer_on_pkt(struct upf_urr *uu)
{
	if (!(uu->flags & UPF_FL_MEAS_DUR))
		return;

	__u64 now = bpf_ktime_get_ns();
	__u64 pkt_last_ns = uu->fwd_pkt_last;
	if (uu->inactivity_det_time && pkt_last_ns) {
		__u64 elapsed = now - pkt_last_ns;
		__u64 inactive_time = (__u64)uu->inactivity_det_time * NSEC_PER_SEC;
		if (elapsed > inactive_time)
			uu->inactive_time += elapsed - inactive_time;
	}
	if (!uu->fwd_pkt_first) {
		uu->fwd_pkt_first = now;
		__u64 next = _urr_compute_next_tick(uu, now);
		bpf_printk("got first packet: next: %ld", next);
		if (next)
			bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);
	}
	uu->fwd_pkt_last = now;
}


SEC("syscall")
int urr_ctl(struct upf_urr_cmd_req *c)
{
	struct upf_urr *uu;
	__u64 now = bpf_ktime_get_ns();

	__u32 idx = c->urr_idx;
	uu = bpf_map_lookup_elem(&upf_urr, &idx);
	if (uu == NULL)
		return -1;

	if (c->ctl_fl & UPF_FL_CTL_UPDATE) {
		uu->urr_idx = c->urr_idx;
		uu->flags = c->flags;
		uu->cur_ver = c->cur_ver;
		uu->time_th = c->time_th;
		uu->time_qu = c->time_qu;
		uu->time_periodic = c->time_periodic;
		uu->time_inactivity = c->time_inactivity;
		uu->inactivity_det_time = c->inactivity_det_time;
		uu->total_th = c->total_th;
		uu->total_qu = c->total_qu;
		uu->ul.th = c->ul_th;
		uu->ul.qu = c->ul_qu;
		uu->dl.th = c->dl_th;
		uu->dl.qu = c->dl_qu;
	}

	if (c->ctl_fl & UPF_FL_CTL_REPORT) {
		_urr_send_report(uu, 0, c->request_id);

	} else if (c->ctl_fl & UPF_FL_CTL_INIT) {
		uu->seid = c->seid;

		/* reset all counters */
		uu->total_th_next = uu->total_th;
		uu->total_qu_next = uu->total_qu;
		uu->ul.drop_pkt = 0;
		uu->ul.pkt = 0;
		uu->ul.bytes = 0;
		uu->ul.th_next = uu->ul.th;
		uu->ul.qu_next = uu->ul.qu;
		uu->dl.drop_pkt = 0;
		uu->dl.pkt = 0;
		uu->dl.bytes = 0;
		uu->dl.th_next = uu->dl.th;
		uu->dl.qu_next = uu->dl.qu;
		uu->fwd_pkt_first = 0;
		uu->fwd_pkt_last = 0;
		uu->time_th_next = 0;
		uu->time_qu_next = 0;
		uu->inactive_time = 0;
		uu->time_periodic_next = 0;
		uu->time_inactivity_next = 0;

		/* arm timer */
		if (uu->time_periodic)
			uu->time_periodic_next = now +
				uu->time_periodic * NSEC_PER_SEC;
		if (bpf_timer_init(&uu->timer, &upf_urr, CLOCK_MONOTONIC) != 0)
			return -1;
		bpf_timer_set_callback(&uu->timer, _urr_timer_tick);
		__u64 next = _urr_compute_next_tick(uu, now);
		if (next)
			bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);
	}

	if (c->ctl_fl & UPF_FL_CTL_DELETE)
		bpf_timer_cancel(&uu->timer);

	/* ack command */
	if (!(c->ctl_fl & UPF_FL_CTL_REPORT)) {
		struct upf_urr_report ur = {
			.seid = c->seid,
			.urr_idx = c->urr_idx,
			.request_id = c->request_id,
		};
		bpf_ringbuf_output(&upf_events, &ur, sizeof(ur), 0);
	}

	return 0;
}
