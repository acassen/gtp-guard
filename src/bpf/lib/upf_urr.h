/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once



struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} upf_events SEC(".maps");


static __always_inline void
_urr_save_quota(struct upf_urr *u, struct upf_urr_data *uc)
{
	/* remember used quota */
	if (u->vol_quota_ul || u->vol_quota_dl || u->vol_quota_to) {
		uc->vol_quota_ul_used += uc->fwd_bytes_ul;
		uc->vol_quota_dl_used += uc->fwd_bytes_dl;
	}
	if (u->time_quota && uc->fwd_pkt_first) {
		uc->time_quota_used += bpf_ktime_get_ns() - uc->fwd_pkt_first;
	}
}

static __always_inline void
_urr_reset(struct upf_urr_data *uud)
{
	uud->report_flags = 0;
	uud->fwd_pkt_ul = 0;
	uud->fwd_bytes_ul = 0;
	uud->drop_pkt_ul = 0;
	uud->fwd_pkt_dl = 0;
	uud->fwd_bytes_dl = 0;
	uud->drop_pkt_dl = 0;
	uud->fwd_pkt_first = 0;
	uud->fwd_pkt_last = 0;
	uud->inactive_time = 0;
}

static __always_inline void
_urr_send_report(struct upf_urr *u, struct upf_urr_data *uc)
{
	_urr_save_quota(u, uc);

	bpf_printk("sending ringbuf event for vol thr/quota");
	bpf_ringbuf_output(&upf_events, uc, sizeof(*uc), 0);

	_urr_reset(uc);

}

static __always_inline __u64
_urr_compute_next_tick(struct upf_urr *u, struct upf_urr_data *uc, __u64 now)
{
	__u64 ret = ~0;

	if (u->time_threshold && uc->fwd_pkt_first) {
		__u64 timeth_next = uc->fwd_pkt_first +
			u->time_threshold * NSEC_PER_SEC;
		ret = min(ret, timeth_next);
	}

	if (u->time_quota && uc->fwd_pkt_first) {
		__u64 timequ_next = uc->fwd_pkt_first +
			u->time_quota * NSEC_PER_SEC;
		ret = min(ret, timequ_next);
	}

	/* periodic timer */
	if (u->time_periodic) {
		if (!uc->time_periodic_next)
			uc->time_periodic_next = now +
				u->time_periodic * NSEC_PER_SEC;
		ret = min(ret, uc->time_periodic_next);
	}

	/* inactivity timer (quota holding time) */
	if (u->time_inactivity) {
		if (!uc->time_inactivity_next)
			uc->time_inactivity_next = now +
				u->time_inactivity * NSEC_PER_SEC;
		ret = min(ret, uc->time_inactivity_next);
	}

	return ret == ~0 ? 0 : ret - now;
}

static __always_inline int
_urr_timer_tick(void *map, int *key, struct upf_urr *uu)
{
	struct upf_urr_data *uud;
	__u64 now = bpf_ktime_get_ns();

	uud = bpf_map_lookup_elem(&upf_urr_data, &uu->urr_idx);
	if (uud == NULL)
		return 0;

	/* check timers */
	if (uud->fwd_pkt_first) {
		if (uu->time_threshold) {
			__u64 timeth_next = uud->fwd_pkt_first +
				uu->time_threshold * NSEC_PER_SEC;
			if (timeth_next < now)
				uud->report_flags = UPF_TRIG_FL_TIMTH;
		}
		if (uu->time_quota) {
			__u64 timequ_next = uud->fwd_pkt_first +
				uu->time_quota * NSEC_PER_SEC;
			if (timequ_next < now) {
				uud->report_flags = UPF_TRIG_FL_TIMQU;
				uud->quota_reached = 1;
			}
		}
	}

	if (uud->time_inactivity_next && uud->time_inactivity_next < now) {
		uud->report_flags = UPF_TRIG_FL_QUHTI;
		uud->time_inactivity_next = ~0;
	}

	if (uud->time_periodic_next && uud->time_periodic_next < now) {
		uud->report_flags = UPF_TRIG_FL_PERIO;
		uud->time_periodic_next += uu->time_periodic * NSEC_PER_SEC;
	}

	/* send report if any */
	if (uud->report_flags)
		_urr_send_report(uu, uud);

	if (!uud->quota_reached) {
		/* re-arm timer */
		__u64 next = _urr_compute_next_tick(uu, uud, now);
		bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);
	}

	return 0;
}

static __always_inline void
_check_urr_ul(struct upf_urr *u, struct upf_urr_data *uc)
{
	bpf_printk("%s: %ld < %ld", __func__, u->vol_quota_to,
		   uc->fwd_bytes_ul);
	if ((u->vol_thres_ul && uc->fwd_bytes_ul >= u->vol_thres_ul) ||
	    (u->vol_thres_to && uc->fwd_bytes_dl + uc->fwd_bytes_ul >=
	     u->vol_thres_to)) {
		uc->report_flags = UPF_TRIG_FL_VOLTH;
	}

	if ((u->vol_quota_ul && uc->fwd_bytes_ul >=
	     u->vol_quota_ul - uc->vol_quota_ul_used) ||
	    (u->vol_quota_to && uc->fwd_bytes_dl + uc->fwd_bytes_ul >=
	     u->vol_quota_to - uc->vol_quota_ul_used + uc->vol_quota_dl_used)) {
		uc->vol_quota_ul_used += uc->fwd_bytes_ul;

		uc->vol_quota_dl_used += uc->fwd_bytes_dl;
		uc->report_flags |= UPF_TRIG_FL_VOLQU;
		uc->quota_reached = 1;
	}

	if (uc->report_flags)
		_urr_send_report(u, uc);
}

static __always_inline void
_check_urr_dl(struct upf_urr *u, struct upf_urr_data *uc)
{
	bpf_printk("%s: %ld < %ld", __func__, u->vol_quota_to,
		   uc->fwd_bytes_dl);
	if ((u->vol_thres_dl && uc->fwd_bytes_dl >= u->vol_thres_dl) ||
	    (u->vol_thres_to && uc->fwd_bytes_dl + uc->fwd_bytes_ul >=
	     u->vol_thres_to)) {
		uc->report_flags = UPF_TRIG_FL_VOLTH;
	}

	if ((u->vol_quota_dl && uc->fwd_bytes_dl >=
	     u->vol_quota_dl - uc->vol_quota_dl_used) ||
	    (u->vol_quota_to && uc->fwd_bytes_dl + uc->fwd_bytes_ul
	     >= u->vol_quota_to - uc->vol_quota_ul_used + uc->vol_quota_dl_used)) {
		uc->vol_quota_ul_used += uc->fwd_bytes_ul;
		uc->vol_quota_dl_used += uc->fwd_bytes_dl;
		uc->report_flags |= UPF_TRIG_FL_VOLQU;
		uc->quota_reached = 1;
	}

	if (uc->report_flags)
		_urr_send_report(u, uc);
}

static __always_inline void
_update_urr_inactivity_time(struct upf_urr *uu, struct upf_urr_data *uud)
{
	if (!(uu->flags & UPF_FL_MEAS_DUR))
		return;

	__u64 now = bpf_ktime_get_ns();
	__u64 pkt_last_ns = uud->fwd_pkt_last;
	if (uu->inactivity_det_time && pkt_last_ns) {
		__u64 elapsed = now - pkt_last_ns;
		__u64 inactive_time = (__u64)uu->inactivity_det_time * NSEC_PER_SEC;
		if (elapsed > inactive_time)
			uud->inactive_time += elapsed - inactive_time;
	}
	if (!uud->fwd_pkt_first) {
		uud->fwd_pkt_first = now;
		__u64 next = _urr_compute_next_tick(uu, uud, now);
		bpf_printk("got first packet: next: %ld", next);
		if (next)
			bpf_timer_start(&uu->timer, next, BPF_F_TIMER_CPU_PIN);
	}
	uud->fwd_pkt_last = now;
}



SEC("syscall")
int urr_ctl_init(struct urr_ctl_init_ctx *ctx)
{
	struct upf_urr_data *uud;
	struct upf_urr *uu;
	__u64 now = bpf_ktime_get_ns();

	__u32 idx = ctx->index;
	uu = bpf_map_lookup_elem(&upf_urr, &idx);
	uud = bpf_map_lookup_elem(&upf_urr_data, &idx);
	if (uu == NULL || uud == NULL)
		return -1;

	/* reset urr data */
	__builtin_memset(uud, 0x00, sizeof (*uud));
	uud->seid = ctx->seid;
	uud->urr_id = ctx->urr_id;

	/* write urr (avoid separate map update) */
	uu->urr_idx = idx;
	uu->cur_ver = 1;
	uu->inactivity_det_time = ctx->uu.inactivity_det_time;
	uu->time_threshold = ctx->uu.time_threshold;
	uu->time_quota = ctx->uu.time_quota;
	uu->time_periodic = ctx->uu.time_periodic;
	uu->vol_thres_to = ctx->uu.vol_thres_to;
	uu->vol_thres_dl = ctx->uu.vol_thres_dl;
	uu->vol_thres_ul = ctx->uu.vol_thres_ul;
	uu->vol_quota_to = ctx->uu.vol_quota_to;
	uu->vol_quota_dl = ctx->uu.vol_quota_dl;
	uu->vol_quota_ul = ctx->uu.vol_quota_ul;

	/* arm timer */
	if (bpf_timer_init(&uu->timer, &upf_urr, CLOCK_MONOTONIC) != 0)
		return -1;
	bpf_timer_set_callback(&uu->timer, _urr_timer_tick);
	__u64 next = _urr_compute_next_tick(uu, uud, now);
	bpf_printk("SET time threshold: %d, next: %d", uu->time_threshold,
		   next);
	if (next)
		bpf_timer_start(&uu->timer, next, 0);

	return 0;
}

SEC("syscall")
int urr_ctl_report(struct urr_ctl_report_ctx *ctx)
{
	struct upf_urr_data *uud;
	struct upf_urr *uu;

	__u32 idx = ctx->index;
	uu = bpf_map_lookup_elem(&upf_urr, &idx);
	uud = bpf_map_lookup_elem(&upf_urr_data, &idx);
	if (uu == NULL || uud == NULL)
		return -1;

	switch (ctx->action) {
	case 1:
		_urr_save_quota(uu, uud);
		ctx->uud = *uud;
		_urr_reset(uud);
		break;

	case 2:
		ctx->uud = *uud;
		bpf_timer_cancel(&uu->timer);
		break;
	}

	return 0;
}
