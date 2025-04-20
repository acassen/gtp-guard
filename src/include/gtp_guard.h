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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _GTP_GUARD_H
#define _GTP_GUARD_H

#include <net/ethernet.h>
#include <resolv.h>

#include "daemon.h"
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "pidfile.h"
#include "signals.h"
#include "timer.h"
#include "timer_thread.h"
#include "scheduler.h"
#include "vector.h"
#include "command.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "list_head.h"
#include "json_reader.h"
#include "json_writer.h"
#include "pkt_buffer.h"
#include "asn1_encoder.h"
#include "jhash.h"
#include "gtp.h"
#include "gtp_msg.h"
#include "gtp_if.h"
#include "gtp_request.h"
#include "gtp_data.h"
#include "gtp_htab.h"
#include "gtp_teid.h"
#include "gtp_iptnl.h"
#include "gtp_conn.h"
#include "gtp_stats.h"
#include "gtp_server.h"
#include "gtp_pppoe.h"
#include "gtp_pppoe_session.h"
#include "gtp_pppoe_proto.h"
#include "gtp_pppoe_monitor.h"
#include "gtp_pppoe_vty.h"
#include "gtp_ppp.h"
#include "gtp_ppp_session.h"
#include "gtp_disk.h"
#include "gtp_cdr.h"
#include "gtp_cdr_asn1.h"
#include "gtp_cdr_file.h"
#include "gtp_cdr_spool.h"
#include "gtp_cdr_vty.h"
#include "gtp_vrf.h"
#include "gtp_apn.h"
#include "gtp_session.h"
#include "gtp_dpd.h"
#include "gtp_resolv.h"
#include "gtp_sched.h"
#include "gtp_proxy.h"
#include "gtp_proxy_hdl.h"
#include "gtp_proxy_hdl_v1.h"
#include "gtp_proxy_hdl_v2.h"
#include "gtp_router.h"
#include "gtp_router_hdl.h"
#include "gtp_sqn.h"
#include "gtp_utils.h"
#include "gtp_utils_uli.h"
#include "gtp_disk.h"
#include "gtp_vty.h"
#include "gtp_cmd.h"

#ifndef _WITHOUT_BPF_
 #include "gtp_bpf_utils.h"
 #include "gtp_bpf.h"
 #include "gtp_bpf_ppp.h"
 #include "gtp_bpf_iptnl.h"
 #include "gtp_bpf_fwd.h"
 #include "gtp_bpf_mirror.h"
 #include "gtp_bpf_rt.h"
#endif

#endif
