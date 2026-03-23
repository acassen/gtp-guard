#!/usr/bin/env python3
"""
smf_pfcp.py — Async SMF / N4 interface simulator  (3GPP TS 29.244 Release 15)
Requires Python 3.13+.

Commands (stdin):
  urr set id <n> [triggers <t,...>] [measure <m,...>]
                 [volth total <bytes>] [volth ul <bytes>] [volth dl <bytes>]
                 [timth <seconds>]
  urr show [<id>]
  urr clear [<id>]

  session add [imsi <d>] [msisdn <d>] [imei <d>]
              [dnn <n>] [pool <n>]
              [enb-ip <ip>] [enb-teid <teid>]
              [urr <id1,id2,...>]
  session delete <cp_seid>
  session ping   <cp_seid> [<dst_ip>] [count <n>]
  sessions

  expect report [timeout <s>] [cp_seid <n>] [urr_id <n>]
                [trigger <name,...>]
                [total <b>] [total_min <b>] [total_max <b>]
                [ul <b>]    [ul_min <b>]    [ul_max <b>]
                [dl <b>]    [dl_min <b>]    [dl_max <b>]

  pause <seconds>
  help / quit / exit

  Byte suffixes: GB MiB MB KiB KB (or plain integer).
  Trigger names: perio volth timth quhti start stopt droth liusa
                 termr monit envcl timqu volqu
  Measure names: volume duration event

Usage:
  python smf_pfcp.py --smf-ip 10.0.0.1 --upf-ip 10.0.0.2
  python smf_pfcp.py --smf-ip 10.0.0.1 --upf-ip 10.0.0.2 --hb-interval 10
  python smf_pfcp.py --smf-ip 10.0.0.1 --upf-ip 10.0.0.2 --gtpu-ip 192.168.1.1
"""

import argparse
import asyncio
import logging
import random
import shlex
import socket
import struct
import sys
import time
from dataclasses import dataclass, field

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

PFCP_PORT = 8805
GTPU_PORT = 2152
NTP_DELTA = 2_208_988_800


# ══════════════════════════════════════════════════════════════════════════
#  Message types  (TS 29.244 §7.2)
# ══════════════════════════════════════════════════════════════════════════
class MT:
    HB_REQ        = 1
    HB_RESP       = 2
    ASSOC_REQ     = 5
    ASSOC_RSP     = 6
    SESS_EST_REQ  = 50
    SESS_EST_RSP  = 51
    SESS_DEL_REQ  = 54
    SESS_DEL_RSP  = 55
    SESS_RPT_REQ  = 56
    SESS_RPT_RSP  = 57

MSG_NAME = {
    MT.HB_REQ:       "Heartbeat Request",
    MT.HB_RESP:      "Heartbeat Response",
    MT.ASSOC_REQ:    "Association Setup Request",
    MT.ASSOC_RSP:    "Association Setup Response",
    MT.SESS_EST_REQ: "Session Establishment Request",
    MT.SESS_EST_RSP: "Session Establishment Response",
    MT.SESS_DEL_REQ: "Session Deletion Request",
    MT.SESS_DEL_RSP: "Session Deletion Response",
    MT.SESS_RPT_REQ: "Session Report Request",
    MT.SESS_RPT_RSP: "Session Report Response",
}


# ══════════════════════════════════════════════════════════════════════════
#  IE types  (TS 29.244 Table 8.1-1)
# ══════════════════════════════════════════════════════════════════════════
class IET:
    CREATE_PDR                     = 1
    PDI                            = 2
    CREATE_FAR                     = 3
    FORWARDING_PARAMS              = 4
    CREATE_URR                     = 6
    CREATED_PDR                    = 8
    CAUSE                          = 19
    SOURCE_INTERFACE               = 20
    FTEID                          = 21
    NETWORK_INSTANCE               = 22
    REPORT_TYPE                    = 39
    PRECEDENCE                     = 29
    VOLUME_MEASUREMENT             = 66
    VOLUME_THRESHOLD               = 31
    TIME_THRESHOLD                 = 32
    MONITORING_TIME                = 33
    REPORTING_TRIGGERS             = 37
    DEST_INTERFACE                 = 42
    UP_FUNC_FEATURES               = 43
    APPLY_ACTION                   = 44
    DURATION_MEASUREMENT           = 67
    INACTIVITY_DETECTION_TIME      = 36
    MEASUREMENT_PERIOD             = 64
    TIME_QUOTA                     = 74
    QUOTA_HOLDING_TIME             = 71
    VOLUME_QUOTA                   = 73
    FSEID                          = 57
    PDR_ID                         = 56
    NODE_ID                        = 60
    MEASUREMENT_METHOD             = 62
    USAGE_REPORT_TRIGGER           = 63
    UR_SEQN                        = 104
    START_TIME                     = 75
    END_TIME                       = 76
    URR_ID                         = 81
    USAGE_REPORT_SRR               = 80
    OUTER_HEADER_CREATION          = 84
    CP_FUNC_FEATURES               = 89
    UE_IP_ADDRESS                  = 93
    RECOVERY_TIMESTAMP             = 96
    FAR_ID                         = 108
    USER_ID                        = 141
    APN_DNN                        = 159
    UE_IP_ADDRESS_POOL_IDENTITY    = 177
    UE_IP_ADDRESS_POOL_INFORMATION = 233


# ── Apply Action
AA_DROP    = 0x01
AA_FORW    = 0x02

# ── Measurement Method
MM_DURAT   = 0x01
MM_VOLUM   = 0x02
MM_EVENT   = 0x04

# ── §8.2.19 Reporting Triggers (used in Create/Modify URR)
#    2-byte big-endian; octet 5 = high byte, octet 6 = low byte
RT_PERIO   = 0x0100   # octet 5, bit 1 — Periodic Reporting
RT_VOLTH   = 0x0200   # octet 5, bit 2 — Volume Threshold
RT_TIMTH   = 0x0400   # octet 5, bit 3 — Time Threshold
RT_QUHTI   = 0x0800   # octet 5, bit 4 — Quota Holding Time
RT_START   = 0x1000   # octet 5, bit 5 — Start of Traffic
RT_STOPT   = 0x2000   # octet 5, bit 6 — Stop of Traffic
RT_DROTH   = 0x4000   # octet 5, bit 7 — Dropped DL Traffic Threshold
RT_LIUSA   = 0x8000   # octet 5, bit 8 — Linked Usage Reporting
RT_VOLQU   = 0x0001   # octet 6, bit 1 — Volume Quota
RT_TIMQU   = 0x0002   # octet 6, bit 2 — Time Quota
RT_ENVCL   = 0x0004   # octet 6, bit 3 — Envelope Closure
RT_MACAR   = 0x0008   # octet 6, bit 4 — MAC Addresses Reporting
RT_EVETH   = 0x0010   # octet 6, bit 5 — Event Threshold
RT_EVEQU   = 0x0020   # octet 6, bit 6 — Event Quota
RT_IPMJL   = 0x0040   # octet 6, bit 7 — IP Multicast Join/Leave

REPORTING_TRIGGER_NAMES: dict[str, int] = {
    "perio": RT_PERIO, "volth": RT_VOLTH, "timth": RT_TIMTH,
    "quhti": RT_QUHTI, "start": RT_START, "stopt": RT_STOPT,
    "droth": RT_DROTH, "liusa": RT_LIUSA, "volqu": RT_VOLQU,
    "timqu": RT_TIMQU, "envcl": RT_ENVCL, "macar": RT_MACAR,
    "eveth": RT_EVETH, "evequ": RT_EVEQU, "ipmjl": RT_IPMJL,
}
REPORTING_TRIGGER_NAMES_INV = {v: k.upper() for k, v in REPORTING_TRIGGER_NAMES.items()}

# ── §8.2.41 Usage Report Trigger (received in Session Report Request)
#    2-byte big-endian; octet 5 = high byte, octet 6 = low byte
URT_PERIO  = 0x0100   # octet 5, bit 1 — Periodic Reporting
URT_VOLTH  = 0x0200   # octet 5, bit 2 — Volume Threshold
URT_TIMTH  = 0x0400   # octet 5, bit 3 — Time Threshold
URT_QUHTI  = 0x0800   # octet 5, bit 4 — Quota Holding Time
URT_START  = 0x1000   # octet 5, bit 5 — Start of Traffic
URT_STOPT  = 0x2000   # octet 5, bit 6 — Stop of Traffic
URT_DROTH  = 0x4000   # octet 5, bit 7 — Dropped DL Traffic Threshold
URT_IMMER  = 0x8000   # octet 5, bit 8 — Immediate Report
URT_VOLQU  = 0x0001   # octet 6, bit 1 — Volume Quota exhausted
URT_TIMQU  = 0x0002   # octet 6, bit 2 — Time Quota exhausted
URT_LIUSA  = 0x0004   # octet 6, bit 3 — Linked Usage Reporting
URT_TERMR  = 0x0008   # octet 6, bit 4 — Termination Report
URT_MONIT  = 0x0010   # octet 6, bit 5 — Monitoring Time
URT_ENVCL  = 0x0020   # octet 6, bit 6 — Envelope Closure
URT_MACAR  = 0x0040   # octet 6, bit 7 — MAC Addresses Reporting
URT_EVETH  = 0x0080   # octet 6, bit 8 — Event Threshold

USAGE_REPORT_TRIGGER_NAMES: dict[str, int] = {
    "perio": URT_PERIO, "volth": URT_VOLTH, "timth": URT_TIMTH,
    "quhti": URT_QUHTI, "start": URT_START, "stopt": URT_STOPT,
    "droth": URT_DROTH, "immer": URT_IMMER, "volqu": URT_VOLQU,
    "timqu": URT_TIMQU, "liusa": URT_LIUSA, "termr": URT_TERMR,
    "monit": URT_MONIT, "envcl": URT_ENVCL, "macar": URT_MACAR,
    "eveth": URT_EVETH,
}
USAGE_REPORT_TRIGGER_NAMES_INV = {v: k.upper() for k, v in USAGE_REPORT_TRIGGER_NAMES.items()}

MEASURE_NAMES: dict[str, int] = {
    "duration": MM_DURAT, "volume": MM_VOLUM, "event": MM_EVENT,
}
MEASURE_NAMES_INV = {v: k.upper() for k, v in MEASURE_NAMES.items()}
VT_TOVOL   = 0x01
VT_ULVOL   = 0x02
VT_DLVOL   = 0x04

# ── Report Type
RPT_USAR   = 0x02
RPT_UPIR   = 0x01

# ── Interfaces
IF_ACCESS  = 0
IF_CORE    = 1

# ── UE IP Address  (§8.2.62)  bit1=V6, bit2=V4, bit3=SD, bit5=CHV4
UEIP_V6    = 0x01
UEIP_V4    = 0x02
UEIP_SD    = 0x04
UEIP_CHV4  = 0x10

# ── F-TEID  (§8.2.3)  bit1=V4, bit2=V6, bit3=CH
FTEID_V4   = 0x01
FTEID_V6   = 0x02
FTEID_CH   = 0x04

# ── F-SEID  (§8.2.82)  bit2=V4
FSEID_V4   = 0x02

# ── Outer Header Creation
OHC_GTP_U_UDP_IPV4 = 0x0100

# ── User ID
USERID_IMSI   = 0x01
USERID_IMEI   = 0x02
USERID_MSISDN = 0x04

CAUSE_ACCEPTED = 1
CAUSE_NAME     = {CAUSE_ACCEPTED: "Request Accepted"}

# ── GTP-U
GTPU_FLAGS    = 0x30
GTPU_GPDU     = 0xFF
IP_PROTO_ICMP = 1
ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0


# ══════════════════════════════════════════════════════════════════════════
#  Dataclasses
# ══════════════════════════════════════════════════════════════════════════
@dataclass
class URRConfig:
    urr_id:                  int
    triggers:                int       = 0
    measure:                 int       = 0
    volth_total:             int | None = None
    volth_ul:                int | None = None
    volth_dl:                int | None = None
    timth:                   int | None = None   # seconds
    # Quota
    vol_quota_total:         int | None = None
    vol_quota_ul:            int | None = None
    vol_quota_dl:            int | None = None
    time_quota:              int | None = None   # seconds
    quota_holding_time:      int | None = None   # seconds
    inactivity_detection:    int | None = None   # seconds
    measurement_period:      int | None = None   # seconds (periodic timer)

    def summary(self) -> str:
        trig_names = ",".join(n for f, n in REPORTING_TRIGGER_NAMES_INV.items() if self.triggers & f) or "none"
        meas_names = ",".join(n for f, n in MEASURE_NAMES_INV.items() if self.measure  & f) or "none"
        parts = [f"id={self.urr_id}", f"triggers={trig_names}", f"measure={meas_names}"]
        if self.volth_total          is not None: parts.append(f"volth_total={fmt_bytes(self.volth_total)}")
        if self.volth_ul             is not None: parts.append(f"volth_ul={fmt_bytes(self.volth_ul)}")
        if self.volth_dl             is not None: parts.append(f"volth_dl={fmt_bytes(self.volth_dl)}")
        if self.timth                is not None: parts.append(f"timth={self.timth}s")
        if self.vol_quota_total      is not None: parts.append(f"vol_quota_total={fmt_bytes(self.vol_quota_total)}")
        if self.vol_quota_ul         is not None: parts.append(f"vol_quota_ul={fmt_bytes(self.vol_quota_ul)}")
        if self.vol_quota_dl         is not None: parts.append(f"vol_quota_dl={fmt_bytes(self.vol_quota_dl)}")
        if self.time_quota           is not None: parts.append(f"time_quota={self.time_quota}s")
        if self.quota_holding_time   is not None: parts.append(f"quota_holding={self.quota_holding_time}s")
        if self.inactivity_detection is not None: parts.append(f"inactivity={self.inactivity_detection}s")
        if self.measurement_period   is not None: parts.append(f"period={self.measurement_period}s")
        return "  ".join(parts)


@dataclass
class UsageReport:
    urr_id:    int  = 0
    seqn:      int  = 0
    trigger:   int  = 0
    total:     int | None = None
    ul:        int | None = None
    dl:        int | None = None
    duration:  int | None = None
    start:     str  = ""
    end:       str  = ""

    def summary(self) -> str:
        trig_names = ",".join(n for f, n in USAGE_REPORT_TRIGGER_NAMES_INV.items() if self.trigger & f) or "?"
        parts = [f"urr_id={self.urr_id}", f"seqn={self.seqn}",
                 f"trigger=0x{self.trigger:04X}({trig_names})"]
        if self.total    is not None: parts.append(f"total={fmt_bytes(self.total)}")
        if self.ul       is not None: parts.append(f"ul={fmt_bytes(self.ul)}")
        if self.dl       is not None: parts.append(f"dl={fmt_bytes(self.dl)}")
        if self.duration is not None: parts.append(f"duration={self.duration}s")
        if self.start:                parts.append(f"start={self.start}")
        if self.end:                  parts.append(f"end={self.end}")
        return "  ".join(parts)


@dataclass
class SessionReport:
    cp_seid:      int
    report_type:  int
    usage_reports: list[UsageReport] = field(default_factory=list)


@dataclass
class Session:
    cp_seid:     int
    up_seid:     int = 0
    ue_ip:       str = ""
    upf_teid:    int = 0
    upf_gtpu_ip: str = ""
    urr_ids:     list[int] = field(default_factory=list)
    imsi:        str = ""
    msisdn:      str = ""
    imei:        str = ""


# ══════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════
def fmt_bytes(n: int) -> str:
    for unit, div in (("GiB", 1<<30), ("MiB", 1<<20), ("KiB", 1<<10)):
        if n and n % div == 0:
            return f"{n // div}{unit}"
    for unit, div in (("GB", 10**9), ("MB", 10**6), ("KB", 10**3)):
        if n and n % div == 0:
            return f"{n // div}{unit}"
    return str(n)

def parse_bytes(s: str) -> int:
    u = s.upper()
    for suffix, mul in (("GIB", 1<<30), ("MIB", 1<<20), ("KIB", 1<<10),
                        ("GB",  10**9), ("MB",  10**6), ("KB",  10**3)):
        if u.endswith(suffix):
            return int(u[:-len(suffix)]) * mul
    return int(s)

def parse_flags(s: str, name_map: dict[str, int]) -> int:
    result = 0
    for name in s.split(","):
        name = name.strip().lower()
        if name not in name_map:
            raise ValueError(f"Unknown flag {name!r}. Valid: {sorted(name_map)}")
        result |= name_map[name]
    return result

def _ntp_to_str(raw: bytes) -> str:
    if len(raw) < 4:
        return "?"
    ts = struct.unpack("!I", raw[:4])[0]
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts - NTP_DELTA))


# ══════════════════════════════════════════════════════════════════════════
#  Usage Report parser
# ══════════════════════════════════════════════════════════════════════════
def parse_usage_report_ie(raw: bytes) -> UsageReport:
    ies = decode_ies(raw)
    ur  = UsageReport()

    r = ies.get(IET.URR_ID, [None])[0]
    if r and len(r) >= 4:
        ur.urr_id = struct.unpack("!I", r)[0]

    r = ies.get(IET.UR_SEQN, [None])[0]
    if r and len(r) >= 4:
        ur.seqn = struct.unpack("!I", r)[0]

    r = ies.get(IET.USAGE_REPORT_TRIGGER, [None])[0]
    if r and len(r) >= 2:
        ur.trigger = struct.unpack("!H", r[:2])[0]

    r = ies.get(IET.VOLUME_MEASUREMENT, [None])[0]
    if r and len(r) >= 1:
        flags, off = r[0], 1
        for flag, attr in ((VT_TOVOL, "total"), (VT_ULVOL, "ul"), (VT_DLVOL, "dl")):
            if flags & flag and len(r) >= off + 8:
                setattr(ur, attr, struct.unpack("!Q", r[off:off+8])[0])
                off += 8

    r = ies.get(IET.DURATION_MEASUREMENT, [None])[0]
    if r and len(r) >= 4:
        ur.duration = struct.unpack("!I", r)[0]

    r = ies.get(IET.START_TIME, [None])[0]
    if r: ur.start = _ntp_to_str(r)

    r = ies.get(IET.END_TIME, [None])[0]
    if r: ur.end = _ntp_to_str(r)

    return ur


# ══════════════════════════════════════════════════════════════════════════
#  GTP-U packet builders
# ══════════════════════════════════════════════════════════════════════════
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def build_icmp_echo_request(icmp_id: int, seq: int,
                            payload: bytes = b"pfcp-smf-ping\x00\x00\x00") -> bytes:
    hdr  = struct.pack("!BBHHH", ICMP_ECHO_REQ, 0, 0, icmp_id, seq)
    csum = _checksum(hdr + payload)
    return struct.pack("!BBHHH", ICMP_ECHO_REQ, 0, csum, icmp_id, seq) + payload

def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    tlen = 20 + len(payload)
    ip_id = random.randint(0, 0xFFFF)
    hdr = struct.pack("!BBHHHBBH4s4s",
                      0x45, 0, tlen, ip_id, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    csum = _checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s",
                       0x45, 0, tlen, ip_id, 0x4000, 64, proto, csum,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload

def build_gtpu(teid: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", GTPU_FLAGS, GTPU_GPDU, len(payload), teid) + payload

def parse_gtpu_icmp_reply(data: bytes) -> dict | None:
    if len(data) < 8:
        return None
    _, msg_type, _, _ = struct.unpack("!BBHI", data[:8])
    if msg_type != GTPU_GPDU:
        return None
    inner = data[8:]
    if len(inner) < 20:
        return None
    ihl  = (inner[0] & 0x0F) * 4
    proto = inner[9]
    src   = socket.inet_ntoa(inner[12:16])
    if proto != IP_PROTO_ICMP or len(inner) < ihl + 8:
        return None
    icmp = inner[ihl:]
    t, _, _, icmp_id, seq = struct.unpack("!BBHHH", icmp[:8])
    if t != ICMP_ECHO_REP:
        return None
    return {"icmp_id": icmp_id, "seq": seq, "src_ip": src}


# ══════════════════════════════════════════════════════════════════════════
#  GTP-U asyncio protocol + sender
# ══════════════════════════════════════════════════════════════════════════
class GTPUProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport: asyncio.DatagramTransport | None = None
        self._pending: dict[int, tuple[asyncio.Future, float]] = {}

    def connection_made(self, transport):
        self.transport = transport
        host, port = transport.get_extra_info("sockname")
        log.info(f"GTP-U socket ready on {host}:{port}")

    def datagram_received(self, data: bytes, addr: tuple):
        recv_time = time.monotonic()
        result    = parse_gtpu_icmp_reply(data)
        if result is None:
            return
        entry = self._pending.pop(result["icmp_id"], None)
        if entry and not entry[0].done():
            result["rtt_ms"] = (recv_time - entry[1]) * 1000
            entry[0].set_result(result)

    def error_received(self, exc):
        log.error(f"GTP-U error: {exc}")

    def connection_lost(self, exc):
        for fut, _ in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    def send_ping(self, teid: int, upf_addr: tuple,
                  icmp_id: int, seq: int,
                  ue_ip: str, dst_ip: str) -> asyncio.Future:
        pkt = build_gtpu(teid, build_ipv4(ue_ip, dst_ip, IP_PROTO_ICMP,
                                          build_icmp_echo_request(icmp_id, seq)))
        fut = asyncio.get_event_loop().create_future()
        self._pending[icmp_id] = (fut, time.monotonic())
        self.transport.sendto(pkt, upf_addr)
        return fut


class GTPUSender:
    TIMEOUT = 5.0

    def __init__(self, local_ip: str):
        self.local_ip  = local_ip
        self._proto: GTPUProtocol | None = None
        self._icmp_id  = random.randint(1, 0xFFFE)
        self._icmp_seq = 0

    async def start(self):
        proto = GTPUProtocol()
        await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: proto, local_addr=(self.local_ip, GTPU_PORT))
        self._proto = proto

    def close(self):
        if self._proto and self._proto.transport:
            self._proto.transport.close()

    async def ping(self, sess: Session, dst_ip: str = "8.8.8.8", count: int = 1) -> int:
        if not sess.ue_ip or not sess.upf_gtpu_ip or not sess.upf_teid:
            log.error("Session missing UE IP or UPF GTP-U endpoint")
            return 0
        upf_addr = (sess.upf_gtpu_ip, GTPU_PORT)
        ok = 0
        for i in range(count):
            self._icmp_seq = (self._icmp_seq + 1) & 0xFFFF
            icmp_id        = self._icmp_id
            seq            = self._icmp_seq
            log.info(f"GTP-U → ping {dst_ip}  ue={sess.ue_ip}  "
                     f"upf={sess.upf_gtpu_ip}  teid=0x{sess.upf_teid:08X}  "
                     f"id={icmp_id}  seq={seq}")
            fut = self._proto.send_ping(sess.upf_teid, upf_addr,
                                        icmp_id, seq, sess.ue_ip, dst_ip)
            try:
                r = await asyncio.wait_for(fut, timeout=self.TIMEOUT)
                log.info(f"GTP-U ← reply from {r['src_ip']}  "
                         f"id={r['icmp_id']}  seq={r['seq']}  rtt={r['rtt_ms']:.2f}ms")
                ok += 1
            except TimeoutError:
                log.warning(f"GTP-U ← timeout  seq={seq}")
                self._proto._pending.pop(icmp_id, None)
            if i < count - 1:
                await asyncio.sleep(1)
        return ok


# ══════════════════════════════════════════════════════════════════════════
#  PFCP IE builders — primitives
# ══════════════════════════════════════════════════════════════════════════
def _ie(ie_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", ie_type, len(value)) + value

def ie_cause(cause: int) -> bytes:
    return _ie(IET.CAUSE, bytes([cause]))

def ie_node_id_ipv4(ip: str) -> bytes:
    return _ie(IET.NODE_ID, b"\x00" + socket.inet_aton(ip))

def ie_recovery_timestamp() -> bytes:
    return _ie(IET.RECOVERY_TIMESTAMP,
               struct.pack("!I", int(time.time()) + NTP_DELTA))

def ie_cp_features(f: int = 0x00) -> bytes:
    return _ie(IET.CP_FUNC_FEATURES, bytes([f]))

def ie_fseid(seid: int, ip: str) -> bytes:
    return _ie(IET.FSEID,
               bytes([FSEID_V4]) + struct.pack("!Q", seid) + socket.inet_aton(ip))

def ie_pdr_id(v: int) -> bytes:
    return _ie(IET.PDR_ID, struct.pack("!H", v))

def ie_precedence(v: int) -> bytes:
    return _ie(IET.PRECEDENCE, struct.pack("!I", v))

def ie_source_interface(v: int) -> bytes:
    return _ie(IET.SOURCE_INTERFACE, bytes([v & 0x0F]))

def ie_dest_interface(v: int) -> bytes:
    return _ie(IET.DEST_INTERFACE, bytes([v & 0x0F]))

def ie_network_instance(name: str) -> bytes:
    return _ie(IET.NETWORK_INSTANCE, name.encode())

def ie_fteid_ch() -> bytes:
    return _ie(IET.FTEID, bytes([FTEID_CH]))

def ie_fteid(teid: int, ip: str) -> bytes:
    return _ie(IET.FTEID,
               bytes([FTEID_V4]) + struct.pack("!I", teid) + socket.inet_aton(ip))

def ie_ue_ip_address_ul() -> bytes:
    return _ie(IET.UE_IP_ADDRESS, bytes([UEIP_CHV4 | UEIP_SD]))

def ie_ue_ip_address_dl() -> bytes:
    return _ie(IET.UE_IP_ADDRESS, bytes([UEIP_CHV4]))

def ie_far_id(v: int) -> bytes:
    return _ie(IET.FAR_ID, struct.pack("!I", v))

def ie_urr_id(v: int) -> bytes:
    return _ie(IET.URR_ID, struct.pack("!I", v))

def ie_apply_action(v: int) -> bytes:
    return _ie(IET.APPLY_ACTION, bytes([v]))

def ie_measurement_method(v: int) -> bytes:
    return _ie(IET.MEASUREMENT_METHOD, bytes([v]))

def ie_reporting_triggers(v: int) -> bytes:
    return _ie(IET.REPORTING_TRIGGERS, struct.pack("!H", v))

def ie_volume_threshold(total: int | None = None,
                        ul: int | None = None,
                        dl: int | None = None) -> bytes:
    flags, body = 0, b""
    if total is not None: flags |= VT_TOVOL; body += struct.pack("!Q", total)
    if ul    is not None: flags |= VT_ULVOL; body += struct.pack("!Q", ul)
    if dl    is not None: flags |= VT_DLVOL; body += struct.pack("!Q", dl)
    return _ie(IET.VOLUME_THRESHOLD, bytes([flags]) + body) if flags else b""

def ie_time_threshold(seconds: int) -> bytes:
    return _ie(IET.TIME_THRESHOLD, struct.pack("!I", seconds))

def ie_volume_quota(total: int | None = None,
                    ul:    int | None = None,
                    dl:    int | None = None) -> bytes:
    """Volume Quota IE (73) — same layout as Volume Threshold."""
    flags, body = 0, b""
    if total is not None: flags |= VT_TOVOL; body += struct.pack("!Q", total)
    if ul    is not None: flags |= VT_ULVOL; body += struct.pack("!Q", ul)
    if dl    is not None: flags |= VT_DLVOL; body += struct.pack("!Q", dl)
    return _ie(IET.VOLUME_QUOTA, bytes([flags]) + body) if flags else b""

def ie_time_quota(seconds: int) -> bytes:
    """Time Quota IE (65) — uint32 seconds."""
    return _ie(IET.TIME_QUOTA, struct.pack("!I", seconds))

def ie_quota_holding_time(seconds: int) -> bytes:
    """Quota Holding Time IE (71) — uint32 seconds."""
    return _ie(IET.QUOTA_HOLDING_TIME, struct.pack("!I", seconds))

def ie_inactivity_detection_time(seconds: int) -> bytes:
    """Inactivity Detection Time IE (36) — uint32 seconds."""
    return _ie(IET.INACTIVITY_DETECTION_TIME, struct.pack("!I", seconds))

def ie_measurement_period(seconds: int) -> bytes:
    """Measurement Period IE (64) — uint32 seconds, used with PERIO trigger."""
    return _ie(IET.MEASUREMENT_PERIOD, struct.pack("!I", seconds))

def ie_outer_header_creation(teid: int, ip: str) -> bytes:
    return _ie(IET.OUTER_HEADER_CREATION,
               struct.pack("!H", OHC_GTP_U_UDP_IPV4) +
               struct.pack("!I", teid) + socket.inet_aton(ip))

def ie_apn_dnn(apn: str) -> bytes:
    return _ie(IET.APN_DNN,
               b"".join(bytes([len(l)]) + l.encode() for l in apn.split(".")))

def ie_ue_ip_address_pool_identity(pool_name: str) -> bytes:
    enc = pool_name.encode()
    return _ie(IET.UE_IP_ADDRESS_POOL_IDENTITY, struct.pack("!H", len(enc)) + enc)

def _bcd_encode(digits: str) -> bytes:
    """TBCD: first digit in low nibble, second in high nibble."""
    if len(digits) % 2:
        digits += "F"
    return bytes((int(digits[i+1], 16) << 4) | int(digits[i], 16)
                 for i in range(0, len(digits), 2))

def ie_user_id(msisdn: str | None = None,
               imsi:   str | None = None,
               imei:   str | None = None) -> bytes:
    flags, body = 0, b""
    if imsi   is not None:
        flags |= USERID_IMSI;   enc = _bcd_encode(imsi);   body += bytes([len(enc)]) + enc
    if imei   is not None:
        flags |= USERID_IMEI;   enc = _bcd_encode(imei);   body += bytes([len(enc)]) + enc
    if msisdn is not None:
        flags |= USERID_MSISDN; enc = _bcd_encode(msisdn); body += bytes([len(enc)]) + enc
    return _ie(IET.USER_ID, bytes([flags]) + body)


# ══════════════════════════════════════════════════════════════════════════
#  PFCP IE builders — grouped
# ══════════════════════════════════════════════════════════════════════════
def ie_pdi_ul(network_instance: str) -> bytes:
    return _ie(IET.PDI,
               ie_source_interface(IF_ACCESS)        +
               ie_network_instance(network_instance) +
               ie_fteid_ch()                         +
               ie_ue_ip_address_ul())

def ie_pdi_dl(network_instance: str) -> bytes:
    return _ie(IET.PDI,
               ie_source_interface(IF_CORE)          +
               ie_network_instance(network_instance) +
               ie_ue_ip_address_dl())

def ie_create_pdr_ul(network_instance: str, urr_ids: list[int]) -> bytes:
    body = (ie_pdr_id(1) + ie_precedence(100) + ie_pdi_ul(network_instance) +
            ie_far_id(1) + b"".join(ie_urr_id(u) for u in urr_ids))
    return _ie(IET.CREATE_PDR, body)

def ie_create_pdr_dl(network_instance: str, urr_ids: list[int]) -> bytes:
    body = (ie_pdr_id(2) + ie_precedence(200) + ie_pdi_dl(network_instance) +
            ie_far_id(2) + b"".join(ie_urr_id(u) for u in urr_ids))
    return _ie(IET.CREATE_PDR, body)

def ie_create_far_ul() -> bytes:
    return _ie(IET.CREATE_FAR,
               ie_far_id(1) + ie_apply_action(AA_FORW) +
               _ie(IET.FORWARDING_PARAMS, ie_dest_interface(IF_CORE)))

def ie_create_far_dl(enb_teid: int, enb_ip: str) -> bytes:
    return _ie(IET.CREATE_FAR,
               ie_far_id(2) + ie_apply_action(AA_FORW) +
               _ie(IET.FORWARDING_PARAMS,
                   ie_dest_interface(IF_ACCESS) +
                   ie_outer_header_creation(enb_teid, enb_ip)))

def ie_create_urr_from_config(urr: URRConfig) -> bytes:
    body = (ie_urr_id(urr.urr_id) +
            ie_measurement_method(urr.measure) +
            ie_reporting_triggers(urr.triggers))
    # Thresholds
    vt = ie_volume_threshold(urr.volth_total, urr.volth_ul, urr.volth_dl)
    if vt:                               body += vt
    if urr.timth is not None:            body += ie_time_threshold(urr.timth)
    # Quotas
    vq = ie_volume_quota(urr.vol_quota_total, urr.vol_quota_ul, urr.vol_quota_dl)
    if vq:                               body += vq
    if urr.time_quota           is not None: body += ie_time_quota(urr.time_quota)
    if urr.quota_holding_time   is not None: body += ie_quota_holding_time(urr.quota_holding_time)
    if urr.inactivity_detection is not None: body += ie_inactivity_detection_time(urr.inactivity_detection)
    if urr.measurement_period   is not None: body += ie_measurement_period(urr.measurement_period)
    return _ie(IET.CREATE_URR, body)

def ie_ue_ip_address_pool_information(ni: str, pool: str) -> bytes:
    return _ie(IET.UE_IP_ADDRESS_POOL_INFORMATION,
               ie_network_instance(ni) + ie_ue_ip_address_pool_identity(pool))


# ══════════════════════════════════════════════════════════════════════════
#  PFCP header encode / decode
# ══════════════════════════════════════════════════════════════════════════
def encode_header(msg_type: int, seq: int, body: bytes,
                  seid: int | None = None) -> bytes:
    flags = 0x20
    if seid is not None:
        flags |= 0x01
        hdr = struct.pack("!BBH", flags, msg_type, 4 + 8 + len(body))
        hdr += struct.pack("!Q", seid)
    else:
        hdr = struct.pack("!BBH", flags, msg_type, 4 + len(body))
    hdr += struct.pack("!BBBx",
                       (seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF)
    return hdr + body


def decode_header(data: bytes) -> dict:
    if len(data) < 8:
        raise ValueError(f"Packet too short ({len(data)} bytes)")
    flags, msg_type, _ = struct.unpack("!BBH", data[:4])
    off, seid = 4, 0
    if flags & 0x01:
        seid = struct.unpack("!Q", data[off:off+8])[0]; off += 8
    seq = (data[off] << 16) | (data[off+1] << 8) | data[off+2]
    return {"msg_type": msg_type,
            "name":     MSG_NAME.get(msg_type, f"Unknown(0x{msg_type:02X})"),
            "seid":     seid, "seq": seq, "ies_raw": data[off+4:]}


def decode_ies(raw: bytes) -> dict[int, list[bytes]]:
    """Returns {ie_type: [value, ...]} — list preserves duplicate IEs."""
    ies: dict[int, list[bytes]] = {}
    off = 0
    while off + 4 <= len(raw):
        ie_type, ie_len = struct.unpack("!HH", raw[off:off+4])
        ies.setdefault(ie_type, []).append(raw[off+4: off+4+ie_len])
        off += 4 + ie_len
    return ies


# ══════════════════════════════════════════════════════════════════════════
#  PFCP UDP protocol
# ══════════════════════════════════════════════════════════════════════════
class PFCPProtocol(asyncio.DatagramProtocol):
    _RESPONSE_TYPES = {MT.HB_RESP, MT.ASSOC_RSP, MT.SESS_EST_RSP, MT.SESS_DEL_RSP}

    def __init__(self, local_ip: str, on_session_report=None):
        self.local_ip           = local_ip
        self._on_session_report = on_session_report
        self.transport: asyncio.DatagramTransport | None = None
        self._pending:  dict[int, asyncio.Future]        = {}

    def connection_made(self, transport):
        self.transport = transport
        host, port = transport.get_extra_info("sockname")
        log.info(f"PFCP socket ready on {host}:{port}")

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            hdr = decode_header(data)
        except ValueError as e:
            log.warning(f"Malformed PFCP from {addr}: {e}"); return
        log.debug(f"PFCP RX {len(data)}B [{hdr['name']}] from {addr[0]}")
        if hdr["msg_type"] in self._RESPONSE_TYPES:
            self._resolve(hdr)
        elif hdr["msg_type"] == MT.HB_REQ:
            self._reply_heartbeat(hdr, addr)
        elif hdr["msg_type"] == MT.SESS_RPT_REQ:
            self._handle_session_report(hdr, addr)
        else:
            log.warning(f"Unhandled PFCP: {hdr['name']}")

    def error_received(self, exc):
        log.error(f"PFCP UDP error: {exc}")

    def connection_lost(self, exc):
        for f in self._pending.values():
            if not f.done(): f.cancel()
        self._pending.clear()

    def _resolve(self, hdr: dict):
        fut = self._pending.pop(hdr["seq"], None)
        if fut and not fut.done():
            fut.set_result(hdr)
        elif fut is None:
            log.warning(f"No pending PFCP req for seq={hdr['seq']}")

    def _reply_heartbeat(self, req: dict, addr: tuple):
        log.info(f"←  {req['name']}  (seq={req['seq']}) from {addr[0]}")
        self.transport.sendto(
            encode_header(MT.HB_RESP, req["seq"], ie_recovery_timestamp()), addr)
        log.info(f"→  {MSG_NAME[MT.HB_RESP]}  (seq={req['seq']})")

    def _handle_session_report(self, req: dict, addr: tuple):
        ies = decode_ies(req["ies_raw"])

        rt_raw = ies.get(IET.REPORT_TYPE, [None])[0]
        rt_str = ""
        if rt_raw:
            rt = rt_raw[0]
            flags = []
            if rt & RPT_USAR: flags.append("USAR")
            if rt & RPT_UPIR: flags.append("UPIR")
            rt_str = f"  report_type=0x{rt:02X}({','.join(flags)})"

        log.info(f"←  {req['name']}  "
                 f"(seq={req['seq']}, seid=0x{req['seid']:016X}){rt_str}")

        usage_reports = []
        for ur_raw in ies.get(IET.USAGE_REPORT_SRR, []):
            ur = parse_usage_report_ie(ur_raw)
            log.info(f"   Usage Report: {ur.summary()}")
            usage_reports.append(ur)

        # callback into SMF — returns the UP SEID for the response header
        up_seid = 0
        if self._on_session_report:
            sr = SessionReport(cp_seid=req["seid"],
                               report_type=rt_raw[0] if rt_raw else 0,
                               usage_reports=usage_reports)
            up_seid = self._on_session_report(sr) or 0

        resp = encode_header(MT.SESS_RPT_RSP, req["seq"],
                             ie_cause(CAUSE_ACCEPTED), seid=up_seid)
        self.transport.sendto(resp, addr)
        log.info(f"→  {MSG_NAME[MT.SESS_RPT_RSP]}  "
                 f"(seq={req['seq']}, seid=0x{up_seid:016X}, cause=Request Accepted)")

    def send_request(self, msg_type: int, seq: int, body: bytes,
                     upf_addr: tuple, seid: int | None = None) -> asyncio.Future:
        pkt = encode_header(msg_type, seq, body, seid)
        log.debug(f"PFCP TX {len(pkt)}B [{MSG_NAME[msg_type]}] to {upf_addr[0]}")
        fut = asyncio.get_event_loop().create_future()
        self._pending[seq] = fut
        self.transport.sendto(pkt, upf_addr)
        return fut


# ══════════════════════════════════════════════════════════════════════════
#  SMF
# ══════════════════════════════════════════════════════════════════════════
class SMF:
    TIMEOUT = 5.0

    def __init__(self, local_ip: str, upf_ip: str, upf_port: int = PFCP_PORT):
        self.local_ip        = local_ip
        self.upf_addr        = (upf_ip, upf_port)
        self.associated      = False
        self._seq            = 0
        self._proto: PFCPProtocol | None = None
        self._next_cp_seid   = 1
        self.sessions:    dict[int, Session]   = {}
        self.urr_configs: dict[int, URRConfig] = {}
        # Queue of SessionReport objects for `expect report` command
        self.report_queue: asyncio.Queue[SessionReport] = asyncio.Queue()

    async def start(self):
        proto = PFCPProtocol(self.local_ip,
                             on_session_report=self._on_session_report)
        await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: proto, local_addr=(self.local_ip, 0))
        self._proto = proto

    def _on_session_report(self, sr: SessionReport) -> int:
        """Called from PFCPProtocol. Returns UP SEID for the response header."""
        sess = self.sessions.get(sr.cp_seid)
        if sess is None:
            log.warning(f"Session Report for unknown cp_seid=0x{sr.cp_seid:016X}")
        self.report_queue.put_nowait(sr)
        return sess.up_seid if sess else 0

    def close(self):
        if self._proto and self._proto.transport:
            self._proto.transport.close()
        log.info("SMF closed")

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFF_FFFF
        return self._seq

    async def _request(self, msg_type: int, body: bytes,
                       seid: int | None = None) -> dict:
        seq = self._next_seq()
        log.info("──────────────────────────────────────")
        log.info(f"→  {MSG_NAME[msg_type]}  (seq={seq})")
        fut = self._proto.send_request(msg_type, seq, body, self.upf_addr, seid)
        return await asyncio.wait_for(fut, timeout=self.TIMEOUT)

    async def send_heartbeat(self) -> bool:
        try:
            hdr = await self._request(MT.HB_REQ, ie_recovery_timestamp())
        except TimeoutError:
            log.error("Heartbeat timed out"); return False
        ies    = decode_ies(hdr["ies_raw"])
        ts_raw = ies.get(IET.RECOVERY_TIMESTAMP, [None])[0]
        ts_str = ""
        if ts_raw and len(ts_raw) >= 4:
            ts_str = f"  recovery_ts={_ntp_to_str(ts_raw)}"
        log.info(f"←  {hdr['name']}  (seq={hdr['seq']}){ts_str}")
        return True

    async def association_setup(self) -> bool:
        try:
            hdr = await self._request(
                MT.ASSOC_REQ,
                ie_node_id_ipv4(self.local_ip) +
                ie_recovery_timestamp()        +
                ie_cp_features(0x00))
        except TimeoutError:
            log.error("Association Setup timed out"); return False

        ies       = decode_ies(hdr["ies_raw"])
        cause     = ies.get(IET.CAUSE, [b"\xff"])[0][0]
        cause_str = CAUSE_NAME.get(cause, f"Unknown({cause})")
        if cause != CAUSE_ACCEPTED:
            log.error(f"←  {hdr['name']}  cause={cause_str}  (REJECTED)")
            return False

        upf_node = "?"
        nid = ies.get(IET.NODE_ID, [None])[0]
        if nid and len(nid) >= 5 and nid[0] == 0x00:
            upf_node = socket.inet_ntoa(nid[1:5])

        up_feat_str = ""
        up_feat_raw = ies.get(IET.UP_FUNC_FEATURES, [None])[0]
        if up_feat_raw:
            val = int.from_bytes(up_feat_raw, "big")
            up_feat_str = f"  up_features=0x{val:0{len(up_feat_raw)*2}X}"

        log.info(f"←  {hdr['name']}  "
                 f"(seq={hdr['seq']}, cause={cause_str}, upf_node_id={upf_node})"
                 f"{up_feat_str}")
        self.associated = True
        return True

    async def session_establishment(
        self,
        imsi:             str | None = None,
        msisdn:           str | None = None,
        imei:             str | None = None,
        network_instance: str = "internet",
        pool_name:        str = "default",
        enb_ip:           str | None = None,
        enb_teid:         int | None = None,
        urr_ids:          list[int] | None = None,
    ) -> Session | None:
        # Resolve URR IDs: explicit list or all configured
        if urr_ids is None:
            urr_ids = list(self.urr_configs.keys())
        missing = [uid for uid in urr_ids if uid not in self.urr_configs]
        if missing:
            log.error(f"URR(s) not configured: {missing}")
            return None

        cp_seid = self._next_cp_seid
        self._next_cp_seid += 1

        # Downlink FAR
        if enb_ip and enb_teid is not None:
            far_dl = ie_create_far_dl(enb_teid, enb_ip)
        else:
            log.warning("No eNB endpoint — downlink FAR will DROP")
            far_dl = _ie(IET.CREATE_FAR, ie_far_id(2) + ie_apply_action(AA_DROP))

        body = (
            ie_node_id_ipv4(self.local_ip)                            +
            ie_fseid(cp_seid, self.local_ip)                          +
            ie_create_pdr_ul(network_instance, urr_ids)               +
            ie_create_pdr_dl(network_instance, urr_ids)               +
            ie_create_far_ul()                                        +
            far_dl                                                    +
            b"".join(ie_create_urr_from_config(self.urr_configs[uid])
                     for uid in urr_ids)                              +
            ie_apn_dnn(network_instance)                              +
            ie_ue_ip_address_pool_information(network_instance,
                                              pool_name)              +
            ie_user_id(msisdn=msisdn, imsi=imsi, imei=imei)
        )
        try:
            hdr = await self._request(MT.SESS_EST_REQ, body, seid=0)
        except TimeoutError:
            log.error("Session Establishment timed out"); return None

        ies       = decode_ies(hdr["ies_raw"])
        cause     = ies.get(IET.CAUSE, [b"\xff"])[0][0]
        cause_str = CAUSE_NAME.get(cause, f"Unknown({cause})")
        if cause != CAUSE_ACCEPTED:
            log.error(f"←  {hdr['name']}  cause={cause_str}  (REJECTED)")
            return None

        sess = Session(cp_seid=cp_seid, imsi=imsi or "",
                       msisdn=msisdn or "", imei=imei or "",
                       urr_ids=list(urr_ids))

        fseid_raw = ies.get(IET.FSEID, [None])[0]
        if fseid_raw and len(fseid_raw) >= 9:
            sess.up_seid = struct.unpack("!Q", fseid_raw[1:9])[0]

        for created_pdr_raw in ies.get(IET.CREATED_PDR, []):
            ci = decode_ies(created_pdr_raw)
            ue_ip_raw = ci.get(IET.UE_IP_ADDRESS, [None])[0]
            if ue_ip_raw and len(ue_ip_raw) >= 5 and (ue_ip_raw[0] & UEIP_V4):
                sess.ue_ip = socket.inet_ntoa(ue_ip_raw[1:5])
            fteid_raw = ci.get(IET.FTEID, [None])[0]
            if (fteid_raw and len(fteid_raw) >= 9
                    and (fteid_raw[0] & FTEID_V4)
                    and not (fteid_raw[0] & FTEID_CH)):
                sess.upf_teid    = struct.unpack("!I", fteid_raw[1:5])[0]
                sess.upf_gtpu_ip = socket.inet_ntoa(fteid_raw[5:9])

        self.sessions[cp_seid] = sess
        log.info(f"←  {hdr['name']}  "
                 f"(seq={hdr['seq']}, cause={cause_str}, "
                 f"cp_seid=0x{cp_seid:016X}, up_seid=0x{sess.up_seid:016X}, "
                 f"ue_ip={sess.ue_ip or '?'}, "
                 f"upf_gtpu={sess.upf_gtpu_ip or '?'}:0x{sess.upf_teid:08X})")
        return sess

    async def session_deletion(self, cp_seid: int) -> bool:
        sess = self.sessions.get(cp_seid)
        if sess is None:
            log.error(f"Unknown cp_seid 0x{cp_seid:016X}"); return False
        try:
            hdr = await self._request(MT.SESS_DEL_REQ, b"", seid=sess.up_seid)
        except TimeoutError:
            log.error("Session Deletion timed out"); return False

        ies       = decode_ies(hdr["ies_raw"])
        cause     = ies.get(IET.CAUSE, [b"\xff"])[0][0]
        cause_str = CAUSE_NAME.get(cause, f"Unknown({cause})")
        if cause != CAUSE_ACCEPTED:
            log.error(f"←  {hdr['name']}  cause={cause_str}  (REJECTED)")
            return False

        del self.sessions[cp_seid]
        log.info(f"←  {hdr['name']}  (seq={hdr['seq']}, cause={cause_str}, "
                 f"cp_seid=0x{cp_seid:016X})")
        return True


# ══════════════════════════════════════════════════════════════════════════
#  Expect Report
# ══════════════════════════════════════════════════════════════════════════
async def wait_for_report(queue: asyncio.Queue[SessionReport],
                          cp_seid: int | None,
                          timeout: float) -> SessionReport:
    """
    Dequeue reports until one matching cp_seid is found.
    Skipped reports (wrong session) are re-queued.
    Raises TimeoutError if deadline expires.
    """
    deadline = time.monotonic() + timeout
    skipped  = []
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            report = await asyncio.wait_for(queue.get(), timeout=remaining)
            if cp_seid is None or report.cp_seid == cp_seid:
                return report
            skipped.append(report)
    finally:
        for r in skipped:
            queue.put_nowait(r)


def validate_report(report: SessionReport,
                    urr_id:    int | None = None,
                    trigger:   int | None = None,
                    total:     int | None = None, total_min: int | None = None, total_max: int | None = None,
                    ul:        int | None = None, ul_min:    int | None = None, ul_max:    int | None = None,
                    dl:        int | None = None, dl_min:    int | None = None, dl_max:    int | None = None,
                    ) -> list[str]:
    """Returns list of failure strings (empty = PASS)."""
    failures = []

    # Find matching usage report
    candidates = [ur for ur in report.usage_reports
                  if urr_id is None or ur.urr_id == urr_id]
    if not candidates:
        return [f"no usage report with urr_id={urr_id} in session report"]
    ur = candidates[0]

    if trigger is not None and not (ur.trigger & trigger):
        names = ",".join(n for f, n in USAGE_REPORT_TRIGGER_NAMES_INV.items() if trigger & f)
        got   = ",".join(n for f, n in USAGE_REPORT_TRIGGER_NAMES_INV.items() if ur.trigger & f)
        failures.append(f"trigger: got={got or '0x0'} missing expected={names}")

    def check_vol(val, exact, vmin, vmax, label):
        if exact is not None and val != exact:
            failures.append(f"{label}: got={val} expected={exact}")
        if vmin is not None and (val is None or val < vmin):
            failures.append(f"{label}: got={val} < min={vmin}")
        if vmax is not None and (val is None or val > vmax):
            failures.append(f"{label}: got={val} > max={vmax}")

    check_vol(ur.total, total, total_min, total_max, "total")
    check_vol(ur.ul,    ul,    ul_min,    ul_max,    "ul")
    check_vol(ur.dl,    dl,    dl_min,    dl_max,    "dl")

    return failures


# ══════════════════════════════════════════════════════════════════════════
#  Command parser
# ══════════════════════════════════════════════════════════════════════════
HELP_TEXT = """\
── URR ──────────────────────────────────────────────────────────────────
  urr set id <n> [triggers <t,...>] [measure <m,...>]
                 [volth total <bytes>] [volth ul <bytes>] [volth dl <bytes>]
                 [timth <seconds>]
                 [volquota total <bytes>] [volquota ul <bytes>] [volquota dl <bytes>]
                 [timquota <seconds>]
                 [qht <seconds>]
                 [inactivity <seconds>]
                 [period <seconds>]
      Configure a URR.  Trigger/measure names (comma-separated, no spaces):
      Trigger names for urr set (§8.2.19 Reporting Triggers):
        perio volth timth quhti start stopt droth liusa
        termr monit envcl timqu volqu eveth macar ipmjl
      Trigger names for expect report (§8.2.41 Usage Report Trigger):
        perio volth timth quhti start stopt droth liusa
        termr monit envcl immer timqu volqu eveth macar
        volth/volquota sub-options: total ul dl
        timth     : Time Threshold (seconds)
        timquota  : Time Quota (seconds)
        qht       : Quota Holding Time (seconds)
        inactivity: Inactivity Detection Time (seconds)
        period    : Measurement Period / Periodic Timer (seconds)
      Byte suffixes: GB MiB MB KiB KB (or plain integer).

  urr show [<id>]       Show configured URR(s).
  urr clear [<id>]      Remove one or all URRs.

── Session ───────────────────────────────────────────────────────────────
  session add [imsi <d>] [msisdn <d>] [imei <d>]
              [dnn <n>] [pool <n>]
              [enb-ip <ip>] [enb-teid <teid>]
              [urr <id1,id2,...>]
      Create session.  urr defaults to all configured URRs.
      enb-ip/enb-teid: eNB GTP-U endpoint for downlink OHC.

  session delete <cp_seid>
  session ping   <cp_seid> [<dst_ip>] [count <n>]
  sessions

── Expect ────────────────────────────────────────────────────────────────
  expect report [timeout <s>] [cp_seid <n>] [urr_id <n>]
                [trigger <name,...>]
                [total <b>] [total_min <b>] [total_max <b>]
                [ul <b>]    [ul_min <b>]    [ul_max <b>]
                [dl <b>]    [dl_min <b>]    [dl_max <b>]
      Wait for a Session Report Request and validate it.
      Prints PASS or FAIL <reason>.

── Misc ──────────────────────────────────────────────────────────────────
  pause <seconds>     Sleep (useful in command files).
  help                Show this message.
  quit / exit\
"""


def parse_urr_set(tokens: list[str]) -> URRConfig:
    urr_id = None; triggers = 0; measure = 0
    volth_total = volth_ul = volth_dl = timth = None
    vol_quota_total = vol_quota_ul = vol_quota_dl = None
    time_quota = quota_holding_time = inactivity_detection = measurement_period = None
    it = iter(tokens)
    for key in it:
        match key:
            case "id":       urr_id   = int(next(it))
            case "triggers": triggers = parse_flags(next(it), REPORTING_TRIGGER_NAMES)
            case "measure":  measure  = parse_flags(next(it), MEASURE_NAMES)
            case "volth":
                match next(it):
                    case "total": volth_total = parse_bytes(next(it))
                    case "ul":    volth_ul    = parse_bytes(next(it))
                    case "dl":    volth_dl    = parse_bytes(next(it))
                    case sub:     raise ValueError(f"Unknown volth sub-option: {sub!r}")
            case "timth":    timth                = int(next(it))
            case "volquota":
                match next(it):
                    case "total": vol_quota_total = parse_bytes(next(it))
                    case "ul":    vol_quota_ul    = parse_bytes(next(it))
                    case "dl":    vol_quota_dl    = parse_bytes(next(it))
                    case sub:     raise ValueError(f"Unknown volquota sub-option: {sub!r}")
            case "timquota":    time_quota           = int(next(it))
            case "qht":         quota_holding_time   = int(next(it))
            case "inactivity":  inactivity_detection = int(next(it))
            case "period":      measurement_period   = int(next(it))
            case _:             raise ValueError(f"Unknown urr option: {key!r}")
    if urr_id is None:
        raise ValueError("urr id is required")
    return URRConfig(
        urr_id=urr_id, triggers=triggers, measure=measure,
        volth_total=volth_total, volth_ul=volth_ul, volth_dl=volth_dl,
        timth=timth, vol_quota_total=vol_quota_total,
        vol_quota_ul=vol_quota_ul, vol_quota_dl=vol_quota_dl,
        time_quota=time_quota, quota_holding_time=quota_holding_time,
        inactivity_detection=inactivity_detection,
        measurement_period=measurement_period,
    )


def parse_session_add(tokens: list[str]) -> dict:
    params: dict = {}
    it = iter(tokens)
    for key in it:
        match key:
            case "imsi":     params["imsi"]             = next(it)
            case "msisdn":   params["msisdn"]           = next(it)
            case "imei":     params["imei"]             = next(it)
            case "dnn":      params["network_instance"] = next(it)
            case "pool":     params["pool_name"]        = next(it)
            case "enb-ip":   params["enb_ip"]           = next(it)
            case "enb-teid": params["enb_teid"]         = int(next(it), 0)
            case "urr":      params["urr_ids"]          = [int(x) for x in next(it).split(",")]
            case _:          raise ValueError(f"Unknown session option: {key!r}")
    return params


def parse_expect_report(tokens: list[str]) -> dict:
    p: dict = {}
    it = iter(tokens)
    for key in it:
        match key:
            case "timeout":   p["timeout"]   = float(next(it))
            case "cp_seid":   p["cp_seid"]   = int(next(it), 0)
            case "urr_id":    p["urr_id"]    = int(next(it))
            case "trigger":   p["trigger"]   = parse_flags(next(it), USAGE_REPORT_TRIGGER_NAMES)
            case "total":     p["total"]     = parse_bytes(next(it))
            case "total_min": p["total_min"] = parse_bytes(next(it))
            case "total_max": p["total_max"] = parse_bytes(next(it))
            case "ul":        p["ul"]        = parse_bytes(next(it))
            case "ul_min":    p["ul_min"]    = parse_bytes(next(it))
            case "ul_max":    p["ul_max"]    = parse_bytes(next(it))
            case "dl":        p["dl"]        = parse_bytes(next(it))
            case "dl_min":    p["dl_min"]    = parse_bytes(next(it))
            case "dl_max":    p["dl_max"]    = parse_bytes(next(it))
            case _:           raise ValueError(f"Unknown expect option: {key!r}")
    return p


def parse_session_ping(tokens: list[str]) -> tuple[str, int]:
    dst_ip, count = "8.8.8.8", 1
    it = iter(tokens)
    for tok in it:
        if tok == "count": count = int(next(it))
        else:              dst_ip = tok
    return dst_ip, count


async def command_loop(smf: SMF, gtpu: GTPUSender, stop_event: asyncio.Event):
    loop   = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    while not stop_event.is_set():
        try:
            line_bytes = await reader.readline()
        except asyncio.CancelledError:
            break
        if not line_bytes:
            stop_event.set(); break

        line = line_bytes.decode().strip()
        if not line or line.startswith("#"):
            continue

        tokens = shlex.split(line)
        try:
            match tokens:
                case ["quit"] | ["exit"]:
                    log.info("Quit requested"); stop_event.set()

                case ["help"]:
                    print(HELP_TEXT, flush=True)

                # ── URR ────────────────────────────────────────────────
                case ["urr", "set", *rest]:
                    urr = parse_urr_set(rest)
                    smf.urr_configs[urr.urr_id] = urr
                    print(f"urr configured: {urr.summary()}", flush=True)

                case ["urr", "show", *rest]:
                    filt = int(rest[0]) if rest else None
                    configs = ({filt: smf.urr_configs[filt]}
                               if filt else smf.urr_configs)
                    if not configs:
                        print("(no URRs configured)", flush=True)
                    for urr in configs.values():
                        print(f"  {urr.summary()}", flush=True)

                case ["urr", "clear", *rest]:
                    if rest:
                        uid = int(rest[0])
                        smf.urr_configs.pop(uid, None)
                        print(f"urr {uid} cleared", flush=True)
                    else:
                        smf.urr_configs.clear()
                        print("all URRs cleared", flush=True)

                # ── Session ────────────────────────────────────────────
                case ["sessions"]:
                    if not smf.sessions:
                        print("(no active sessions)", flush=True)
                    for s in smf.sessions.values():
                        print(f"  cp_seid=0x{s.cp_seid:016X}"
                              f"  up_seid=0x{s.up_seid:016X}"
                              f"  ue_ip={s.ue_ip or '?':15s}"
                              f"  upf_gtpu={s.upf_gtpu_ip or '?'}:0x{s.upf_teid:08X}"
                              f"  urr={s.urr_ids}"
                              f"  imsi={s.imsi or '-'}", flush=True)

                case ["session", "add", *rest]:
                    params = parse_session_add(rest)
                    sess   = await smf.session_establishment(**params)
                    if sess:
                        print(f"session created"
                              f" cp_seid=0x{sess.cp_seid:016X}"
                              f" ue_ip={sess.ue_ip or '?'}"
                              f" upf_gtpu={sess.upf_gtpu_ip or '?'}"
                              f":0x{sess.upf_teid:08X}", flush=True)

                case ["session", "delete", seid_str]:
                    ok = await smf.session_deletion(int(seid_str, 0))
                    if ok:
                        print(f"session deleted cp_seid={seid_str}", flush=True)

                case ["session", "ping", seid_str, *rest]:
                    sess = smf.sessions.get(int(seid_str, 0))
                    if sess is None:
                        print(f"error: unknown cp_seid {seid_str}", flush=True)
                    else:
                        dst_ip, count = parse_session_ping(rest)
                        ok = await gtpu.ping(sess, dst_ip=dst_ip, count=count)
                        print(f"ping {ok}/{count} replies from {dst_ip}", flush=True)

                # ── Expect ─────────────────────────────────────────────
                case ["expect", "report", *rest]:
                    p       = parse_expect_report(rest)
                    timeout = p.pop("timeout", 10.0)
                    cp_seid = p.pop("cp_seid", None)
                    try:
                        report = await wait_for_report(
                            smf.report_queue, cp_seid, timeout)
                    except TimeoutError:
                        print(f"FAIL: timeout after {timeout}s "
                              f"waiting for session report", flush=True)
                    else:
                        failures = validate_report(report, **p)
                        if failures:
                            for f in failures:
                                print(f"FAIL: {f}", flush=True)
                        else:
                            urs = report.usage_reports
                            summary = urs[0].summary() if urs else "no usage reports"
                            print(f"PASS: {summary}", flush=True)

                # ── Misc ───────────────────────────────────────────────
                case ["pause", secs_str]:
                    secs = float(secs_str)
                    log.info(f"pause {secs}s")
                    await asyncio.sleep(secs)

                case _:
                    print(f"unknown command: {line!r}  (type 'help')", flush=True)

        except (ValueError, StopIteration, KeyError) as exc:
            print(f"error: {exc}", flush=True)


# ══════════════════════════════════════════════════════════════════════════
#  Background tasks
# ══════════════════════════════════════════════════════════════════════════
async def hb_sender(smf: SMF, interval: int):
    log.info(f"hb_sender started (interval={interval}s)")
    while True:
        await asyncio.sleep(interval)
        await smf.send_heartbeat()


# ══════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════
async def amain(args: argparse.Namespace):
    smf  = SMF(args.smf_ip, args.upf_ip, args.upf_port)
    gtpu = GTPUSender(args.gtpu_ip)
    await smf.start()
    await gtpu.start()
    stop_event = asyncio.Event()
    try:
        if not await smf.send_heartbeat():
            log.error("Initial heartbeat failed — aborting"); return
        if not await smf.association_setup():
            log.error("Association setup failed — aborting"); return

        log.info("══════════════════════════════════════")
        log.info("  Association established ✓")
        log.info("══════════════════════════════════════")

        async with asyncio.TaskGroup() as tg:
            tg.create_task(command_loop(smf, gtpu, stop_event), name="cmd_loop")
            if args.hb_interval > 0:
                tg.create_task(hb_sender(smf, args.hb_interval), name="hb_sender")
            tg.create_task(stop_event.wait(), name="stop_watcher")

    except* KeyboardInterrupt:
        log.info("Interrupted")
    finally:
        gtpu.close()
        smf.close()


def main():
    p = argparse.ArgumentParser(
        description="PFCP N4 SMF simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python smf_pfcp.py --smf-ip 10.0.0.1 --upf-ip 10.0.0.2
  python smf_pfcp.py --smf-ip 10.0.0.1 --gtpu-ip 192.168.1.1 --upf-ip 10.0.0.2 --hb-interval 10
        """)
    p.add_argument("--smf-ip",      default="127.0.0.1",
                   help="Local IP for PFCP N4 control plane")
    p.add_argument("--gtpu-ip",     default=None,
                   help="Local IP for GTP-U data plane (defaults to --smf-ip)")
    p.add_argument("--upf-ip",      required=True)
    p.add_argument("--upf-port",    type=int, default=PFCP_PORT)
    p.add_argument("--hb-interval", type=int, default=0,
                   help="Seconds between Heartbeat Requests (0=disabled)")
    args = p.parse_args()
    if args.gtpu_ip is None:
        args.gtpu_ip = args.smf_ip
    asyncio.run(amain(args))


if __name__ == "__main__":
    main()
