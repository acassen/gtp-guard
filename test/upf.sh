#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh

clean() {
    clean_netns "cloud" "access" "internet"
}

# UPF has everything on one interface
setup_combined() {
    setup_netns "cloud"
    sleep 0.5

    # trunk
    ip link add dev veth0 netns cloud address d2:ad:ca:fe:aa:01 type veth \
       peer name upf address d2:f0:0c:ba:bb:01
    ip -n cloud link set dev veth0 up
    ip -n cloud link set dev lo up
    ip link set dev upf up
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1
    ip netns exec cloud sysctl -q net.ipv6.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.upf.forwarding=1
    sysctl -q net.ipv6.conf.upf.forwarding=1

    # pfcp
    ip -n cloud addr add 192.168.61.193/27 dev veth0
    ip addr add 192.168.61.194/27 dev upf

    # gtp-u
    ip -n cloud addr add 192.168.61.2/25 dev veth0
    ip -n cloud addr add 192.168.61.3 dev veth0
    ip -n cloud addr add fc::2/64 dev veth0
    ip addr add 192.168.61.1/25 dev upf
    ip addr add fc::1/64 dev upf
    ip neigh add 192.168.61.2 lladdr d2:ad:ca:fe:aa:01 dev upf
    ip neigh add 192.168.61.3 lladdr d2:ad:ca:fe:aa:01 dev upf
    ip -6 neigh add fc::2 lladdr d2:ad:ca:fe:aa:01 nud permanent dev upf

    # outside
    ip -n cloud addr add 8.8.8.8/32 dev veth0
    ip -n cloud addr add 8::8 dev veth0
    ip -n cloud route add default via 192.168.61.1 dev veth0
    ip -n cloud route add default via fc::1 dev veth0
    ip route add 192.168.61.0/25 dev upf table 1020
    ip route add default via 192.168.61.2 dev upf table 1020
    ip route add default via fc::2 dev upf table 1020

    ip netns exec cloud ethtool -K veth0 gro on
    ip netns exec cloud ethtool -K veth0 tx-checksumming off >/dev/null
}


# 2 interfaces for UPF: access and internet
setup_split() {
    setup_netns "access" "internet"
    sleep 0.5

    # access trunk
    ip link add dev veth0 netns access address d2:ad:ca:fe:aa:01 type veth \
       peer name ran address d2:f0:0c:ba:bb:01
    ip -n access link set dev veth0 up
    ip -n access link set dev lo up
    ip link set dev ran up
    ip netns exec access sysctl -q net.ipv4.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.ran.forwarding=1
    sysctl -q net.ipv6.conf.ran.forwarding=1

    # internet trunk
    ip link add dev veth0 netns internet address d2:ad:ca:fe:aa:02 type veth \
       peer name pub address d2:f0:0c:ba:bb:02
    ip -n internet link set dev veth0 up
    ip -n internet link set dev lo up
    ip link set dev pub up
    ip netns exec internet sysctl -q net.ipv4.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.pub.forwarding=1
    sysctl -q net.ipv6.conf.pub.forwarding=1

    # pfcp, on access
    ip -n access addr add 192.168.61.193/27 dev veth0
    ip addr add 192.168.61.194/27 dev ran

    # gtp-u, on access
    ip -n access addr add 192.168.61.2/25 dev veth0
    ip -n access addr add 192.168.61.3 dev veth0
    ip addr add 192.168.61.1/25 dev ran
    ip neigh add 192.168.61.2 lladdr d2:ad:ca:fe:aa:01 dev ran
    ip neigh add 192.168.61.3 lladdr d2:ad:ca:fe:aa:01 dev ran

    # (almost) whole internet
    ip -n internet addr add 192.168.62.1/24 dev veth0
    ip -n internet addr add fc::1:2/64 dev veth0
    ip addr add 192.168.62.2/24 dev pub
    ip addr add fc::1:1/64 dev pub
    ip -n internet addr add 8.8.8.8/32 dev veth0
    ip -n internet addr add 8::8 dev veth0
    ip -n internet route add default via 192.168.62.2 dev veth0
    ip -n internet route add default via fc::1:1 dev veth0
    ip route add 192.168.61.0/25 dev ran table 1020
    ip route add default via 192.168.62.1 dev pub table 1020
    ip route add default via fc::1:2 dev pub table 1020
    ip neigh add 192.168.62.1 lladdr d2:ad:ca:fe:aa:02 dev pub
    ip -6 neigh add fc::1:2 lladdr d2:ad:ca:fe:aa:02 nud permanent dev pub

    ip netns exec access ethtool -K veth0 gro on
    ip netns exec access ethtool -K veth0 tx-checksumming off >/dev/null
    ip netns exec internet ethtool -K veth0 gro on
    ip netns exec internet ethtool -K veth0 tx-checksumming off >/dev/null
}

run_split_combined() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program upf-1
no carrier-grade-nat upf-1
no pfcp-router pfcp-1
"

    if [ $with_cgn == "no" ]; then
	gtpg_conf "
bpf-program upf-1 
 path bin/upf.bpf
 no shutdown
" || fail "cannot load bpf program"
    else
	prg=upf_cgn.bpf
	gtpg_conf "
bpf-program upf-1 
 path bin/upf_cgn.bpf
 no shutdown

carrier-grade-nat upf-1
 bpf-program upf-1
 ipv4-pool 37.141.0.0/24
" || fail "cannot configure cgn / load bpf"
    fi

    if [ $type == "combined" ]; then
	gtpg_conf "
interface upf
 bpf-program upf-1
 ip route table-id 1020
 no shutdown
" || fail "cannot execute vty commands"
    else
	gtpg_conf "
interface ran
 bpf-program upf-1
 ip route table-id 1020
 no shutdown

interface pub
 bpf-program upf-1
 no shutdown
" || fail "cannot execute vty commands"
    fi

    gtpg_conf "
pfcp-router pfcp-1
 description first_one
 bpf-program upf-1
 listen 192.168.61.194 port 2123
 gtpu-tunnel-endpoint all 192.168.61.1 port 2152
 debug teid add ingress 1 192.168.61.2 10.0.0.1
 debug teid add ingress 2 192.168.61.2 1234::1
 debug teid add ingress 3 192.168.61.2 10.0.0.2 1234::2
 debug teid add egress 17 192.168.61.1
 debug teid add egress 18 192.168.61.1
 debug teid add egress 19 192.168.61.1
 debug teid add fwd 2220 192.168.61.1 192.168.61.2 4
 debug teid add fwd 20 192.168.61.1 192.168.61.3 5
" || fail "cannot execute vty commands"

    gtpg_show "
show running-config
show interface
show interface-rule all
show interface-rule input
show bpf pfcp
"

    gtpg_show "
capture prog upf-1 start upf
"
}

run_combined() { run_split_combined; }
run_split() { run_split_combined; }

#
# 1st pkt: simulate a ping (in a gtp-u packet) from UE.
# upf decap it, send to iface holding 8.8.8.8, receive echo-response,
# then encap it again in gtp-u.
# 2nd pkt: same thing in ipv6
# 3th pkt: act as gtp-u proxy
#
pkt() {
    if [ $type == 'combined' ]; then
	ingress_ns=cloud
    else
	ingress_ns=access
    fi

    # for all packets
    (
ip netns exec $ingress_ns python3 - <<EOF
import socket
import struct
fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fd.bind(('', 2152))
for i in range(0,4):
    data, remote = fd.recvfrom(4096)
    data = bytearray(data)
    teid = struct.unpack('!I', data[4:8])[0]
    if teid == 5:
       rteid = 2220
       print('CORE: FWD teid %d back to %d' % (teid, rteid))
       data[4:8] = struct.pack('!I', rteid)
       data = bytes(data)
       fd.sendto(data, remote)
    else:
      print('CORE: RECV REPLY ! teid is 0x%08x' % struct.unpack('!I', data[4:8]))
fd.close()
EOF
    ) &
    python_pid=$!
    cat >> $tmp/cleanup.sh <<EOF
kill $python_pid 2> /dev/null
EOF

    sleep 1

    if [ $type == "split" -o $type == "combined" ]; then
	send_py_pkt $ingress_ns veth0 "
p = [Ether(src='d2:ad:ca:fe:aa:01', dst='d2:f0:0c:ba:bb:01') /
  IP(src='192.168.61.2', dst='192.168.61.1') /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=17, gtp_type=255) /
  IP(src='10.0.0.1',dst='8.8.8.8') /
  ICMP(type='echo-request',id=126),
Ether(src='d2:ad:ca:fe:aa:01', dst='d2:f0:0c:ba:bb:01') /
  IP(src='192.168.61.2', dst='192.168.61.1') /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=18, gtp_type=255) /
  IPv6(src='1234::1',dst='8::8') /
  ICMPv6EchoRequest(id=99),
Ether(src='d2:ad:ca:fe:aa:01', dst='d2:f0:0c:ba:bb:01') /
  IP(src='192.168.61.2', dst='192.168.61.1') /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=20, gtp_type=255) /
  IP(src='10.0.0.3',dst='8.8.8.8') /
  ICMP(type='echo-request',id=113),
]
"
    fi

    sleep 1
    echo "done"
}


action=${1:-setup}
type=${2:-combined}
with_cgn=${3:-no}

case $action in
    clean)
	clean
	exit 0 ;;
    setup)
	clean
	sleep 0.5
	setup_$type ;;
    run)
	run_$type ;;
    pkt)
	pkt ;;

    *) fail "action '$action' not recognized" ;;
esac
