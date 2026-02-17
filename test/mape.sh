#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh

clean() {
    clean_netns "cloud"
}

# MAPE_BR has everything on one interface
setup_combined() {
    setup_netns "cloud"
    sleep 0.5

    # trunk
    ip link add dev veth0 netns cloud address d2:ad:ca:fe:aa:01 type veth \
       peer name mapebr address d2:f0:0c:ba:bb:01
    ip -n cloud link set dev veth0 up
    ip -n cloud link set dev lo up
    ip link set dev mapebr up
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1
    ip netns exec cloud sysctl -q net.ipv6.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.mapebr.forwarding=1
    sysctl -q net.ipv6.conf.mapebr.forwarding=1

    # ipv6
    ip -n cloud addr add fc::2/64 dev veth0
    ip addr add fc::1/64 dev mapebr
    ip route add default via fc::2 dev mapebr table 1020
    ip -6 neigh add fc::2 lladdr d2:ad:ca:fe:aa:01 nud permanent dev mapebr

    # ipv4
    ip -n cloud addr add 8.8.8.8/32 dev veth0
    ip -n cloud addr add 192.168.61.2/28 dev veth0
    ip -n cloud route add default via 192.168.61.1 dev veth0 mtu 1460
    ip addr add 192.168.61.1/28 dev mapebr
    ip route add 192.168.61.0/28 dev mapebr table 1020
    ip route add default via 192.168.61.2 dev mapebr table 1020
    ip neigh add 192.168.61.2 lladdr d2:ad:ca:fe:aa:01 dev mapebr

    ip netns exec cloud ethtool -K veth0 gro on
    ip netns exec cloud ethtool -K veth0 tx-checksumming off >/dev/null
}

run_combined() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program mape-prg
no mape-rule m1
"
    gtpg_conf "
    bpf-program mape-prg 
 path bin/mape.bpf
 no shutdown

interface mapebr
 bpf-program mape-prg
 ip route table-id 1020
 no shutdown

mape-rule m1
 description blabla
 border-relay-address 2a01:ffff::1
 ipv6-prefix 2a01:e456:123f::3:4/46
 ipv4-prefix 87.12.1.2/16
 port-parameters share-ratio 4
 bpf-program mape-prg
" || fail "cannot execute vty commands"

    gtpg_show "
show running-config
show interface
show interface-rule all
show interface-rule input
show mape
"
}

pkt() {

    # display map-e encap packets
    (
	ip netns exec cloud python3 - <<EOF
from scapy.all import *
def receive(p):
  print(p.summary())
p = sniff(count=10, iface="veth0", filter=f"ip6 proto 4", prn=receive)
EOF
    ) &
    python_pid=$!
    echo "kill $python_pid 2> /dev/null" >> $tmp/cleanup.sh

    sleep 1
    
#     send_py_pkt cloud veth0 "
# p = [Ether(src='d2:ad:ca:fe:aa:01', dst='d2:f0:0c:ba:bb:01') /
#   IPv6(src='2a01:e456::55', dst='2a01:ffff::1', nh=4) /
#   IP(src='87.12.255.85 ', dst='8.8.8.8') /
#   ICMP(type='echo-request', id=18000, seq=33),
# ]
# "

    send_py_pkt cloud veth0 "
p = [Ether(src='d2:ad:ca:fe:aa:01', dst='d2:f0:0c:ba:bb:01') /
  IPv6(src='2a01:e456::55', dst='2a01:ffff::1', nh=4) /
  IP(src='87.12.255.85', dst='8.8.8.8') /
  ICMP(type='echo-request', id=38000, seq=33) /
  Raw('X' + 'Y' * 1820 + 'Z')
]
p = fragment(p, fragsize=1400)
"

    sleep 1
    echo "done"
}


action=${1:-setup}
type=${2:-combined}

case $action in
    clean)
	clean ;;
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
