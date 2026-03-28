#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Olivier Gournet

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

    ip -n cloud link set veth0 xdp obj bin/xdp_pass.bpf sec xdp
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

    ip -n access link set veth0 xdp obj bin/xdp_pass.bpf sec xdp
    ip netns exec access ethtool -K veth0 tx-checksumming off >/dev/null
    ip -n internet link set veth0 xdp obj bin/xdp_pass.bpf sec xdp
    ip netns exec internet ethtool -K veth0 tx-checksumming off >/dev/null
}

run_pkt() {
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
ip pool upf-v4
 prefix 10.0.0.0/12
 no shutdown

ip pool upf-v6
 prefix 2a01:e00:6020::/44
 no shutdown

access-point-name boa
 ip pool upf-v4
 ip pool upf-v6

pfcp-router pfcp-1
 description first_one
 node-id sut.example.com
 strict-apn
 bpf-program upf-1
 listen 192.168.61.194 port 8805
 debug ingress_msg
 debug egress_msg
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


_hash_set() {
    local -n _arr=$1
    local key=$2
    local line

    while IFS= read -r line; do
        _arr["$key"]+="$line"$'\n'
    done
}

smf_basic_urr() {
    if [ "$4" ]; then
	urr_expect="expect report timeout 10 cp_seid 1 urr_id 1 $4"
    else
	urr_expect="expect no report timeout 4"
    fi
    _hash_set $1 $2 <<EOF
urr set id 1 $3
session add imsi 208010101234568 dnn boa.com.example.fr enb-ip 192.168.61.2 enb-teid 8 urr 1
session ping 1 8.8.8.8 count 3
$urr_expect
session delete 1
EOF
}

smf_more_adv_urr() {
    arr=$1
    key=$2
    shift 2

    urr_def=''
    urr_expect=''
    for l in "$@"; do
	if [[ "$l" == urr* ]]; then
	    urr_def+="$l"$'\n'
	elif [[ "$l" == expect* ]]; then
	    urr_expect+="$l"$'\n'
	fi
    done

    urr_expect+="expect no report timeout 4"

    _hash_set $arr $key <<EOF
$urr_def
session add imsi 208010101234568 dnn boa.com.example.fr enb-ip 192.168.61.2 enb-teid 8 urr 2,3
session ping 1 8.8.8.8 count 3
$urr_expect
session delete 1
EOF
}


run_with_smf() {
    smf_cmd="ip netns exec cloud python3 ./test/smf.py --smf-ip 192.168.61.193 --upf-ip 192.168.61.194 --gtpu-ip 192.168.61.2 --upf-port 8805"

    declare -A testset

    # volume measurement
    smf_basic_urr testset volth1			\
    "triggers volth measure volume volth total 240"	\
    "trigger volth total_min 240"
    smf_basic_urr testset volth2			\
    "triggers volth measure volume volth ul 160 volth dl 120"	\
    "trigger volth total_min 240 ul_min 120 dl_min 120"
    smf_basic_urr testset volth3			\
    "triggers volth measure volume volth total 176"	\
    "trigger volth total_min 176"

    # don't work well, trigger 2 will also report 3 (trig volth)
    smf_more_adv_urr testset volth4			\
    "urr set id 2 triggers volth measure volume volth total 176"	\
    "urr set id 3 triggers volth measure volume volth total 240"	\
    "expect report timeout 10 cp_seid 1 urr_id 2 trigger volth total_min 176 urr_id 3 trigger volth total_min 176"

    # no measure vol, do not expect report
    smf_basic_urr testset volth10			\
    "triggers volth volth ul 160 volth dl 120"	\
    ""

    # volume quota
    smf_basic_urr testset volqu1			\
    "triggers volqu measure volume volquota total 120"	\
    "trigger volqu total_min 120"

    # duration
    smf_basic_urr testset timth1			\
    "triggers timth measure duration timth 3"		\
    "trigger timth"
    smf_basic_urr testset timqu1			\
    "triggers timqu measure duration timquota 3"	\
    "trigger timqu"
    smf_basic_urr testset quht				\
    "triggers quht qht 3"				\
    "trigger quht"

    # period
    smf_basic_urr testset period1			\
    "triggers perio period 2"				\
    "trigger perio"
    smf_basic_urr testset period2			\
    "triggers perio measure volume period 2"		\
    "trigger perio"


    if [ "$smf_test_id" ]; then
	if [ "${testset[$smf_test_id]}" ]; then
	    # echo "*****"
	    # printf '%s' "${testset[$smf_test_id]}"
	    # echo "*****"
	    echo "${testset[$smf_test_id]}" | $smf_cmd
	else
	    echo "no such smf-test: $smf_test_id"
	fi
    else
	echo "XXXX run all tests"
    fi
    
}



action=${1:-setup}
type=${2:-combined}
with_cgn=${3:-no}
smf_test_id=${3}

case $action in
    clean)
	clean
	exit 0 ;;
    setup)
	clean
	sleep 0.5
	setup_$type ;;
    run)
	run_with_smf ;;
    run-pkt)
	run_pkt ;;
    pkt)
	pkt ;;

    *) fail "action '$action' not recognized" ;;
esac
