#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh

clean() {
    ip tunnel del ptun 2>/dev/null && true
    ip link del ptun 2>/dev/null && true
    ip link del gtpp 2>/dev/null && true
    clean_netns "sgw" "pgw" "cloud" "cloud-r2"
}

# simplest setup, without bells and whistles
setup_simple() {
    setup_netns "cloud"
    sleep 0.5

    # trunk
    ip link add dev veth0 netns cloud address d2:ad:ca:fe:aa:01 type veth \
       peer name gtpp address d2:f0:0c:ba:bb:01
    ip -n cloud link set dev veth0 up
    ip -n cloud link set dev lo up
    ip link set dev gtpp up
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.gtpp.forwarding=1

    # gtp-c
    ip -n cloud addr add 192.168.61.193/27 dev veth0
    ip addr add 192.168.61.194/27 dev gtpp

    # gtp-u
    ip -n cloud addr add 192.168.61.2/25 dev veth0
    ip -n cloud addr add 192.168.61.3/25 dev veth0
    ip addr add 192.168.61.1/25 dev gtpp
    arp -s 192.168.61.2 d2:ad:ca:fe:aa:01
    arp -s 192.168.61.3 d2:ad:ca:fe:aa:01

    ip netns exec cloud ethtool -K veth0 gro on
    ip netns exec cloud ethtool -K veth0 tx-checksumming off >/dev/null
}


# everyone on the same interface
setup_combined() {
    setup_netns "cloud"
    sleep 0.5

    # trunk
    ip link add dev veth0 netns cloud address d2:ad:ca:fe:aa:01 type veth \
       peer name gtpp address d2:f0:0c:ba:bb:01
    ip -n cloud link set dev veth0 up
    ip -n cloud link set dev lo up
    ip link set dev gtpp up
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.gtpp.forwarding=1

    ip -n cloud addr add 192.168.61.193/27 dev veth0
    for i in `seq 0 $((gtp_proxy_count-1))`; do
	# gtp-c
	ip addr add 192.168.61.$((i+194))/27 dev gtpp

	# gtp-u
	ip -n cloud addr add 192.168.61.$((i*8+2))/25 dev veth0
	ip -n cloud addr add 192.168.61.$((i*8+3))/25 dev veth0
	ip addr add 192.168.61.$((i*8+1))/25 dev gtpp
	arp -s 192.168.61.$((i*8+2)) d2:ad:ca:fe:aa:01
	arp -s 192.168.61.$((i*8+3)) d2:ad:ca:fe:aa:01

	# for ipfrag test, when replying
	ip -n cloud route add 192.168.61.$((i*8+1)) dev veth0 mtu 1480
    done

    # tun
    ns_tun_dev=veth0
    if [ $tun_vlan -ne 0 ]; then
	ns_tun_dev=veth0.$tun_vlan
	ip -n cloud link add link veth0 name $ns_tun_dev type vlan id $tun_vlan
	ip -n cloud link set $ns_tun_dev up
    fi
    ip -n cloud addr add 192.168.61.129/30 dev $ns_tun_dev
    ip -n cloud tunnel add ptun mode ipip local 192.168.61.129 remote 192.168.61.130
    ip -n cloud link set ptun up
    # ip -n cloud addr add 192.168.62.1/30 dev ptun

    tun_dev=gtpp
    if [ $tun_vlan -ne 0 ]; then
	tun_dev=gtpp.$tun_vlan
	ip link add link gtpp name $tun_dev type vlan id $tun_vlan
	ip link set $tun_dev up
    fi
    ip addr add 192.168.61.130/30 dev $tun_dev
    ip tunnel add ptun mode ipip local 192.168.61.130 remote 192.168.61.129
    ip link set ptun up
    # ip addr add 192.168.62.2/30 dev ptun
    arp -s 192.168.61.129 d2:ad:ca:fe:aa:01

    ip netns exec cloud ethtool -K veth0 gro on
    ip netns exec cloud ethtool -K veth0 tx-checksumming off >/dev/null
}


# 2 physical interfaces. remotes are available from any two interface.
# vip ip on dummy interface
setup_vip() {
    setup_netns "cloud" "cloud-r2"
    sleep 0.5

    # trunk1
    ip link add dev veth0 netns cloud address d2:ad:ca:fe:aa:01 type veth \
       peer name gtpp1 address d2:f0:0c:ba:bb:01
    ip -n cloud link set dev veth0 up
    ip -n cloud link set dev lo up
    ip link set dev gtpp1 up
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.gtpp1.forwarding=1
    ip -n cloud link add link veth0 name veth0.100 type vlan id 100
    ip -n cloud link set veth0.100 up
    ip link add link gtpp1 name gtpp1.100 type vlan id 100
    ip link set gtpp1.100 up

    # trunk2
    ip link add dev veth0 netns cloud-r2 address d2:ad:ca:fe:aa:02 type veth \
       peer name gtpp2 address d2:f0:0c:ba:bb:02
    ip -n cloud-r2 link set dev veth0 up
    ip -n cloud-r2 link set dev lo up
    ip link set dev gtpp2 up
    ip netns exec cloud-r2 sysctl -q net.ipv4.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.gtpp2.forwarding=1
    ip -n cloud-r2 link add link veth0 name veth0.100 type vlan id 100
    ip -n cloud-r2 link set veth0.100 up
    ip link add link gtpp2 name gtpp2.100 type vlan id 100
    ip link set gtpp2.100 up

    # dummy
    rmmod dummy 2>/dev/null
    modprobe dummy numdummies=$gtp_proxy_count

    for i in `seq 0 $((gtp_proxy_count-1))`; do
	ip -n cloud link add dummy$i type dummy
	ip -n cloud-r2 link add dummy$i type dummy
	ip -n cloud link set dummy$i up
	ip -n cloud-r2 link set dummy$i up
	ip link set dummy$i up

	# gtp-c. not used here, just set dummy for binding
	ip addr add 192.168.61.$((i+240))/32 dev dummy$i

	# gtp-u
	ip -n cloud addr add 192.168.61.$((i*4+2))/27 dev veth0.100
	ip -n cloud-r2 addr add 192.168.61.$((64+i*4+2))/27 dev veth0.100
	ip -n cloud addr add 192.168.61.$((192+i))/32 dev dummy$i
	ip -n cloud-r2 addr add 192.168.61.$((192+i))/32 dev dummy$i
	ip -n cloud addr add 192.168.61.$((210+i))/32 dev dummy$i
	ip -n cloud-r2 addr add 192.168.61.$((210+i))/32 dev dummy$i

	ip addr add 192.168.61.$((i*4+1))/27 dev gtpp1.100
	ip addr add 192.168.61.$((64+i*4+1))/27 dev gtpp2.100
	ip addr add 192.168.61.$((176+i))/32 dev dummy$i   # 176-191
	ip r add 192.168.61.192/27 via 192.168.61.$((i*4+2)) metric 10 dev gtpp1.100
	ip r add 192.168.61.192/27 via 192.168.61.$((64+i*4+2)) metric 20 dev gtpp2.100
	ip -n cloud route add 192.168.61.176/28 via 192.168.61.$((i*4+1)) dev veth0.100
	ip -n cloud-r2 route add 192.168.61.176/28 via 192.168.61.$((64+i*4+1)) dev veth0.100

	arp -s 192.168.61.$((i*4+2)) d2:ad:ca:fe:aa:01 -i gtpp1.100
	arp -s 192.168.61.$((64+i*4+2)) d2:ad:ca:fe:aa:02 -i gtpp2.100
    done

    # tun
    ns_tun_dev=veth0
    if [ $tun_vlan -ne 0 ]; then
	ns_tun_dev=veth0.$tun_vlan
	ip -n cloud link add link veth0 name $ns_tun_dev type vlan id $tun_vlan
	ip -n cloud link set $ns_tun_dev up
    fi
    ip -n cloud addr add 192.168.61.129/30 dev $ns_tun_dev
    ip -n cloud tunnel add ptun mode ipip local 192.168.61.129 remote 192.168.61.130
    ip -n cloud link set ptun up

    tun_dev=gtpp1
    if [ $tun_vlan -ne 0 ]; then
	tun_dev=gtpp1.$tun_vlan
	ip link add link gtpp1 name $tun_dev type vlan id $tun_vlan
	ip link set $tun_dev up
    fi
    ip addr add 192.168.61.130/30 dev $tun_dev
    ip tunnel add ptun mode ipip local 192.168.61.130 remote 192.168.61.129 dev $tun_dev
    ip link set ptun up
    arp -s 192.168.61.129 d2:ad:ca:fe:aa:01

    ip netns exec cloud ethtool -K veth0 gro on
    ip netns exec cloud ethtool -K veth0 tx-checksumming off >/dev/null
    ip netns exec cloud-r2 ethtool -K veth0 gro on
    ip netns exec cloud-r2 ethtool -K veth0 tx-checksumming off >/dev/null
}


# everyone on its own interface
setup_split() {
    setup_netns "sgw" "pgw" "cloud"
    sleep 0.5

    # pgw side
    ip link add dev pgw netns pgw address d2:ad:ca:fe:b4:01 type veth \
       peer name pgw address d2:f0:0c:ba:a5:02
    ip -n pgw link set dev pgw up
    ip -n pgw link set dev lo up
    ip link set dev pgw up
    ip -n pgw addr add 192.168.61.193/28 dev pgw
    ip -n pgw link add link pgw name pgw.9 type vlan id 9
    ip -n pgw link set pgw.9 up
    ip -n pgw addr add 192.168.61.225/28 dev pgw.9
    ip link add link pgw name pgw.9 type vlan id 9
    ip link set dev pgw.9 up

    # sgw side
    ip link add dev sgw netns sgw address d2:ad:ca:fe:b4:02 type veth \
       peer name sgw address d2:f0:0c:ba:a5:06
    ip -n sgw link set dev sgw up
    ip -n sgw link set dev lo up
    ip link set dev sgw up
    ip -n sgw addr add 192.168.61.209/28 dev sgw

    for i in `seq 0 $((gtp_proxy_count-1))`; do
	# gtp-c
	ip addr add 192.168.61.$((i+194))/28 dev pgw
	ip addr add 192.168.61.$((i+226))/28 dev pgw.9
	ip addr add 192.168.61.$((i+210))/28 dev sgw

	# gtp-u
	ip -n pgw addr add 192.168.61.$((i*4+2))/27 dev pgw
	ip addr add 192.168.61.$((i*4+1))/27 dev pgw
	ip -n pgw addr add 192.168.61.$((i*4+0))/27 dev pgw.9
	ip addr add 192.168.61.$((i*4+3))/27 dev pgw.9
	ip -n sgw addr add 192.168.61.$((64+i*4+2))/27 dev sgw
	ip addr add 192.168.61.$((64+i*4+1))/27 dev sgw

	arp -s 192.168.61.$((i*4+2)) d2:ad:ca:fe:b4:01
	arp -s 192.168.61.$((64+i*4+2)) d2:ad:ca:fe:b4:02
    done

    # tun side
    ip link add dev veth0 netns cloud address d2:ad:ca:fe:b4:03 type veth \
       peer name gtpptun address d2:f0:0c:ba:05:02
    ip -n cloud link set dev lo up
    ip -n cloud link set dev veth0 up
    ns_tun_dev=veth0
    if [ $tun_vlan -ne 0 ]; then
	ns_tun_dev=veth0.$tun_vlan
	ip -n cloud link add link veth0 name $ns_tun_dev type vlan id $tun_vlan
	ip -n cloud link set $ns_tun_dev up
    fi
    ip -n cloud addr add 192.168.61.129/30 dev $ns_tun_dev
    ip -n cloud tunnel add ptun mode ipip local 192.168.61.129 remote 192.168.61.130
    ip -n cloud link set ptun up
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1

    ip link set dev gtpptun up
    tun_dev=gtpptun
    if [ $tun_vlan -ne 0 ]; then
	tun_dev=gtpptun.$tun_vlan
	ip link add link gtpptun name $tun_dev type vlan id $tun_vlan
	ip link set $tun_dev up
    fi
    ip addr add 192.168.61.130/30 dev $tun_dev
    ip tunnel add ptun mode ipip local 192.168.61.130 remote 192.168.61.129 dev $tun_dev
    ip link set ptun up
    sysctl -q net.ipv4.conf.gtpptun.forwarding=1

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    arp -s 192.168.61.129 d2:ad:ca:fe:b4:03

    # tx-checksumming on means it is offloaded on nic.
    # on veth, it is done on the RX side, but after xdp hook. disable it.
    ip netns exec cloud ethtool -K $ns_tun_dev tx-checksumming off >/dev/null
    ip netns exec sgw ethtool -K sgw tx-checksumming off >/dev/null
    ip netns exec pgw ethtool -K pgw tx-checksumming off >/dev/null

    # remove vlan offload on veth
    ip netns exec cloud ethtool -K $ns_tun_dev tx-vlan-offload off
    ip netns exec cloud ethtool -K $ns_tun_dev rx-vlan-offload off
    ethtool -K gtpptun tx-vlan-offload off
    ethtool -K gtpptun rx-vlan-offload off

    # xdp prg must be loaded on the 2 side of veth pair.
    # enabling gro does it too
    ip netns exec cloud ethtool -K veth0 gro on
    ip netns exec pgw ethtool -K pgw gro on
    ip netns exec sgw ethtool -K sgw gro on
}

run_simple() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program fwd-1
no gtp-proxy all
"

    gtpg_conf "
bpf-program fwd-1
 path bin/gtp_fwd_mirror.bpf
 no shutdown

interface gtpp
 bpf-program fwd-1
 no shutdown
" || fail "cannot execute vty commands"

    gtpg_conf "
gtp-proxy gtpp-undertest
 bpf-program fwd-1
 gtpc-tunnel-endpoint 192.168.61.194 port 2123
 gtpu-tunnel-endpoint 192.168.61.1 port 2152 both-sides
 debug teid add 257 1 192.168.61.3 ingress
 debug teid add 258 2 192.168.61.2 egress

" || fail "cannot execute vty commands"

    gtpg_show "
show interface
show bpf forwarding
show interface-rule all
show interface-rule installed
"
}

run_combined() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program fwd-1
no gtp-proxy all
no mirror sig-dbg
"

    gtpg_conf "
bpf-program fwd-1
 path bin/gtp_fwd_mirror.bpf
 no shutdown

mirror sig-dbg
 bpf-program fwd-1
 ip-src-dst 192.168.61.129 port-src-dst 3000 protocol UDP interface ptun
 no shutdown

interface gtpp
 bpf-program fwd-1
 no shutdown

interface ptun
 no shutdown
" || fail "cannot execute vty commands"

    for i in `seq 0 $((gtp_proxy_count-1))`; do
	gtpg_conf "
gtp-proxy gtpp-undertest-$i
 bpf-program fwd-1
 gtpc-tunnel-endpoint 192.168.61.$((i+194)) port 2123
 gtpu-tunnel-endpoint 192.168.61.$((i*8+1)) port 2152 both-sides
 gtpu-ipip interface ptun view egress
 debug teid add $((i*10 + 257)) $((i*10 + 1)) 192.168.61.$((i*8+3)) ingress
 debug teid add $((i*10 + 258)) $((i*10 + 2)) 192.168.61.$((i*8+2)) egress
! debug teid add $((i*10 + 259)) $((i*10 + 3)) 192.168.61.$((i*8+5)) ingress
! debug teid add $((i*10 + 260)) $((i*10 + 4)) 192.168.61.$((i*8+4)) egress

" || fail "cannot execute vty commands"
    done

    gtpg_show "
show interface
show bpf forwarding
show interface-rule all
show interface-rule installed
"
}


run_vip() {
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program fwd-1
no gtp-proxy all
"

    gtpg_conf "
interface gtpp1.100
 no shutdown
 exit

bpf-program fwd-1
 path bin/gtp_fwd.bpf
 no shutdown

interface gtpp1
 bpf-program fwd-1
 no shutdown

interface gtpp2
 bpf-program fwd-1
 no shutdown

interface gtpp2.100
 no shutdown

interface ptun
 bpf-packet input disable-rule
 no shutdown
" || fail "cannot execute vty commands"

    for i in `seq 0 $((gtp_proxy_count-1))`; do
	gtpg_conf "
gtp-proxy gtpp-undertest-$i
 bpf-program fwd-1
 gtpc-tunnel-endpoint 192.168.61.$((i+240)) port 2123
 gtpu-tunnel-endpoint 192.168.61.$((i+176)) port 2152 both-sides
 gtpu-ipip interface ptun view egress
 debug teid add $((i*10 + 257)) $((i*10 + 1)) 192.168.61.$((210+i)) ingress
 debug teid add $((i*10 + 258)) $((i*10 + 2)) 192.168.61.$((192+i)) egress
 debug teid add $((i*10 + 261)) $((i*10 + 5)) 192.168.61.$((210+i)) ingress
 debug teid add $((i*10 + 262)) $((i*10 + 6)) 192.168.61.$((192+i)) egress

" || fail "cannot execute vty commands"
    done

    gtpg_show "
show interface
show bpf forwarding
show interface-rule all
show interface-rule installed
"
}



run_split() {
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program fwd-1
no gtp-proxy all
"

    gtpg_conf "
bpf-program fwd-1
 path bin/gtp_fwd.bpf
 no shutdown

interface pgw
 bpf-program fwd-1
 no shutdown

interface sgw
 bpf-program fwd-1
 no shutdown

interface gtpptun
 bpf-program fwd-1
 no shutdown

interface ptun
 no shutdown
" || fail "cannot execute vty commands"

    for i in `seq 0 $((gtp_proxy_count-1))`; do
	gtpg_conf "
gtp-proxy gtpp-undertest-$i
 bpf-program fwd-1
 gtpc-tunnel-endpoint 192.168.61.$((i+210)) port 2123
 gtpc-egress-tunnel-endpoint 192.168.61.$((i+194)) port 2123
 gtpu-tunnel-endpoint 192.168.61.$((64+i*4+1)) port 2152 ingress
 gtpu-tunnel-endpoint 192.168.61.$((i*4+1)) port 2152 egress
 gtpu-ipip interface ptun view egress
 debug teid add $((i*10 + 257)) $((i*10 + 1)) 192.168.61.$((i*4+2)) ingress
 debug teid add $((i*10 + 258)) $((i*10 + 2)) 192.168.61.$((64+i*4+2)) egress

" || fail "cannot execute vty commands"
    done

    gtpg_show "
show interface
show bpf forwarding
show interface-rule all
show interface-rule installed
"
}


#
# send a gtp-u packet that should do a full trip:
#  ingress -> egress -> ingress
#
pkt() {
    # gtp-proxy instance number to use
    inst=${1:-0}
    data=${2:-'Raw("DATADATA")]'}

    echo "run instance $inst, mode $type"

    pkt_count=1
    if [ $type == "split" ]; then
	ingress_ns=("sgw")
	egress_ns=("pgw")
	ingress_ip=192.168.61.$((64+inst*4+2))
	egress_ip=192.168.61.$((inst*4+2))
    elif [ $type == "combined" -o $type == "simple" ]; then
	ingress_ns=("cloud")
	egress_ns=("cloud")
	ingress_ip=192.168.61.$((inst*8+2))
	egress_ip=192.168.61.$((inst*8+3))
    elif [ $type == "vip" ]; then
	ingress_ns=("cloud" "cloud-r2")
	egress_ns=${ingress_ns[*]}
	ingress_ip=192.168.61.$((inst+192))
	egress_ip=192.168.61.$((inst+210))
	pkt_count=3
    else
	return
    fi

    if [ $type != "simple" -a $inst -eq 0 ]; then
	(
ip netns exec cloud python3 - <<EOF
from scapy.all import *
def receive(p):
  if IP in p and p[IP].proto == 4 and p[IP].dst == "192.168.61.129":
    # switch eth mac, ipip address, and send back
    tmp = p[IP].src
    p[IP].src = p[IP].dst
    p[IP].dst = tmp
    tmp = p[Ether].src
    p[Ether].src = p[Ether].dst
    p[Ether].dst = tmp
    #print("tun sending packet back src:%s dst:%s" % (p[IP].dst, p[IP].src))
    #print(p.summary())
    sendp(p, iface="veth0", verbose=0)
p = sniff(count=100, iface="veth0", filter=f"ip proto 4", prn=receive)
print("tun forwarder done")
EOF
	) &
	python_pid=$!
	echo "kill $python_pid 2> /dev/null" >> $tmp/cleanup.sh
    fi

    for ns in ${egress_ns[*]}; do
	(
ip netns exec $ns python3 - <<EOF
import socket
import struct
fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fd.bind(('$egress_ip', 2152))
for i in range(0, $pkt_count):
    data, remote = fd.recvfrom(8096)
    data = bytearray(data)
    teid = struct.unpack('!I', data[4:8])[0]
    rteid = (teid + 1) + 256
    print('PGW{$ns}: receive data len:%d, teid is 0x%08x, send back 0x%08x' %
       (len(data),teid,rteid))
    data[4:8] = struct.pack('!I', rteid)
    data = bytes(data)
    fd.sendto(data, remote)
fd.close()
EOF
	) &
	echo "kill $! 2> /dev/null" >> $tmp/cleanup.sh
    done

    for ns in ${ingress_ns[*]}; do
	(
ip netns exec $ns python3 - <<EOF
import socket
import struct
fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fd.bind(('$ingress_ip', 2152))
for i in range(0, $pkt_count):
    data, remote = fd.recvfrom(1024)
    data = bytearray(data)
    print('SGW{$ns}: DONE ! teid is 0x%08x' % struct.unpack('!I', data[4:8]))
fd.close()
EOF
	) &
	echo "kill $! 2> /dev/null" >> $tmp/cleanup.sh
    done

    sleep 1


    if [ $type == "combined" -o $type == "simple" ]; then
	send_py_pkt cloud veth0 "
p = [Ether(src='d2:ad:ca:fe:aa:01', dst='d2:f0:0c:ba:bb:01') /
  IP(src='$ingress_ip', dst='192.168.61.$((inst*8+1))') /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=$((inst*10+257)), gtp_type=255) /
  $data
"
    elif [ $type == "vip" ]; then
	send_py_pkt cloud veth0.100 "
p = [Ether(src='d2:ad:ca:fe:aa:01', dst='d2:f0:0c:ba:bb:01') /
  IP(src='$ingress_ip', dst='192.168.61.$((inst+176))') /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=$((inst*10+257)), gtp_type=255) /
  $data
"
	send_py_pkt cloud-r2 veth0.100 "
p = [Ether(src='d2:ad:ca:fe:aa:02', dst='d2:f0:0c:ba:bb:02') /
  IP(src='$ingress_ip', dst='192.168.61.$((inst+176))') /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=$((inst*10+261)), gtp_type=255) /
  $data
"
    else
	send_py_pkt sgw sgw "
p = [Ether(dst='d2:f0:0c:ba:a5:06', src='d2:ad:ca:fe:b4:02') /
  IP(src='$ingress_ip', dst='192.168.61.$((64+inst*4+1))') /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=$((inst*10+257)), gtp_type=255) /
  $data
"
    fi

    sleep 2
    echo "done"
}

# send a gtp-u packet on all instances
pkt_all() {
    for i in `seq 0 $((gtp_proxy_count-1))`; do
	pkt $i
    done
}

# send a fragmented gtp-u packet
pkt_frag() {
    pkt 0 '
  Raw("B" + "a" * 1800 + "E") ]
p = fragment(p, fragsize=1460)
# to send out of order
#p.insert(0, p.pop(1))
'
}

action=${1:-setup}
type=${2:-simple}
tun_vlan=${3:-0}
gtp_proxy_count=${4:-1}

if [ $gtp_proxy_count -gt 15 ]; then
    gtp_proxy_count=15
fi

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
    pkt_all)
	pkt_all ;;
    pkt_frag)
	pkt_frag ;;

    *) fail "action '$action' not recognized" ;;
esac
