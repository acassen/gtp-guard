#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh

clean()
{
    ip tunnel del ptun 2>/dev/null && true
    ip link del ptun 2>/dev/null && true
    ip link del gtpp 2>/dev/null && true
    clean_netns "sgw" "pgw" "cloud"
}

# everyone on the same interface
setup_combined()
{
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

    # pgw & sgw
    ip -n cloud addr add 192.168.61.1/30 dev veth0
    ip addr add 192.168.61.2/30 dev gtpp

    # data
    ip -n cloud addr add 192.168.61.4/30 dev veth0
    ip -n cloud addr add 192.168.61.5/30 dev veth0
    ip addr add 192.168.61.6/30 dev gtpp

    # tun
    ip -n cloud addr add 192.168.61.9/30 dev veth0
    ip -n cloud tunnel add ptun mode ipip local 192.168.61.9 remote 192.168.61.10
    ip -n cloud link set ptun up
    ip addr add 192.168.61.10/30 dev gtpp
    ip tunnel add ptun mode ipip local 192.168.61.10 remote 192.168.61.9 dev gtpp
    ip link set ptun up

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    arp -s 192.168.61.4 d2:ad:ca:fe:aa:01
    arp -s 192.168.61.5 d2:ad:ca:fe:aa:01
    arp -s 192.168.61.9 d2:ad:ca:fe:aa:01

    ip netns exec cloud ethtool -K veth0 gro on
}

# everyone on its own interface
setup_split() {
    setup_netns "sgw" "pgw" "cloud"
    sleep 0.5

    # sgw side
    ip link add dev sgw netns sgw address d2:ad:ca:fe:b4:02 type veth \
       peer name sgw address d2:f0:0c:ba:a5:06
    ip -n sgw link set dev sgw up
    ip -n sgw link set dev lo up
    ip -n sgw addr add 192.168.61.5/30 dev sgw
    ip link set dev sgw up
    ip addr add 192.168.61.6/30 dev sgw

    # pgw side
    ip link add dev pgw netns pgw address d2:ad:ca:fe:b4:01 type veth \
       peer name pgw address d2:f0:0c:ba:a5:02
    ip -n pgw link set dev pgw up
    ip -n pgw link set dev lo up
    ip -n pgw addr add 192.168.61.1/30 dev pgw
    ip -n pgw route add default via 192.168.61.2 dev pgw
    ip link set dev pgw up
    ip addr add 192.168.61.2/30 dev pgw

    # ptun side
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
    ip -n cloud addr add 192.168.61.9/30 dev $ns_tun_dev
    ip -n cloud tunnel add ptun mode ipip local 192.168.61.9 remote 192.168.61.10
    ip -n cloud link set ptun up
    ip netns exec cloud sysctl -q net.ipv4.conf.veth0.forwarding=1

    ip link set dev gtpptun up
    tun_dev=gtpptun
    if [ $tun_vlan -ne 0 ]; then
	tun_dev=gtpptun.$tun_vlan
	ip link add link gtpptun name $tun_dev type vlan id $tun_vlan
	ip link set $tun_dev up
    fi
    ip addr add 192.168.61.10/30 dev $tun_dev
    ip tunnel add ptun mode ipip local 192.168.61.10 remote 192.168.61.9 dev $tun_dev
    ip link set ptun up
    sysctl -q net.ipv4.conf.gtpptun.forwarding=1

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    arp -s 192.168.61.1 d2:ad:ca:fe:b4:01
    arp -s 192.168.61.5 d2:ad:ca:fe:b4:02
    arp -s 192.168.61.9 d2:ad:ca:fe:b4:03

    # fix weird thing with packet checksum sent from a
    # classic socket (eg SOCK_DGRAM).
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


run_combined() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf "
bpf-program fwd-1
 path bin/gtp_fwd.bpf
 no shutdown

gtp-proxy gtpp-undertest
 bpf-program fwd-1
 gtpc-tunnel-endpoint 192.168.61.2 port 2123
 gtpu-tunnel-endpoint 192.168.61.6 both-side interface gtpp
 gtpu-ipip interface ptun view egress

interface gtpp
 bpf-program fwd-1
 no shutdown

interface ptun
 no shutdown

gtp-proxy gtpp-undertest
 gtpu-ipip debug teid add 257 1 192.168.61.5 ingress
 gtpu-ipip debug teid add 258 2 192.168.61.4 egress

" || fail "cannot execute vty commands"

    gtpg_show "
show interface
show bpf forwarding
show interface-rules
"
}

run_split() {
    start_gtpguard

    gtpg_conf "
bpf-program fwd-1
 path bin/gtp_fwd.bpf
 no shutdown

gtp-proxy gtpp-undertest
 bpf-program fwd-1
 gtpc-tunnel-endpoint 192.168.61.6 port 2123
 gtpc-egress-tunnel-endpoint 192.168.61.2 port 2123
 gtpu-tunnel-endpoint 192.168.61.6 ingress interface sgw
 gtpu-tunnel-endpoint 192.168.61.2 egress interface pgw
 gtpu-ipip interface ptun view egress

interface sgw
 bpf-program fwd-1
 no shutdown

interface pgw
 bpf-program fwd-1
 no shutdown

interface gtpptun
 bpf-program fwd-1
 no shutdown

interface ptun
 no shutdown

gtp-proxy gtpp-undertest
 gtpu-ipip debug teid add 257 1 192.168.61.1 ingress
 gtpu-ipip debug teid add 258 2 192.168.61.5 egress

" || fail "cannot execute vty commands"

    gtpg_show "
show interface
show bpf forwarding
show interface-rules
"
}


#
# send a gtp-u packet that should do a full trip:
#  ingress -> egress -> ingress
#
pkt() {
    if [ "$type" == "split" ]; then
	ingress_ns=sgw
	ingress_ip=192.168.61.5
	egress_ns=pgw
	egress_ip=192.168.61.1
    elif [ "$type" == "combined" ]; then
	ingress_ns=cloud
	ingress_ip=192.168.61.4
	egress_ns=cloud
	egress_ip=192.168.61.5
    else
	return
    fi

    (
ip netns exec cloud python3 - <<EOF
from scapy.all import *
def receive(p):
  if IP in p and p[IP].proto == 4 and p[IP].dst == "192.168.61.9":
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
p = sniff(count=8, iface="veth0", filter=f"ip proto 4", prn=receive)
print("tun forwarder done")
EOF
    ) &
    python_pid=$!

    (
ip netns exec $egress_ns python3 - <<EOF
import socket
import struct
fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fd.bind(('$egress_ip', 2152))
data, remote = fd.recvfrom(1024)
data = bytearray(data)
print('PGW: receive data, teid is 0x%08x' % struct.unpack('!I', data[4:8]))
data[4:8] = struct.pack('!I', 258)
data = bytes(data)
fd.sendto(data, remote)
fd.close()
EOF
    ) &
    python2_pid=$!

    (
ip netns exec $ingress_ns python3 - <<EOF
import socket
import struct
fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fd.bind(('$ingress_ip', 2152))
data, remote = fd.recvfrom(1024)
data = bytearray(data)
print('SGW: DONE ! teid is 0x%08x' % struct.unpack('!I', data[4:8]))
fd.close()
EOF
    ) &
    python3_pid=$!

    cat >> $tmp/cleanup.sh <<EOF
kill $python_pid 2> /dev/null
kill $python2_pid 2> /dev/null
kill $python3_pid 2> /dev/null
EOF
    sleep 1

    
    if [ "$type" == "combined" ]; then
	send_py_pkt cloud veth0 '
p = [Ether(src="d2:ad:ca:fe:aa:01", dst="d2:f0:0c:ba:bb:01") /
  IP(src="192.168.61.4", dst="192.168.61.6") /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=257, gtp_type=255) /
  Raw("DATADATA")]
'
    else
	send_py_pkt sgw sgw '
p = [Ether(dst="d2:f0:0c:ba:a5:06", src="d2:ad:ca:fe:b4:02") /
  IP(src="192.168.61.5", dst="192.168.61.6") /
  UDP(sport=2152, dport=2152) /
  GTP_U_Header(teid=257, gtp_type=255) /
  Raw("DATADATA")]
'
    fi

    sleep 2
    echo "done, exit"

}

action=${1:-setup}
type=${2:-combined}
tun_vlan=200

case $action in
    setup)
	clean
	sleep 0.5
	setup_$type ;;
    clean)
	clean ;;
    run)
	clean
	sleep 0.5
	setup_$type
	run_$type ;;
    pkt)
	pkt ;;

    *) fail "action '$action' not recognized" ;;
esac
