#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet


. $(dirname $0)/_gtpg_cmd.sh

#
# simplified cgn scenario, with minimal configuration.
# this script set up environement, netns and ip. to be run once.
#
#
# |-------------------------|              |-----------------------|
# |  priv (netns cgn-priv)  |              |  pub (netns cgn-pub)  |
# |-------------------------|              |-----------------------|
#   ip 192.168.61.1/30 (connected)     ip 192.168.61.5/30 (connected)
#   ip 10.0.0.1 (simulate a user)      ip 8.8.8.8 (simulate a server)
#          |                                         |
#          | veth pair                               | veth pair
#          |                                         |
# |-------------------------|              |-----------------------|
# |   priv (XDP, gtp-guard) |   <----->    |  pub (XDP, gtp-guard) |
# |-------------------------|              |-----------------------|
#    ip 192.168.61.2/30 (connected)      ip 192.168.61.6/30 (connected)
#
# the same cgn application is loaded on 'priv' and 'pub' by gtp-guard.
#
# here is processing for packets
# - TX on priv iface (in ns)            IP{ src=10.0.0.1, dst=8.8.8.8 }
# - RX on priv, catched by xdp  
# - XDP inspect/modify packet, create/check flows,
#   then XDP_REDIRECT the result on pub IP{ src=37.141.0.1 dst=8.8.8.8 }
# - pub itf in netns receive packet, and TX an icmp-reply
# - RX on pub, catched by xdp
# - XDP inspect/modify packet, check flows,
#   then XDP_REDIRECT the result on priv IP{ src=8.8.8.8 dst=10.0.0.1 }
#

setup() {
    setup_netns "cgn-pub" "cgn-priv"

    # let system some time to setup ns
    sleep 0.5

    # pub side
    ip link add dev pub netns cgn-pub address d2:ad:ca:fe:b4:05 type veth \
       peer name pub address d2:f0:0c:ba:a5:06
    ip -n cgn-pub link set dev pub up
    ip -n cgn-pub link set dev lo up
    ip -n cgn-pub addr add 192.168.61.5/30 dev pub
    ip -n cgn-pub addr add 8.8.8.8/32 dev pub
    ip -n cgn-pub route add 37.141.0.0/24 via 192.168.61.6 dev pub
    ip link set dev pub up
    ip addr add 192.168.61.6/30 dev pub
    ip route add default via 192.168.61.5 dev pub table 1290

    # priv side
    ip link add dev priv netns cgn-priv address d2:ad:ca:fe:b4:01 type veth \
       peer name priv address d2:f0:0c:ba:a5:02
    ip -n cgn-priv link set dev priv up
    ip -n cgn-priv link set dev lo up
    ip -n cgn-priv addr add 192.168.61.1/30 dev priv
    ip -n cgn-priv addr add 10.0.0.1/8 dev priv
    ip -n cgn-priv route add default via 192.168.61.2 dev priv
    ip link set dev priv up
    ip addr add 192.168.61.2/30 dev priv
    ip route add 10.0.0.0/8 via 192.168.61.1 dev priv table 1290
    ip route add 37.141.0.0/24 via 192.168.61.1 dev priv table 1290

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    arp -s 192.168.61.1 d2:ad:ca:fe:b4:01
    arp -s 192.168.61.5 d2:ad:ca:fe:b4:05

    # this script also serve for ip6fw test
    ip -n cgn-pub addr add fc:1::2/64 dev pub
    ip -n cgn-pub addr add 2001::8:8:8:8/128 dev pub
    ip -n cgn-pub route add 2002::1/16 via fc:1::1 dev pub
    ip -n cgn-priv addr add fc:1::1/64 dev priv
    ip -n cgn-priv route add default via fc:1::2 dev priv

    # fix weird thing with packet checksum sent from a
    # classic socket (eg SOCK_DGRAM).
    ip netns exec cgn-pub ethtool -K pub tx-checksumming off >/dev/null
    ip netns exec cgn-priv ethtool -K priv tx-checksumming off >/dev/null

    # xdp prg must be loaded on the 2 side of veth pair.
    # enabling gro does it too
    ip netns exec cgn-pub ethtool -K pub gro on
    ip netns exec cgn-priv ethtool -K priv gro on
}

#
# gtp-guard must either:
#  - be manually started (in another console, optionally with
#    valgrind, gdb, ...):
#    # sudo ./bin/gtp-guard -l -D -n -f test/conf/minimal.conf
#  - started by this function
#
# this function will configure gtp-guard and run a ping.
#
run() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf "
cdr-fwd cgn
 spool-path /tmp/spool
 instance-id 2
 remote 127.0.0.1:1900
 no shutdown

bpf-program cgn	
 path bin/cgn.bpf
 no shutdown

carrier-grade-nat cgn
 description trop_bien
 ipv4-pool 37.141.0.0/24
 cdr-fwd cgn

interface priv
 description priv_itf
 bpf-program cgn
 carrier-grade-nat cgn side network-in
 ip route table-id 1290
 no shutdown

interface pub
 description pub_itf
 bpf-program cgn
 carrier-grade-nat cgn side network-out
 ip route table-id 1290
 no shutdown
" || fail "cannot execute vty commands"

    gtpg_show "
show interface
"

    ip netns exec cgn-priv ping -c 1 -I 10.0.0.1 8.8.8.8

    gtpg_show "
show carrier-grade-nat flows 10.0.0.1
"

}


pkt() {
    ip netns exec cgn-priv ping -c 1 -I 10.0.0.1 8.8.8.8
    echo tata | ip netns exec cgn-priv nc -s 10.0.0.1 8.8.8.8  9000
    echo toto | ip netns exec cgn-priv nc -u -s 10.0.0.1 8.8.8.8 9000

    gtpg_show "
show carrier-grade-nat flows 10.0.0.1
"

}


action=${1:-setup}

case $action in
    setup)
	setup ;;
    clean)
	clean_netns "cgn-pub" "cgn-priv" ;;
    run)
	setup
	run ;;
    pkt)
	pkt ;;


    *) fail "action '$action' not recognized" ;;
esac
