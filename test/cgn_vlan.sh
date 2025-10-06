#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh


#
# cgn scenario with vlan, than match as closely as possible production environment.
# this script set up environement, netns and ip, then configure/start gtp-guard.
#
#
# |------------------------------|               |---------------------------|
# |  priv.20 (netns router-priv) |               |  priv.20                  |
# |------------------------------|               |---------------------------|
#   ip 192.168.61.1/30 (connected)               ip 192.168.61.2/30 (connected)
#   ip 10.0.0.1 (simulate a user)
#          |                                               |
#          |                                               |
# |------------------------------|   veth pair   |---------------------------|
# | router (netns router)        | <-----------> |  cgn (XDP, gtp-guard)     |
# |------------------------------|               |---------------------------|
#    'phy' interface (router)                        'phy' interface (cgn)
#         |				                   |
#	  |			                           |
# |------------------------------|               |---------------------------|
# |  pub.10 (netns router-pub)   |               |  pub.10                   |
# |------------------------------|               |---------------------------|
#   ip 192.168.61.5/30 (connected)               ip 192.168.61.6/30 (connected)
#   ip 8.8.8.8 (simulate a server)
#
#
# xdp program is only loaded on (what should be phy on a real setup) interface 'cgn',
# and steal packets for vlan 10 and 20. 'cgn', 'pub.10' and 'priv.20' are not bound
# to specific netns.
#
# standard linux routing applies on 'router' side, each interface is on its own netns.
#

setup() {
    setup_netns "router" "router-priv" "router-pub"
    sleep 0.5

    # the 'trunk' between router and cgn server
    ip link add dev router netns router address d2:2d:ca:fe:04:01 type veth \
       peer name virt-eth0 address d2:f0:0c:ba:05:02

    # --- on router side ---
    ip -n router link add link router name pub.10 netns router-pub type vlan id 10
    ip -n router link add link router name priv.20 netns router-priv type vlan id 20
    ip -n router link set dev lo up
    ip -n router link set dev router up
    ip -n router-pub link set dev lo up
    ip -n router-pub link set dev pub.10 up
    ip -n router-pub addr add 192.168.61.5/30 dev pub.10
    ip -n router-pub addr add 8.8.8.8/32 dev pub.10
    ip -n router-pub route add 37.141.0.0/24 via 192.168.61.6 dev pub.10
    ip -n router-priv link set dev lo up
    ip -n router-priv link set dev priv.20 up
    ip -n router-priv addr add 192.168.61.1/30 dev priv.20
    ip -n router-priv addr add 10.0.0.1/8 dev priv.20
    ip -n router-priv route add default via 192.168.61.2 dev priv.20
    ip netns exec router sysctl -q net.ipv4.conf.router.forwarding=1

    # --- on server side ---
    ip link set dev virt-eth0 up
    sysctl -q net.ipv4.conf.virt-eth0.forwarding=1

    # pub side
    ip link add link virt-eth0 name pub.10 type vlan id 10
    ip link set dev pub.10 up
    ip addr add 192.168.61.6/30 dev pub.10
    ip route add default via 192.168.61.5 dev pub.10 table 1310

    # priv side
    ip link add link virt-eth0 name priv.20 type vlan id 20
    ip link set dev priv.20 up
    ip addr add 192.168.61.2/30 dev priv.20
    ip route add 10.0.0.0/8 via 192.168.61.1 dev priv.20 table 1320
    ip route add 37.141.0.0/24 via 192.168.61.1 dev priv.20 table 1320

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    arp -s 192.168.61.1 d2:2d:ca:fe:04:01
    arp -s 192.168.61.5 d2:2d:ca:fe:04:01

    # this script also serve for ip6fw test
    ip -n router-pub addr add fc:1::1/64 dev pub.10
    ip -n router-pub addr add 2001::8:8:8:8/128 dev pub.10
    ip -n router-pub route add 2002::1/16 via fc:1::2 dev pub.10
    ip addr add fc:1::2/64 dev pub.10
    ip -n router-priv addr add fc:2::1/64 dev priv.20
    ip -n router-priv route add default via fc:2::2 dev priv.20
    ip addr add fc:2::2/64 dev priv.20

    # fix weird thing with packet checksum sent from a
    # classic socket (eg SOCK_DGRAM).
    ip netns exec router-pub ethtool -K pub.10 tx-checksumming off >/dev/null
    ip netns exec router-priv ethtool -K priv.20 tx-checksumming off >/dev/null

    # remove vlan offload on veth
    ip netns exec router ethtool -K router tx-vlan-offload off
    ip netns exec router ethtool -K router rx-vlan-offload off
    ethtool -K virt-eth0 tx-vlan-offload off
    ethtool -K virt-eth0 rx-vlan-offload off

    # xdp prg must be loaded on the 2 side of veth pair.
    # enabling gro does it too
    ip netns exec router ethtool -K router gro on
}

run() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf "
carrier-grade-nat cgn-ng-1
 description doit_avoir_le_meme_nom_que_le_prog_bpf
 ipv4-pool 37.141.0.0/24

bpf-program cgn-ng-1
 path bin/cgn.bpf
 no shutdown

interface virt-eth0
 bpf-program cgn-ng-1
 no shutdown

interface priv.20
 description priv_itf
 ip route table-id 1310
 carrier-grade-nat cgn-ng-1 side network-in
 no shutdown

interface pub.10
 description pub_itf
 ip route table-id 1320
 carrier-grade-nat cgn-ng-1 side network-out
 no shutdown
" || fail "cannot execute vty commands"

    gtpg_show "
show interface
"

    sudo ip netns exec router-priv ping -c 1 -I 10.0.0.1 8.8.8.8
}

action=${1:-setup}

case $action in
    setup)
	setup ;;
    clean)
	clean_netns "router" "router-priv" "router-pub" ;;
    run)
	setup
	run ;;

    *) fail "action '$action' not recognized" ;;
esac
