#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh


#
# cgn scenario with gre tunnel, than match as closely as possible production environment.
# this script set up environement, netns and ip, then configure running gtp-guard.
#
#         netns router-priv
# |------------------------------|               |------------------------------|
# |  priv (gre tunnel)           |               |                              |
# |  veth0                       |               |  gre-priv (gre tunnel)       |
# |------------------------------|               |------------------------------|
#   inner ip 192.168.62.1/30                      inner ip 192.168.62.2/30
#   ip 10.0.0.1 (simulate a user)
#   ip 192.168.61.6/30 (connected)
#          |                                               |
#          | veth pair                                     |
#          |                                               |
#          |  netns router                                 |
# |------------------------------|   veth pair   |------------------------------|
# |  router-priv                 | <-----------> |  virt-veth0 (XDP, gtp-guard) |
# |  router                      |               |                              |
# |------------------------------|               |------------------------------|
#   ip 192.168.61.1/30 (connected)               ip 192.168.61.2/30 (connected)
#   ip 192.168.61.5/30 (connected)
#   ip 8.8.8.8 (simulate a server)
#
#
# xdp program is loaded on interface 'virt-veth0', and aslo get packets for gre
# tunnel 'gre-priv'. virt-veth0 and gre-priv are not on specific netns.
#
# standard linux routing applies on 'router' side. 'public' is on router interface/netns,
# 'private' is in its own netns router-priv, with an additional veth between netns router
# and router-priv
#

setup() {
    setup_netns "router" "router-priv"
    ip tunnel del gre-priv 2>/dev/null && true
    sleep 0.5

    # the 'trunk' between router and cgn server
    ip link add dev router netns router address d2:2d:ca:fe:04:01 type veth \
       peer name virt-eth0 address d2:f0:0c:ba:05:02

    # --- on router side ---
    ip link add dev router-priv netns router address d2:2d:ca:cc:cc:01 type veth \
       peer name veth0 netns router-priv address d2:f0:0c:cc:cc:02
    ip -n router link set dev lo up
    ip -n router link set dev router up
    ip -n router addr add 192.168.61.1/30 dev router
    ip -n router addr add 8.8.8.8/32 dev router
    ip -n router route add 37.141.0.0/24 via 192.168.61.2 dev router
    ip -n router link set dev router-priv up
    ip -n router addr add 192.168.61.5/30 dev router-priv

    ip -n router-priv link set lo up
    ip -n router-priv link set veth0 up
    ip -n router-priv addr add 192.168.61.6/30 dev veth0
    ip -n router-priv route add 192.168.61.0/30 via 192.168.61.5 dev veth0
    ip -n router-priv tunnel add priv mode gre local 192.168.61.6 remote 192.168.61.2
    ip -n router-priv link set priv up
    ip -n router-priv addr add 192.168.62.1/30 dev priv
    ip -n router-priv addr add 10.0.0.1/8 dev priv
    ip -n router-priv route add default via 192.168.62.2 dev priv
    ip netns exec router sysctl -q net.ipv4.conf.router.forwarding=1
    ip netns exec router sysctl -q net.ipv4.conf.router-priv.forwarding=1

    # --- on server side ---
    ip link set dev virt-eth0 up
    ip addr add 192.168.61.2/30 dev virt-eth0
    ip route add 192.168.61.4/30 via 192.168.61.1 dev virt-eth0
    sysctl -q net.ipv4.conf.virt-eth0.forwarding=1

    # pub side
    ip route add default via 192.168.61.1 dev virt-eth0 table 1310

    # priv side
    ip tunnel add gre-priv mode gre local 192.168.61.2 remote 192.168.61.6 dev virt-eth0
    ip link set gre-priv up
    ip addr add 192.168.62.2/30 dev gre-priv
    ip route add 192.168.61.4/30 via 192.168.61.1 dev virt-eth0 table 1320

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    # arp -s 192.168.61.1 d2:2d:ca:fe:04:01
    # arp -s 192.168.61.5 d2:2d:ca:fe:04:01

    # this script also serve for ip6fw test
    # ip -n router-pub addr add fc:1::1/64 dev pub.10
    # ip -n router-pub addr add 2001::8:8:8:8/128 dev pub.10
    # ip -n router-pub route add 2002::1/16 via fc:1::2 dev pub.10
    # ip addr add fc:1::2/64 dev pub.10
    # ip -n router-priv addr add fc:2::1/64 dev priv.20
    # ip -n router-priv route add default via fc:2::2 dev priv.20
    # ip addr add fc:2::2/64 dev priv.20

    # fix weird thing with packet checksum sent from a
    # classic socket (eg SOCK_DGRAM).
    ip netns exec router ethtool -K router tx-checksumming off >/dev/null

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
bpf-program cgn-ng-1
 path bin/cgn.bpf
 no shutdown

carrier-grade-nat cgn-ng-1
 description doit_avoir_le_meme_nom_que_le_prog_bpf
 ipv4-pool 37.141.0.0/24

interface virt-eth0
 description internet_connection
 bpf-program cgn-ng-1
 ip route table-id 1320
 carrier-grade-nat cgn-ng-1 side network-out
 no shutdown

interface gre-priv
 description priv_itf_on_gre_tunnel
 ip route table-id 1310
 carrier-grade-nat cgn-ng-1 side network-in
 no shutdown
" || fail "cannot execute vty commands"

    gtpg_show "
show interface
"

    ip netns exec router-priv ping -c 1 -I 10.0.0.1 8.8.8.8
}


action=${1:-setup}

case $action in
    setup)
	setup ;;
    clean)
	clean_netns "router" "router-priv" ;;
    run)
	setup
	run ;;

    *) fail "action '$action' not recognized" ;;
esac
