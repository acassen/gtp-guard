#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh


#
# simplified cgn scenario with vlan on each veth.
# this script set up environement, netns and ip, then configure
# running gtp-guard.
#
#
# |-------------------------|              |-----------------------|
# |  priv (netns cgn-priv)  |              |  pub (netns cgn-pub)  |
# |  priv.20                |              |  pub.10
# |-------------------------|              |-----------------------|
#   ip 192.168.61.1/30 (connected)     ip 192.168.61.5/30 (connected)
#   ip 10.0.0.1 (simulate a user)      ip 8.8.8.8 (simulate a server)
#          |                                         |
#          | veth pair                               | veth pair
#          |                                         |
# |-------------------------|              |-----------------------|
# |   priv (XDP, gtp-guard) |   <----->    |  pub (XDP, gtp-guard) |
# |   priv.20               |              |  pub.10               |
# |-------------------------|              |-----------------------|
#    ip 192.168.61.2/30 (connected)      ip 192.168.61.6/30 (connected)
#
# the same cgn application is loaded on 'priv' and 'pub' by gtp-guard.
# ip address are set on vlan interfaces.
#
# how to use:
#   before executing this script
#    # sudo ./bin/gtp-guard -l -D -n -f test/conf/minimal.conf
#
#   after this script is run, execute
#    # sudo ip netns exec cgn-priv ping -I 10.0.0.1 -c 1 8.8.8.8
#


setup_netns "cgn-pub" "cgn-priv"
sleep 0.5

# pub side
ip link add dev pub netns cgn-pub address d2:ad:ca:fe:b4:05 type veth \
   peer name pub address d2:f0:0c:ba:a5:06
ip link add link pub name pub.10 type vlan id 10
ip -n cgn-pub link add link pub name pub.10 type vlan id 10
ip -n cgn-pub link set dev pub up
ip -n cgn-pub link set dev pub.10 up
ip -n cgn-pub link set dev lo up
ip -n cgn-pub addr add 192.168.61.5/30 dev pub.10
ip -n cgn-pub addr add 8.8.8.8/32 dev pub.10
ip -n cgn-pub route add 37.141.0.0/24 via 192.168.61.6 dev pub.10
ip link set dev pub up
ip link set dev pub.10 up
ip addr add 192.168.61.6/30 dev pub.10
ip route add default via 192.168.61.5 dev pub.10 table 1310

# priv side
ip link add dev priv netns cgn-priv address d2:ad:ca:fe:b4:01 type veth \
   peer name priv address d2:f0:0c:ba:a5:02
ip link add link priv name priv.20 type vlan id 20
ip -n cgn-priv link add link priv name priv.20 type vlan id 20
ip -n cgn-priv link set dev priv up
ip -n cgn-priv link set dev priv.20 up
ip -n cgn-priv link set dev lo up
ip -n cgn-priv addr add 192.168.61.1/30 dev priv.20
ip -n cgn-priv addr add 10.0.0.1/8 dev priv.20
ip -n cgn-priv route add default via 192.168.61.2 dev priv.20
ip link set dev priv up
ip link set dev priv.20 up
ip addr add 192.168.61.2/30 dev priv.20
ip route add 10.0.0.0/8 via 192.168.61.1 dev priv.20 table 1320
ip route add 37.141.0.0/24 via 192.168.61.1 dev priv.20 table 1320

# bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
# so add static entries
arp -s 192.168.61.1 d2:ad:ca:fe:b4:01
arp -s 192.168.61.5 d2:ad:ca:fe:b4:05

# this script also serve for ip6fw test
ip -n cgn-pub addr add fc:1::2/64 dev pub.10
ip -n cgn-pub addr add 2001::8:8:8:8/128 dev pub.10
ip -n cgn-pub route add 2002::1/16 via fc:1::1 dev pub.10
ip -n cgn-priv addr add fc:1::1/64 dev priv.20
ip -n cgn-priv route add default via fc:1::2 dev priv.20

# fix weird thing with packet checksum sent from a
# classic socket (eg SOCK_DGRAM).
ip netns exec cgn-pub ethtool -K pub tx-checksumming off >/dev/null
ip netns exec cgn-priv ethtool -K priv tx-checksumming off >/dev/null

# remove vlan offload
ip netns exec cgn-pub ethtool -K pub tx-vlan-offload off
ip netns exec cgn-priv ethtool -K priv tx-vlan-offload off
ethtool -K pub rx-vlan-offload off
ethtool -K priv rx-vlan-offload off

# xdp prg must be loaded on the 2 side of veth pair.
# enabling gro does it too
ip netns exec cgn-pub ethtool -K pub gro on
ip netns exec cgn-priv ethtool -K priv gro on

gtpg_conf "
bpf-program cgn-ng-1
 path bin/cgn.bpf
 no shutdown

carrier-grade-nat cgn-ng-1
 description doit_avoir_le_meme_nom_que_le_prog_bpf
 ipv4-pool 37.141.0.0/24

interface priv
 bpf-program cgn-ng-1
 no shutdown

interface priv.20
 description priv_itf
 parent priv
 ip table 1310
 carrier-grade-nat cgn-ng-1 side network-in
 no shutdown

interface pub
 bpf-program cgn-ng-1
 no shutdown

interface pub.10
 description pub_itf
 parent pub
 ip table 1320
 carrier-grade-nat cgn-ng-1 side network-out
 no shutdown
" || fail "cannot execute vty commands"

gtpg_show "
show interface
"
