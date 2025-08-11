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
#                                      ip 8.8.8.8 (simulate a server)
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
# how to use:
#   after this script is run, execute these commands in 2 terminals:
#    # sudo ./bin/gtp-guard -l -D -n -f /tmp/cgn-test.conf
#    # sudo ip netns exec cgn-priv ping -c 1 8.8.8.8
#

set -e
set -x

setup_netns "cgn-pub" "cgn-priv"

# pub side
ip link add dev pub netns cgn-pub address d2:ad:ca:fe:b4:01 type veth \
   peer name pub address d2:f0:0c:ba:a5:00
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

# priv side
ip link add dev priv netns cgn-priv address d2:ad:ca:fe:b4:02 type veth \
   peer name priv address d2:f0:0c:ba:a5:01
ip link add link priv name priv.20 type vlan id 20
ip -n cgn-priv link add link priv name priv.20 type vlan id 20
ip -n cgn-priv link set dev priv up
ip -n cgn-priv link set dev priv.20 up
ip -n cgn-priv link set dev lo up
ip -n cgn-priv addr add 192.168.61.1/30 dev priv.20
ip -n cgn-priv addr add 20.0.0.1/8 dev priv.20
ip -n cgn-priv route add default via 192.168.61.2 dev priv.20
ip link set dev priv up
ip link set dev priv.20 up
ip addr add 192.168.61.2/30 dev priv.20

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

# xdp prg must be loaded on the 2 side of veth pair.
# enabling gro does it too
ip netns exec cgn-pub ethtool -K pub gro on
ip netns exec cgn-priv ethtool -K priv gro on

gtpg_cmd "
carrier-grade-nat toto
 description trop_bien
 ipv4-pool 37.142.0.0/24

bpf-program cgn
 path bin/cgn.bpf
 no shutdown

interface priv.20
 description priv_itf
 bpf-program cgn
 carrier-grade-nat toto side network-in
 no shutdown

interface pub.10
 description pub_itf
 bpf-program cgn
 carrier-grade-nat toto side network-out
 no shutdown
" || fail "cannot execute vty commands"
