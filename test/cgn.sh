#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet


. $(dirname $0)/_gtpg_cmd.sh

clean() {
    ip tunnel del gre-priv 2>/dev/null && true
    clean_netns "cgn-pub" "cgn-priv" "router" "router-priv" "router-pub"
}

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

setup_iface() {
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
    ip neigh add 192.168.61.1 lladdr d2:ad:ca:fe:b4:01 dev priv
    ip neigh add 192.168.61.5 lladdr d2:ad:ca:fe:b4:05 dev pub
    sysctl -q net.ipv4.conf.priv.forwarding=1
    sysctl -q net.ipv4.conf.pub.forwarding=1

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
# simplified cgn scenario with vlan on each veth.
# this script set up environement, netns and ip, and can run/configure
# gtp-guard.
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

setup_iface_vlan() {
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
    for vlan in `seq 20 24`; do
	ip link add link priv name priv.$vlan type vlan id $vlan
	ip -n cgn-priv link add link priv name priv.$vlan type vlan id $vlan
	ip -n cgn-priv link set dev priv up
	ip -n cgn-priv link set dev priv.$vlan up
	ip -n cgn-priv link set dev lo up
	ip -n cgn-priv addr add 192.168.61.1/30 dev priv.$vlan
	ip -n cgn-priv addr add 10.0.0.1/8 dev priv.$vlan
	ip link set dev priv up
	ip link set dev priv.$vlan up
	ip addr add 192.168.61.2/30 dev priv.$vlan
	ip neigh add 192.168.61.1 lladdr d2:ad:ca:fe:b4:01 dev priv.$vlan
    done
    ip -n cgn-priv route add default via 192.168.61.2 dev priv.20
    ip route add 10.0.0.0/8 via 192.168.61.1 dev priv.20 table 1320
    ip route add 37.141.0.0/24 via 192.168.61.1 dev priv.20 table 1320

    ip neigh add 192.168.61.5 lladdr d2:ad:ca:fe:b4:05 dev pub.10
    sysctl -q net.ipv4.conf.priv.forwarding=1
    sysctl -q net.ipv4.conf.pub.forwarding=1

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
}



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

setup_vlan() {
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
    ip neigh add 192.168.61.1 lladdr d2:2d:ca:fe:04:01 dev priv.20
    ip neigh add 192.168.61.5 lladdr d2:2d:ca:fe:04:01 dev pub.10

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

setup_gre() {
    setup_netns "router" "router-priv"
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
    ip tunnel add gre-priv mode gre local 192.168.61.2 remote 192.168.61.6
    ip link set gre-priv up
    ip addr add 192.168.62.2/30 dev gre-priv
    ip route add default via 192.168.62.1 dev gre-priv table 1320
    ip route add 192.168.61.4/30 via 192.168.61.1 dev virt-eth0 table 1320
    sysctl -q net.ipv4.conf.gre-priv.forwarding=1

    # bpf_fib_lookup doesn't start arp'ing if there is no neigh entry,
    # so add static entries
    # ip neigh add 192.168.61.1 d2:2d:ca:fe:04:01
    # ip neigh add 192.168.61.5 d2:2d:ca:fe:04:01

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


############################ RUN IFACE #################################

#
# gtp-guard is either:
#  - manually started (in another console, optionally with
#    valgrind, gdb, ...):
#    # sudo ./bin/gtp-guard -l -D -n -f test/conf/minimal.conf
#  - started by this function
#
# this function will configure gtp-guard and run a ping.
#
run_iface() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no carrier-grade-nat cgn-ng-1
no bpf-program cgn
no cdr-fwd cgn
"

    gtpg_conf "
cdr-fwd cgn
 spool-path /tmp/spool
 instance-id 2
 remote 127.0.0.1:1900
! no shutdown

bpf-program cgn
 path bin/cgn.bpf
 no shutdown

carrier-grade-nat cgn-ng-1
 description trop_bien
 bpf-program cgn
 ipv4-pool 37.141.0.0/24
 protocol timeout icmp 2
 protocol timeout udp 2
 interface ingress priv
 interface egress pub
! cdr-fwd cgn

interface priv
 description priv_itf
 bpf-program cgn
 ip route table-id 1290
 no shutdown

interface pub
 description pub_itf
 bpf-program cgn
 ip route table-id 1290
 no shutdown

" || fail "cannot execute vty commands"

    ip netns exec cgn-priv ping -c 1 -W 2 -I 10.0.0.1 8.8.8.8

    gtpg_show "
show carrier-grade-nat config
show carrier-grade-nat flows 10.0.0.1
"
}


############################ RUN IFACE VLAN #################################

run_iface_vlan() {
    start_gtpguard

    gtpg_conf_nofail "
no carrier-grade-nat cgn-ng-1
no cdr-fwd cgn
no bpf-program cgn-ng-1
"

    gtpg_conf "
bpf-program cgn-ng-1
 path bin/cgn.bpf
 no shutdown

carrier-grade-nat cgn-ng-1
 bpf-program cgn-ng-1
 description doit_avoir_le_meme_nom_que_le_prog_bpf
 ipv4-pool 37.141.0.0/24
 interface ingress priv.20 priv.21 priv.22 priv.23
 interface egress pub.10

interface priv.20
 ip route table-id 1310
 no shutdown

interface priv.21
 ip route table-id 1310
 no shutdown

interface priv
 bpf-program cgn-ng-1
 no shutdown

interface priv.22
 ip route table-id 1310
 no shutdown

interface priv.23
 ip route table-id 1310
 no shutdown

interface pub
 bpf-program cgn-ng-1
 no shutdown

interface pub.10
 description pub_itf
 ip route table-id 1320
 no shutdown
" || fail "cannot execute vty commands"

    ip netns exec cgn-priv ping -c 1 -W 2 -I 10.0.0.1 8.8.8.8

    gtpg_show "
show interface
show carrier-grade-nat flows 10.0.0.1
show interface-rule all
"
}


############################ RUN VLAN #################################

run_vlan() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program cgn-ng-1
no carrier-grade-nat cgn-ng-1
no cdr-fwd cgn
"

    gtpg_conf "
bpf-program cgn-ng-1
 path bin/cgn.bpf
 no shutdown

carrier-grade-nat cgn-ng-1
 description doit_avoir_le_meme_nom_que_le_prog_bpf
 bpf-program cgn-ng-1
 ipv4-pool 37.141.0.0/24
! interface ingress priv.20
! interface egress pub.10

interface priv.20
 description priv_itf
 ip route table-id 1310
 no shutdown

interface virt-eth0
 bpf-program cgn-ng-1
 no shutdown

interface pub.10
 description pub_itf
 ip route table-id 1320
 no shutdown

" || fail "cannot execute vty commands"

    sudo ip netns exec router-priv ping -c 1 -W 2 -I 10.0.0.1 8.8.8.8

    gtpg_show "
show interface
show carrier-grade-nat flows 10.0.0.1
show interface-rule all
"
}

############################ RUN GRE #################################
run_gre() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program cgn-ng-1
no carrier-grade-nat cgn-ng-1
no cdr-fwd cgn
"

    gtpg_conf "
bpf-program cgn-ng-1
 path bin/cgn.bpf
 no shutdown

carrier-grade-nat cgn-ng-1
 description doit_avoir_le_meme_nom_que_le_prog_bpf
 ipv4-pool 37.141.0.0/24
! interface gre-priv side ingress
! interface virt-eth0 side egress

interface virt-eth0
 description internet_connection
 bpf-program cgn-ng-1
 ip route table-id 1320
 no shutdown

interface gre-priv
 description priv_itf_on_gre_tunnel
 ip route table-id 1310
 no shutdown
" || fail "cannot execute vty commands"

    ip netns exec router-priv ping -c 1 -W 2 -I 10.0.0.1 8.8.8.8

    gtpg_show "
show interface
show carrier-grade-nat flows 10.0.0.1
show interface-rule all
"
}


#
# send various packets type
#
pkt() {
    netns="cgn-priv"
    if [ $type == "gre" -o $type == "vlan" ]; then
	netns="router-priv"
    fi

    ip netns exec $netns ping -c 1 -W 2 -I 10.0.0.1 8.8.8.8
    echo tata | ip netns exec $netns nc -s 10.0.0.1 8.8.8.8  9000
    echo toto | ip netns exec $netns nc -u -s 10.0.0.1 8.8.8.8 9000

    gtpg_show "
show carrier-grade-nat flows 10.0.0.1
"

}


action=${1:-setup}
type=${2:-iface}

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
