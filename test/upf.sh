#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_gtpg_cmd.sh

clean() {
    clean_netns "access" "internet"
}

# everyone on the same interface
setup_simple() {
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

    # internet trunk
    ip link add dev veth0 netns internet address d2:ad:ca:fe:aa:02 type veth \
       peer name pub address d2:f0:0c:ba:bb:02
    ip -n internet link set dev veth0 up
    ip -n internet link set dev lo up
    ip link set dev pub up
    ip netns exec internet sysctl -q net.ipv4.conf.veth0.forwarding=1
    sysctl -q net.ipv4.conf.pub.forwarding=1

    # pfcp, on access
    ip -n access addr add 192.168.61.193/27 dev veth0
    ip addr add 192.168.61.194/27 dev ran

    # gtp-u, on access
    ip -n access addr add 192.168.61.2/25 dev veth0
    ip addr add 192.168.61.1/25 dev ran
    arp -s 192.168.61.2 d2:ad:ca:fe:aa:01

    # (almost) whole internet
    ip -n internet addr add 192.168.62.1/24 dev veth0
    ip addr add 192.168.62.2/24 dev pub
    ip -n internet addr add 8.8.8.8/32 dev veth0
    ip -n internet route add default via 192.168.62.2 dev veth0

    ip netns exec access ethtool -K veth0 gro on
    ip netns exec access ethtool -K veth0 tx-checksumming off >/dev/null
    ip netns exec internet ethtool -K veth0 gro on
    ip netns exec internet ethtool -K veth0 tx-checksumming off >/dev/null
}


run_simple() {
    # start gtp-guard if not yet started
    start_gtpguard

    gtpg_conf_nofail "
no bpf-program upf-1
no pfcp-router pfcp-1
"

    gtpg_conf "
bpf-program upf-1
 path bin/upf.bpf
 no shutdown

interface ran
 bpf-program upf-1
 no shutdown

interface pub
 bpf-program upf-1
 no shutdown
" || fail "cannot execute vty commands"

    gtpg_conf "
pfcp-router pfcp-1
 description first_one
 bpf-program upf-1
 listen 192.168.61.194 port 2123
 gtpu-tunnel-endpoint all 192.168.61.1 port 2152 interfaces ran
 egress-endpoint interfaces pub
" || fail "cannot execute vty commands"

    gtpg_show "
show interface
show interface-rule all
show interface-rule installed
"
}


action=${1:-setup}
type=${2:-simple}

case $action in
    clean)
	clean ;;
    setup)
	clean
	sleep 0.5
	setup_$type ;;
    run)
	run_$type ;;

    *) fail "action '$action' not recognized" ;;
esac
