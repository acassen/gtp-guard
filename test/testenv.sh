#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# 
# Author: Vincent Jardin, <vjardin@free.fr>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Affero General Public
# License Version 3.0 as published by the Free Software Foundation;
# either version 3.0 of the License, or (at your option) any later
# version.
#
# Copyright (C) 2024 Vincent Jardin, <vjardin@free.fr>

set -e

#         GTPu/GTPc          PPPoE client            PPPoE server
# gw <--------+------> gtp-guard <---------+---------> bras
#  vegw2gtp-g   vegtp-g2gw    vegtp-g2bras   vebras2gtp-g
# 172.1.0.1/24  172.1.0.2/24

if [ "$(id -u)" != "0" ]; then
  echo "This test script must be run as root" 1>&2
  exit 1
fi

gtping="gtping"  # gtping from the default PATH
gtpguard="gtp-guard"  # gtp-guard from the default PATH
gtpguardconf="/tmp/gtp-guard.conf"  # gtp-guard.conf, default path
bpffwd="/usr/share/gtp-guard/gtp_fwd.bpf"
bpfroute="/usr/share/gtp-guard/gtp_route.bpf"
bpfmirror="/usr/share/gtp-guard/gtp_mirror.bpf"
keepsetup="no" # shall we keep the setup after the tests

__usage="
Usage: $(basename $0) [options]

Options:
  -h                      Display this help message.
  -i path/gtping          gtping to be used (default ${gtping}).
  -g path/gtp-guard       gtp-guard to be used (default ${gtpguard}).
  -c path/gtp-guard.conf  gtp-guard.conf to be used (default ${gtpguardconf}).
  -f path/gtp_fwd.bpf     gtp_fwd.bpf to be used (default ${bpffwd}).
  -r path/gtp_route.bpf   gtp_route.bpf to be used (default ${bpfroute}).
  -m path/gtp_mirror.bpf  gtp_mirror.bpf to be used (default ${bpfmirror}).
  -k yes/no               keep the setup after running the tests.
"

# Parse options to the `pip` command
while getopts ":hi:g:c:f:r:m:k:" opt; do
  case ${opt} in
    h )
      echo "$__usage"
      exit 0
      ;;
    i )
      gtping=$OPTARG
      ;;
    g )
      gtpguard=$OPTARG
      ;;
    c )
      gtpguardconf=$OPTARG
      ;;
    f )
      bpffwd=$OPTARG
      ;;
    r )
      bpfroute=$OPTARG
      ;;
    m )
      bpfmirror=$OPTARG
      ;;
    k )
      keepsetup=$OPTARG
      ;;
   \? )
     echo "Invalid Option: -$OPTARG" 1>&2
     exit 1
     ;;
  esac
done
shift $((OPTIND -1))

__start="
$(basename $0) started with:
  -i ${gtping} \\
  -g ${gtpguard} \\
  -c ${gtpguardconf} \\
  -f ${bpffwd} \\
  -r ${bpfroute} \\
  -m ${bpfmirror} \\
  -k ${keepsetup}
"
echo "$__start"

err=0
if [ ! -e ${gtping} ] ; then
  echo "${gtping} is not a valid executable"
  err=1
fi
if [ ! -e ${gtpguard} ] ; then
  echo "${gtpguard} is not a valid executable"
  err=1
fi
if [ ! -f ${bpffwd} ] ; then
  echo "${bpffwd} is not a valid file"
  err=1
fi
if [ ! -f ${bpfroute} ] ; then
  echo "${bpfroute} is not a valid file"
  err=1
fi
if [ ! -f ${bpfmirror} ] ; then
  echo "${bpfmirror} is not a valid file"
  err=1
fi
if [[ $err == 1 ]] ; then
  exit 1
fi
echo "Starting..."

function nsreset() {
  [ -f /run/netns/gw ]        && ip netns del gw
  [ -f /run/netns/gtp-guard ] && ip netns del gtp-guard
  [ -f /run/netns/bras ]      && ip netns del bras
  [ -f /run/netns/sandbox ]   && ip netns del sandbox
  return 0
}

nsreset

ip link add vegw2gtp-g   type veth peer name vegtp-g2gw
ip link add vegtp-g2bras type veth peer name vebras2gtp-g
ip netns add gw
ip netns add gtp-guard
ip netns add bras
ip link set vegw2gtp-g   netns gw
ip link set vegtp-g2gw   netns gtp-guard
ip link set vegtp-g2bras netns gtp-guard   
ip link set vebras2gtp-g netns bras
ip netns exec gw        ifconfig lo up
ip netns exec gtp-guard ifconfig lo up
ip netns exec bras      ifconfig lo up
ip netns exec gw        ip addr add dev vegw2gtp-g 172.1.0.1/24 broadcast +
ip netns exec gtp-guard ip addr add dev vegtp-g2gw 172.1.0.2/24 broadcast +

ip netns exec gw        ip link set dev vegw2gtp-g up
ip netns exec gtp-guard ip link set dev vegtp-g2gw up
ip netns exec gtp-guard ip link set dev vegtp-g2bras up
ip netns exec bras      ip link set dev vebras2gtp-g up

echo "eBPF sandbox check"
ip netns add sandbox
ip netns exec sandbox ifconfig lo up

ip netns exec sandbox \
  ip link set dev lo xdpgeneric obj $bpffwd sec xdp verbose
ip netns exec sandbox \
  ip -d link show dev lo
ip netns exec sandbox \
  ip link set dev lo xdpgeneric off

ip netns exec sandbox \
  ip link set dev lo xdpgeneric obj $bpfroute sec xdp verbose
ip netns exec sandbox \
  ip -d link show dev lo
ip netns exec sandbox \
  ip link set dev lo xdpgeneric off

# XXX TODO: error missing sec prog
# ip netns exec sandbox \
#  ip link set dev lo xdpgeneric obj $bpfmirror verbose
# ip netns exec sandbox \
#  ip -d link show dev lo
# ip netns exec sandbox \
#  ip link set dev lo xdpgeneric off

ip netns del sandbox

# create a default conf file if we are missing one
if [ ! -f ${gtpguardconf} ] ; then
  mkdir etc
  cat <<EOFCONF > etc/gtp-guard.conf
!
gtp-router demo
  gtpc-tunnel-endpoint 0.0.0.0 port 2123 listener-count 3
  gtpu-tunnel-endpoint 0.0.0.0 port 2152 listener-count 3
!
line vty
  no login
  listen 127.0.0.1 8888
!
EOFCONF
  gtpguardconf="etc/gtp-guard.conf"
fi
echo "Using $gtpguardconf running"

GTP_GUARD_PID_FILE=/tmp/gtp-guard.pid \
ip netns exec gtp-guard \
  $gtpguard \
    --dump-conf \
    --dont-fork \
    --log-console \
    --log-detail \
    -f $gtpguardconf \
    &
echo "CLI: sudo ip netns exec gtp-guard telnet 127.0.0.1 8888"
sleep 5

ip netns exec gw \
  $gtping -vvvv -c 3 172.1.0.2 -t 100

if [ ${keepsetup} == "no" ] ; then
  ip netns exec gtp-guard kill -TERM $(pidof gtp-guard)
  nsreset
  sleep 1
  rm -f /tmp/gtp-guard.pid
fi
