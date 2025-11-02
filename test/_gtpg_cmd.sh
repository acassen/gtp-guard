#!/usr/bin/bash

setup_netns() {
    for ns in $@; do
	[ -f /run/netns/$ns ] && ip netns del $ns
	ip netns add $ns
	#echo "[ -f /run/netns/$ns ] && ip netns del $ns" >> $tmp/cleanup.sh
    done
}

clean_netns() {
    for ns in $@; do
	[ -f /run/netns/$ns ] && ip netns del $ns
    done
}

fail() {
	echo "fail: $*" >&2
	exit 1
}

gtpgc_conf() {
    IFS=$'\n'
    for l in $2; do
	if [ "$1" == "conf" ]; then
	    cat >> $tmp/exp_cmd <<EOF
send "$l\n"
expect {
  -re "% interface:.* is already running" {}
  -re "% .*" { exit 13 }
  -re "sut(.*)# "
}
EOF
	elif [ "$1" == "conf_nofail" ]; then
	    cat >> $tmp/exp_cmd <<EOF
send "$l\n"
expect {
  -re "sut(.*)# "
}
EOF
	else
	    cat >> $tmp/exp_cmd <<EOF
send "$l\n"
expect "sut# "
EOF
	fi
    done
    cat >> $tmp/exp_cmd <<EOF
send "exit\n"
expect {
  -re "sut(.*)# " { send "exit\n"; exp_continue }
  "sut# " { send "exit\n"; expect eof }
}
EOF
    unset IFS
}


_gtpg_cmd() {
	cat <<EOF > $tmp/exp_cmd
set timeout 4
spawn telnet 127.0.0.1 1664
expect "sut> " { send "enable\n"; send "terminal length 0\n" }
EOF
    if [ "$1" == "conf" -o "$1" == "conf_nofail" ]; then
	cat <<EOF >> $tmp/exp_cmd
expect "sut# " { send "conf t\n" }
expect "sut(config)# "
EOF
    fi
    gtpgc_conf "$1" "$2"

    expect $tmp/exp_cmd >$tmp/exp_log 2>&1
    rc=$?
    if [ $rc != 0 ]; then
	echo "VTY commands failed, expect exit code:$rc, expect log:"
	echo "==================================================>"
	cat $tmp/exp_log
	echo
	echo "<=================================================="
	return 1
    elif [ "$1" == "show" ]; then
	cat $tmp/exp_log
    fi
    return 0
}

# start gtp-guard only if it is not running
start_gtpguard() {
    pidfile=${GTP_GUARD_PID_FILE:-/var/run/gtp-guard.pid}
    echo "pidfile: $pidfile"
    if [ -r $pidfile ]; then
	kill -0 `head -n 1 $pidfile`
	if [ $? -eq 0 ]; then
	    return
	fi
    fi

    bin/gtp-guard \
	--dump-conf \
	--dont-fork \
	--log-console \
	--log-detail \
	-f test/conf/minimal.conf &
    gtpguard_pid=$!
    if [ $? -ne 0 ]; then
	fail "failed to start gtp-guard"
    fi
    cat >> $tmp/cleanup.sh <<EOF
echo "*** WAITING that gtp-guard($gtpguard_pid) stops. CTRL-C do to so...."
wait $gtpguard_pid
EOF
}

gtpg_conf_nofail() {
    _gtpg_cmd "conf_nofail" "$*"
}

gtpg_conf() {
    _gtpg_cmd "conf" "$*"
}

gtpg_show() {
    _gtpg_cmd "show" "$*"
}

cleanup() {
    . $tmp/cleanup.sh
    rm -rf -- "$tmp"
}

send_py_pkt() {
    ns=$1
    port=$2
    script_head="
#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.gtp import *
"
    script_tail="
[ sendp(i, iface=\"$port\", verbose=0) for i in p ]
"
    if [ -n "$ns" ]; then
	ip netns exec $ns python3 -c "$script_head $3 $script_tail"
    else
	python3 -c "$script_head $3 $script_tail"
    fi
}


tmp=$(mktemp -d)
echo > $tmp/cleanup.sh
trap cleanup EXIT
