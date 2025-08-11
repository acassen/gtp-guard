#!/usr/bin/bash

setup_netns() {
    for ns in $@; do
	[ -f /run/netns/$ns ] && ip netns del $ns
	ip netns add $ns
	#echo "[ -f /run/netns/$ns ] && ip netns del $ns" >> $tmp/cleanup.sh
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
  -re "% .*" { exit 13 }
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
    if [ "$1" == "conf" ]; then
	echo "send \"exit\\n\"; expect \"sut(config)\" " >> $tmp/exp_cmd
    fi
    unset IFS
}


_gtpg_cmd() {
	cat <<EOF > $tmp/exp_cmd
set timeout 4
spawn telnet localhost 1664 
expect "sut> " { send "enable\n"; send "terminal length 0\n" }
EOF
    if [ "$1" == "conf" ]; then
	cat <<EOF >> $tmp/exp_cmd
expect "sut# " { send "conf t\n" }
expect "sut(config)# "
EOF
    fi
    gtpgc_conf "$1" "$2"

    echo 'send "exit\n"; send "exit\n"; expect eof' >> $tmp/exp_cmd

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

tmp=$(mktemp -d)
echo > $tmp/cleanup.sh
trap cleanup EXIT
