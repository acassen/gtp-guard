# GTP Guard: GPRS Tunneling Protocol Routing software


[![gtp-guard CI](https://github.com/acassen/gtp-guard/actions/workflows/actions-compile.yml/badge.svg)](https://github.com/acassen/gtp-guard/actions/workflows/actions-compile.yml)

<img width="30%" src="https://www.gtp-guard.org/assets/logo.png" align="left"/>

GTP-Guard is a routing software written in C. The main goal of this project is to provide robust and secure extensions to GTP protocol (GPRS Tunneling Protocol). GTP is widely used for data-plane in mobile core-network. GTP-Guard implements a set of 3 main framworks. The first one offers a Proxy feature for data-plane tweaking. The second one is a Routing facility to inter-connect, encapsulates or provides any routing related. The last one is a Firewall feature offering filtering, rewriting, redirecting. GTP-Guard relies on Linux Kernel XDP framework for its data-plane using eBPF programs. Administration and user-level interface are available via a standard VTY terminal interface.

GTP-Guard is free software; you can redistribute it and/or modify it under the terms of the GNU Affero General Public License Version 3.0 as published by the Free Software Foundation.

# Build

```
git clone --recursive git@github.com:acassen/gtp-guard.git
cd gtp-guard
make -j $(nproc)
```

gcc is the default compiled. Should you prefer the usage of clang, then use:
```
CC=clang make -j $(nproc)
```

# Basic Run

Define your own `gtp-guard.conf` settings in order to enable its vty over TCP.

```
$ cat <<EOFCONF > /tmp/gtp-guard.conf
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

$ sudo bin/gtp-guard --dont-fork --log-console --log-detail -f /tmp/gtp-guard.conf
```

then from another console, you can `telnet 127.0.0.1 8888` in order to get the CLI:
```
$ telnet 127.0.0.1 8888
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.

 Welcome to GTP-Guard VTY

xps> show version
gtp-guard v1.0.4-pre1 (2023/11/28) ().
Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
xps> quit
Connection closed by foreign host.
```

Then you can start sending your GTPc and GTPu workload to the UDP ports 2123 and 2152.

## basic test

For example, the following `test/testenv.sh` script can be used in order to perform a Basic Run
along with a set of few GTPu and GTPc ping.

It assumes that [gtping](https://github.com/ThomasHabets/gtping) has been isntalled.

```
cd test
sudo ./testenv.sh \
  -i path/dev/gtping/src/gtping \
  -u path/dev/gtpu-guard/test/gtpu-ping.py \
  -g path/dev/gtp-guard/bin/gtp-guard \
  -c /tmp/gtp-guard.conf \
  -f path/dev/gtp-guard/bin/gtp_fwd.bpf \
  -r path/dev/gtp-guard/bin/gtp_route.bpf \
  -m path/dev/gtp-guard/bin/gtp_mirror.bpf \
  -k no
```

## getenv settings

  - `GTP_GUARD_PID_FILE` : set alternate pid file (default = /var/run/gtp-guard.pid)
