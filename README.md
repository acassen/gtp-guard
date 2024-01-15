GTP Guard: GPRS Tunneling Protocol Routing software
===================================================

GTP-Guard is a routing software written in C. The main goal of this project is to provide robust and secure extensions to GTP protocol (GPRS Tunneling Protocol). GTP is widely used for data-plane in mobile core-network. GTP-Guard implements a set of 3 main framworks. The first one offers a Proxy feature for data-plane tweaking. The second one is a Routing facility to inter-connect, encapsulates or provides any routing related. The last one is a Firewall feature offering filtering, rewriting, redirecting. GTP-Guard relies on Linux Kernel XDP framework for its data-plane using eBPF programs. Administration and user-level interface are available via a standard VTY terminal interface.

GTP-Guard is free software; you can redistribute it and/or modify it under the terms of the GNU Affero General Public License Version 3.0 as published by the Free Software Foundation.


[![GTP-Guard](https://www.gtp-guard.org/_images/network.png)](https://www.gtp-guard.org)

Build
=====

```
git clone --recursive git@github.com:acassen/gtp-guard.git
cd gtp-guard
make -j $(nproc)
```
