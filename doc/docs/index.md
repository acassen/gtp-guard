---
hide:
  - navigation
---
# Welcome to GTP-Guard

<img width="20%" src="assets/logo.png" align="left"/>

GTP-Guard is a routing software written in C. The main goal of this project is to
provide robust and secure implementation of **GTP** protocol (GPRS Tunneling Protocol).
GTP is widely used for data-plane in mobile Core-Network. GTP-Guard is implementing pGW
features for 4G and UPF features for 5G Core-Networks. GTP-Guard is acticulated around a
set of 3 main frameworks. The first one offers a **Proxy** feature for data-plane tweaking.
The second one is a **Routing** facility to inter-connect, encapsulates or provides
any routing related. The last one is a **Firewall** feature offering filtering, rewriting,
redirecting. GTP-Guard relies on Linux Kernel **XDP** framework for its data-plane using
**eBPF** programs. Administration and user-level interface are available via a standard
VTY terminal interface.

GTP-Guard is free software; you can redistribute it and/or modify it under the terms
of the GNU Affero General Public License Version 3.0 as published by the Free Software Foundation.

[<img width=20% src="images/download.png">](software/gtp-guard-latest.tar.xz)

---

