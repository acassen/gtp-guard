GTP Guard: GPRS Tunneling Protocol Routing software
===================================================

GTP-Guard is a routing software written in C. The main goal of this project is to provide robust and secure extensions to GTP protocol (GPRS Tunneling Protocol). GTP is widely used for data-plane in mobile core-network. GTP-Guard implements a set of 3 main framworks. The first one offers a Proxy feature for data-plane tweaking. The second one is a Routing facility to inter-connect, encapsulates or provides any routing related. The last one is a Firewall feature offering filtering, rewriting, redirecting. GTP-Guard relies on Linux Kernel XDP framework for its data-plane using eBPF programs. Administration and user-level interface are available via a standard VTY terminal interface.

GTP-Guard is free software; you can redistribute it and/or modify it under the terms of the GNU Affero General Public License Version 3.0 as published by the Free Software Foundation.

# Compile and Run

	$ make
	$ ./bin/gtp-guard --help
	gtp-guard v1.0.0 (2023/07/14)
	Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>

	Usage:
	  ./bin/gtp-guard
	  ./bin/gtp-guard -n
	  ./bin/gtp-guard -f gtp-guard.conf
	  ./bin/gtp-guard -d
	  ./bin/gtp-guard -h
	  ./bin/gtp-guard -v

	Commands:
	Either long or short options are allowed.
	  ./bin/gtp-guard --dont-fork          -n    Dont fork the daemon process.
	  ./bin/gtp-guard --use-file           -f    Use the specified configuration file.
	                                Default is /etc/gtp-guard/gtp-guard.conf.
	  ./bin/gtp-guard --dump-conf          -d    Dump the configuration data.
	  ./bin/gtp-guard --log-console        -l    Log message to stderr.
	  ./bin/gtp-guard --log-detail         -D    Detailed log messages.
	  ./bin/gtp-guard --log-facility       -S    0-7 Set syslog facility to LOG_LOCAL[0-7]. (default=LOG_DAEMON)
	  ./bin/gtp-guard --help               -h    Display this short inlined help screen.
	  ./bin/gtp-guard --version            -v    Display the version number

