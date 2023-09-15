# SPDX-License-Identifier: AGPL-3.0-or-later 
#
# Soft:        The main goal of gtp-guard is to provide robust and secure
#              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
#              widely used for data-plane in mobile core-network. gtp-guard
#              implements a set of 3 main frameworks:
#              A Proxy feature for data-plane tweaking, a Routing facility
#              to inter-connect and a Firewall feature for filtering,
#              rewriting and redirecting.
#
# Authors:     Alexandre Cassen, <acassen@gmail.com>
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU Affero General Public
#              License Version 3.0 as published by the Free Software Foundation;
#              either version 3.0 of the License, or (at your option) any later
#              version.
#
# Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
#

CC	 = gcc
INCLUDES = -Iinclude -I../lib -I../libbpf/src -I../libbpf/src/uapi
CFLAGS	 = -g -O2 -ggdb $(INCLUDES) -Wall -Wunused -Wstrict-prototypes -D_GNU_SOURCE
#DEFS	 = -D_DEBUG_
DEFS	 =
COMPILE	 = $(CC) $(CFLAGS) $(DEFS)

OBJS = 	main.o gtp_data.o gtp_vty.o gtp_if.o gtp_switch.o gtp_switch_vty.o \
	gtp_handle.o gtp_handle_v1.o gtp_handle_v2.o gtp_conn.o gtp_dlock.o \
	gtp_session.o gtp_teid.o gtp_sqn.o gtp_resolv.o gtp_disk.o gtp_xdp.o \
	gtp_utils.o gtp_request.o gtp_dpd.o

HEADERS = $(OBJS:.o=.h)

.c.o:
	@echo "  CC" $@
	@$(COMPILE) -c $<

all:	$(OBJS)

clean:
	rm -f *.a *.o *~