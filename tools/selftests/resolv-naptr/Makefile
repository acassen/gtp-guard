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
# Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
#

EXEC= test-resolv
INCLUDES = -I../../../src/include -I../../../lib -I../../../libbpf/src -I../../../libbpf/src/uapi
CC= gcc
CFLAGS= -Wall -Wstrict-prototypes -Wpointer-arith -O3 -fomit-frame-pointer -fexpensive-optimizations -g $(INCLUDES)
LDFLAGS= -lm -lcrypt -lpthread -lresolv -ggdb
SUBDIRS= ../../../lib
OBJECTS= main.o ../../../src/gtp_resolv.o ../../../src/gtp_sched.o ../../../src/gtp_if.o

.c.o:
	@echo "  CC" $@
	@$(CC) -o $@ $(CFLAGS) -c $*.c

all:    $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC): $(OBJECTS)
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i || exit 1; done && \
	echo "Building $(EXEC)" && \
	$(CC) -o $(EXEC) `find $(SUBDIRS) -name '*.[oa]'` $(OBJECTS) $(LDFLAGS)
	@echo ""
	@echo "Make complete"

clean:
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i clean; done
	rm -f *.o $(EXEC) 

