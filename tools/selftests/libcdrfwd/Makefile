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

CNAT_DIR=../../../src/carrier-grade-nat/

EXEC= cdrfwd_test
INCLUDES = -I../../../src/include -I$(CNAT_DIR)/include -I../../../lib -I../../../libbpf/src -I../../../libbpf/src/uapi
CC= gcc
CFLAGS= -Wall -Wstrict-prototypes -Wpointer-arith -O3 -fomit-frame-pointer -fexpensive-optimizations -g $(INCLUDES) -D_WITHOUT_BPF_
LDFLAGS= -lm -lcrypt -lpthread -lresolv -lpcap -ggdb
SUBDIRS= ../../../lib
OBJECTS= cdr_test.o $(CNAT_DIR)/cdr_fwd.o $(CNAT_DIR)/cdr_fwd_adj.o \
	$(CNAT_DIR)/cdr_fwd_disk.o $(CNAT_DIR)/cdr_fwd_spool.o \
	$(CNAT_DIR)/compat.o $(CNAT_DIR)/addr.o

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

