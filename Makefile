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

EXEC = gtp-guard
BIN  = bin
VERSION := $(shell cat VERSION)
TARBALL = $(EXEC)-$(VERSION).tar.xz
TARFILES = AUTHOR VERSION LICENSE README.md bin conf src lib Makefile

prefix = /usr/local
exec_prefix = ${prefix}
sbindir     = ${exec_prefix}/sbin
sysconfdir  = ${prefix}/etc
init_script = etc/init.d/gtp-guard.init
conf_file   = etc/gtp-guard/gtp-guard.conf

CC        = gcc
LDFLAGS   = -lpthread -lcrypt -ggdb -lm -lresolv -lelf
SUBDIRS   = lib src

all:
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i || exit 1; done && \
	echo "Building $(BIN)/$(EXEC)" && \
	$(CC) -o $(BIN)/$(EXEC) `find $(SUBDIRS) -name '*.[o]'` $(LDFLAGS)
#	strip $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"

debug:
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i || exit 1; done && \
	echo "Building $(BIN)/$(EXEC)" && \
	$(CC) -o $(BIN)/$(EXEC) `find $(SUBDIRS) -name '*.[oa]'` $(LDFLAGS)
	@echo ""
	@echo "Make complete"

clean:
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i clean; done
	rm -f $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"

uninstall:
	rm -f $(sbindir)/$(EXEC)

install:
	install -d $(prefix)
	install -m 700 $(BIN)/$(EXEC) $(sbindir)

tarball: clean
	@mkdir $(EXEC)-$(VERSION)
	@cp -a $(TARFILES) $(EXEC)-$(VERSION)
	@tar -cJf $(TARBALL) $(EXEC)-$(VERSION)
	@rm -rf $(EXEC)-$(VERSION)
	@echo $(TARBALL)
