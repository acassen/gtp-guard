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
# Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
#

CC	 ?= gcc
INCLUDES = -Iinclude -I../include -I../../lib -I../../libbpf/src -I../../libbpf/src/uapi
CFLAGS	 = -g -O2 -ggdb $(INCLUDES) -Wall -Wunused -Wstrict-prototypes \
	-D_GNU_SOURCE -MMD
#DEFS	 = -D_DEBUG_
DEFS	 =
COMPILE	 = $(CC) $(CFLAGS) $(DEFS)

%.o: %.c
	@echo "  CC" $@
	@$(COMPILE) -c $<

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
all: $(OBJS)

clean:
	@rm -vf *.a *.o *.d *~

-include *.d
