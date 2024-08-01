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

# XDP program to build
TARGETS := gtp_fwd.bpf gtp_route.bpf gtp_mirror.bpf sock_rps.bpf
BIN = ../../bin

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang

# gcc does not support Assembly IR, so there is no such LLC wich gcc
ifeq ($(CLANG), gcc)
  LLC = gcc
endif
ifeq ($(LLC), gcc)
  CLANG = gcc
endif

CFLAGS := -g -O2 -Wall -Werror

# Include for BPF are pointing to libbpf
LIBBPF = ../../libbpf
LINUXINCLUDE := -I$(LIBBPF)/src

all: $(TARGETS)
.PHONY: clean $(CLANG) $(LLC)

clean:
	@find . -type f			\
		\( -name '*~'		\
		-o -name '*.ll'		\
		-o -name '*.bc' \)	\
		-exec rm -vf '{}'	\;
	@for i in $(TARGETS); do rm -vf $(BIN)/"$$i"; done

# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
ifeq ($(LLC), gcc)
$(TARGETS): %.bpf: %.c
	@echo "  GCC-bpf" $@
	@$(CLANG) $(CFLAGS) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) \
	    -D__KERNEL__ -D__ASM_SYSREG_H \
	    -D__BPF_TRACING__ \
	    -Wall \
	    -Wno-unused-value -Wno-pointer-sign \
	    -D__TARGET_ARCH_$(ARCH) \
	    -Wno-tautological-compare \
	    -Wno-address-of-packed-member \
	    -O2 -emit-llvm -g -c $< -o $(BIN)/$@
else
$(TARGETS): %.bpf: %.c
	@echo "  CLANG-bpf" $@
	@$(CLANG) $(CFLAGS) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) \
	    -D__KERNEL__ -D__ASM_SYSREG_H \
	    -D__BPF_TRACING__ \
	    -Wall \
	    -Wno-unused-value -Wno-pointer-sign \
	    -D__TARGET_ARCH_$(ARCH) \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -Wno-unknown-warning-option \
	    -Wno-address-of-packed-member \
	    -O2 -emit-llvm -g -c $< -o ${@:.bpf=.ll}
	@$(LLC) -march=bpf -filetype=obj -o $(BIN)/$@ ${@:.bpf=.ll}
endif
