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
CFLAGS := -g -O2 -Wall -Werror

# Include for BPF are pointing to libbpf
LIBBPF = ../../libbpf
LINUXINCLUDE := -I$(LIBBPF)/src

all: dependencies $(TARGETS)
.PHONY: dependencies clean $(CLANG) $(LLC)

clean:
	@find . -type f			\
		\( -name '*~'		\
		-o -name '*.ll'		\
		-o -name '*.bc' \)	\
		-exec rm -vf '{}'	\;
	@for i in $(TARGETS); do rm -vf $(BIN)/"$$i"; done

dependencies: verify_cmds verify_target_bpf
verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		which $${TOOL} ;\
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done
verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi


# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
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
	    -fno-asynchronous-unwind-tables \
	    -O2 -emit-llvm -g -c $< -o ${@:.bpf=.ll}
	@$(LLC) -march=bpf -filetype=obj -o $(BIN)/$@ ${@:.bpf=.ll}
