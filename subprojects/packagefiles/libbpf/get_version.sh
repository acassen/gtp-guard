#!/bin/bash

# make a symlink so -I bpf will work.
# cannot put symlink in packagefile because it doesn't work on meson < 1.7.0
ln -sf src bpf

grep "^LIBBPF_.*VERSION" src/Makefile | grep -v shell > Makefile
cat<<EOF >> Makefile
all:
	@echo \$(LIBBPF_VERSION)
EOF
make -s
