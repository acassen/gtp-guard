#!/bin/bash

# make a symlink so -I bpf will work.
# cannot put symlink in packagefile because it doesn't work on meson < 1.7.0
ln -sf src bpf

grep "^LIBBPF_.*VERSION" src/Makefile | grep -v shell | sed 's/[:() ]//g' > version_env
source version_env
echo $LIBBPF_VERSION
