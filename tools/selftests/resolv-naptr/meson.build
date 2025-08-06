# SPDX-License-Identifier: AGPL-3.0-or-later

test_src = files(
  'main.c',
  '../../../src/gtp_resolv.c',
  '../../../src/gtp_sched.c',
  '../../../src/gtp_interface.c',
  '../../../src/gtp_interface_rule.c',
  '../../../src/gtp_bpf_prog.c',
  '../../../src/gtp_bpf.c',
)

gtpg_obj = gtp_guard_exe.extract_objects(lib_src)

t = executable(
  'test-resolv', test_src,
  objects: gtpg_obj,
  include_directories: inc,
  dependencies: [libbpf_dep, libcrypt_dep, libelf_dep],
  link_args : [ '-lresolv' ],
  install: false,
  build_by_default: false,
)

test('resolv-naptr', t)
