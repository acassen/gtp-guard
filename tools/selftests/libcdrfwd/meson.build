# SPDX-License-Identifier: AGPL-3.0-or-later

test_src = files(
  'cdr_test.c',
  '../../../src/carrier-grade-nat/cdr_fwd.c',
  '../../../src/carrier-grade-nat/cdr_fwd_adj.c',
  '../../../src/carrier-grade-nat/cdr_fwd_disk.c',
  '../../../src/carrier-grade-nat/cdr_fwd_spool.c',
)

gtpg_obj = gtp_guard_exe.extract_objects(lib_src)

t = executable(
  'cdrfwd_test', test_src,
  objects: gtpg_obj,
  c_args: [ '-Wno-unused-result' ],
  include_directories: inc,
  dependencies: [],
  install: false,
  build_by_default: false,
)

test('cdrfwd_test', t)
