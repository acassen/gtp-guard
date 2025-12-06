# SPDX-License-Identifier: AGPL-3.0-or-later

test_src = files(
  'main.c',
  'glue.c',
  '../../../src/carrier-grade-nat/cgn.c',
  '../../../src/carrier-grade-nat/cgn_flow.c',
)

gtpg_obj = gtp_guard_exe.extract_objects(lib_src)

t = executable(
  'carrier-grade-nat', test_src,
  objects: gtpg_obj,
  c_args: [ '-Wno-unused-result' ],
  include_directories: inc,
  dependencies: [libbpf_dep],
  install: false,
  build_by_default: false,
)

test('carrier-grade-nat', t, args:[ '-h' ])

# gtp-guard must be running, with test_cgn.bpf loaded
test('cgn_block_log', t, args:[ '-t', '1', '-p', 'test_block_log' ])
