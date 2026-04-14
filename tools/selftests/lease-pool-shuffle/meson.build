# SPDX-License-Identifier: AGPL-3.0-or-later

gtpg_obj = gtp_guard_exe.extract_objects(lib_src)

t = executable(
  'lease_pool_shuffle_test', files('main.c'),
  objects: gtpg_obj,
  include_directories: inc,
  dependencies: [libbpf_dep],
  install: false,
  build_by_default: false,
)

test('lease_pool shuffle test', t)
