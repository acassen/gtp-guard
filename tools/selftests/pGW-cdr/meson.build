# SPDX-License-Identifier: AGPL-3.0-or-later

gtpg_obj = gtp_guard_exe.extract_objects(lib_src)

t = executable(
  'pGW-cdr', files('main.c'),
  objects: gtpg_obj,
  include_directories: inc,
  dependencies: [libbpf_dep],
  install: false,
  build_by_default: false,
)

test('pgw-cdr', t)
