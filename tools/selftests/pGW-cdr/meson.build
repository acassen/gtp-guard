# SPDX-License-Identifier: AGPL-3.0-or-later

test_src = files(
  'main.c',
  '../../../src/gtp_cdr.c',
  '../../../src/gtp_cdr_asn1.c',
  '../../../src/gtp_cdr_spool.c',
  '../../../src/gtp_cdr_file.c',
  '../../../src/gtp_msg.c',
  '../../../src/gtp_utils.c',
)

gtpg_obj = gtp_guard_exe.extract_objects(lib_src)

t = executable(
  'pGW-cdr', test_src,
  objects: gtpg_obj,
  include_directories: inc,
  dependencies: [libbpf_dep, libpcap_dep, libcrypt_dep],
  install: false,
  build_by_default: false,
)

test('pgw-cdr', t, args : ['-h', 'a'])
