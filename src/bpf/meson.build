# SPDX-License-Identifier: AGPL-3.0-or-later 

fs = import('fs')

bpf_sources = files(
  'capture_trace.c',
  'gtp_fwd.c',
  'gtp_fwd_mirror.c',
  'gtp_route.c',
  'gtp_mirror.c',
  'cgn.c',
  'mape.c',
  'upf.c',
  'upf_cgn.c',
#  'test_cgn.c',
)

clang_bpf_flags = [
  clang_includes,
  '-DEBPF_SRC',
  '-D__x86_64__',
  libbpf_uapi_inc != '' ? '-I' + libbpf_uapi_inc : '',
  '-I' + meson.current_source_dir(),
  '-I' + libbpf_inc,
  '-Wno-unused-value',
  '-Wno-pointer-sign',
  '-Wno-compare-distinct-pointer-types',
  '-Wno-gnu-variable-sized-type-not-at-end',
  '-Wno-tautological-compare',
  '-Wno-unknown-warning-option',
  '-Wno-address-of-packed-member',
  '-fno-asynchronous-unwind-tables',
]

foreach bsrc : bpf_sources
  name = fs.replace_suffix(fs.name(bsrc), '')
  bpf_obj = custom_target('bpf-' + name,
			  input : bsrc,
			  output : name + '.ll',
			  depfile : name + '.d',
			  build_by_default: true,
			  command : [clang, '-c', '-g', '-O2', '-emit-llvm',
				     '-target', 'bpf', '-mcpu=v3',
				     clang_bpf_flags,
				     '-MD', '-MF', '@DEPFILE@',
				     '-o', '@OUTPUT@', '@INPUT@'
				    ],
  )

  bpf_prog = custom_target('bpf-' + name + '-bin',
			   input : bpf_obj,
			   output : name + '.bpf',
			   command : [llc, '-march=bpf', '-filetype=obj',
				      '-o', '@OUTPUT@', '@INPUT@'],
			   install_dir: get_option('sharedstatedir') + '/gtp-guard',
			   install: true
  )
endforeach
