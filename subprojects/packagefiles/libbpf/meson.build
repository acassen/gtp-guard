project('libbpf', 'c',
	meson_version: '>= 0.56.0',
	version: run_command('get_version.sh', check: true).stdout().strip(),
	default_options: [
	  'c_std=gnu89',
	  'werror=true',
	  'optimization=2',
	  'warning_level=1',
	  'buildtype=custom',
	]
       )

add_project_arguments('-Wno-unknown-warning-option', language: 'c')
add_project_arguments('-Wno-format-overflow', language: 'c')
add_project_arguments('-Wno-extra', language: 'c')
add_project_arguments('-O2', language: 'c')

libelf_dep = dependency('libelf')
zlib_dep = dependency('zlib')

src = files(
  'src/bpf.c',
  'src/bpf_prog_linfo.c',
  'src/btf.c',
  'src/btf_dump.c',
  'src/btf_iter.c',
  'src/btf_relocate.c',
  'src/elf.c',
  'src/features.c',
  'src/gen_loader.c',
  'src/hashmap.c',
  'src/libbpf.c',
  'src/libbpf_errno.c',
  'src/libbpf_probes.c',
  'src/linker.c',
  'src/netlink.c',
  'src/nlattr.c',
  'src/relo_core.c',
  'src/ringbuf.c',
  'src/str_error.c',
  'src/strset.c',
  'src/usdt.c',
  'src/zip.c',
)

libbpf_lib = static_library(
  'libbpf',
  sources: src,
  dependencies: [libelf_dep, zlib_dep],
  include_directories: ['src', 'include', 'include/uapi'],
  c_args: [ '-D_LARGEFILE64_SOURCE' ],
  pic: false,
  install: true,
)

libbpf_dep = declare_dependency(
  link_with: libbpf_lib,
  include_directories: ['.'],
  dependencies: [libelf_dep, zlib_dep],
  variables: [
    'includedir=' + meson.project_source_root(),
    'includeuapidir=' + meson.project_source_root() + '/include/uapi'
  ],
)
