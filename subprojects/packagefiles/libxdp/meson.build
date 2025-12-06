project('libxdp', 'c',
	meson_version: '>= 0.56.0',
	version: run_command('get_version.sh', check: true).stdout().strip(),
	default_options: [
	  'c_std=gnu11',
	  'werror=true',
	  'optimization=2',
	  'warning_level=1',
	]
       )

libbpf_dep = dependency('libbpf')

src = files(
  'lib/libxdp/xsk.c',
  'lib/libxdp/libxdp.c',
)

libxdp_lib = static_library(
  'libxdp',
  sources: src,
  dependencies: [libbpf_dep],
  include_directories: ['headers'],
  c_args: [
    '-DBPF_OBJECT_PATH="/usr/local/lib/bpf"',
    '-DBPF_DIR_MNT="/sys/fs/bpf"',
    '-DRUNDIR="/run"',
    '-DHAVE_LIBBPF_PERF_BUFFER__CONSUME',
    '-DHAVE_LIBBPF_BTF__LOAD_FROM_KERNEL_BY_ID',
    '-DHAVE_LIBBPF_BTF__TYPE_CNT',
    '-DHAVE_LIBBPF_BPF_OBJECT__NEXT_MAP',
    '-DHAVE_LIBBPF_BPF_OBJECT__NEXT_PROGRAM',
    '-DHAVE_LIBBPF_BPF_PROGRAM__INSN_CNT',
    '-DHAVE_LIBBPF_BPF_PROGRAM__TYPE',
    '-DHAVE_LIBBPF_BPF_PROGRAM__FLAGS',
    '-DHAVE_LIBBPF_BPF_PROGRAM__EXPECTED_ATTACH_TYPE',
    '-DHAVE_LIBBPF_BPF_MAP_CREATE',
    '-DHAVE_LIBBPF_PERF_BUFFER__NEW_RAW',
    '-DHAVE_LIBBPF_BPF_XDP_ATTACH',
    '-DHAVE_LIBBPF_BPF_MAP__SET_AUTOCREATE',
    '-DHAVE_LIBBPF_BPF_PROG_TEST_RUN_OPTS',
    '-DHAVE_LIBBPF_BPF_XDP_QUERY',
    '-DHAVE_SECURE_GETENV',
    '-DDEBUG',
    '-DLIBBPF_DYNAMIC',
    '-D_LARGEFILE64_SOURCE' ],
  pic: false,
  install: true,
)

libxdp_dep = declare_dependency(
  link_with: libxdp_lib,
  include_directories: ['.'],
  dependencies: [libbpf_dep],
  variables: [
    'includedir=' + meson.project_source_root(),
  ],
)
